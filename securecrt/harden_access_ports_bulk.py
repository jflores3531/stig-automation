# $language = "Python3"
# $interface = "1.0"

"""Push the access/host-facing port STIG fixes to every saved SecureCRT
session, unattended.

READ THIS FIRST - THIS SCRIPT CONFIGURES DEVICES
The SecureCRT twin of scripts/l2_stig_harden_access_ports.py, which needs
netmiko and so cannot run on the machine these switches are reachable from -
the reason this folder exists. Same fixes, same order, different transport.

IT NEVER SENDS A TRUNK COMMAND
Not one, and it never enters a trunk-classified interface. Trunk ports are
l2_stig_harden_trunk_ports.py's job, and they are separate because a mistake on
an access port costs one desk while a mistake on a trunk costs the uplink this
session is riding. Nothing here can take the switch away from you: an access
port serves one endpoint, and every command below is reversible from any
session that can still reach the switch.

INTERFACE TEMPLATES ARE READ AND EXPANDED BEFORE ANY PORT IS CLASSIFIED
This is the part that matters most, and it is why the walk asks the switch two
extra questions. An interface whose block is only `source template UPLINK`
carries no `switchport mode trunk` line of its own. Classified off the raw
running-config it lands in the access bucket, and this script would send it
`switchport mode access` and `spanning-tree portfast` - collapsing the trunk,
and putting PortFast on a port that receives BPDUs as a matter of course, which
is the exact condition BPDU Guard exists to shut down. So every sourced template
is read off the switch (`show template interface source user <name>`, one per
distinct template, none at all for a switch that uses none) and spliced in
first. A switch whose templates cannot be read is skipped rather than guessed
at.

WHAT IT PUSHES, per access port
  switchport mode access          V-220642/220645, as a side effect
  spanning-tree portfast          V-220630b - the global
                                  `spanning-tree portfast bpduguard default`
                                  only activates BPDU Guard on ports that have
                                  PortFast, so without this that command is
                                  present and inert everywhere: a false PASS
  switchport block unicast        V-220632 (UUFB)
  storm-control broadcast ...     V-220636, scaled to ~2% of line rate.
                                  FastEthernet ports are skipped entirely -
                                  DISA's own Fix Text says most do not support it

and on access ports that are ALREADY SHUT, and only those:
  switchport access vlan <unused> V-220641, from inventory.yaml's unused_vlan,
                                  or typed in when that cannot be read

WHAT IT DOES NOT PUSH
V-220642's default access VLAN. That one lands on live ports, where whatever is
plugged in moves with it and needs the new VLAN to be right for that device.
V-220623 (802.1x/MAB): `authentication port-control auto` with no reachable
RADIUS authenticator and no supplicant blocks every port it lands on.
Both stay findings, and every run says so.

It never writes startup-config, and it never aborts: a switch that is offline,
refusing credentials or not a Cisco switch is logged and skipped.

Copy this with capture_l2s.py, capture_l2s_bulk.py and harden_l2s_bulk.py -
it takes session discovery and connect handling from the second and the
config-push machinery from the third rather than carrying copies that drift.
"""

import os
import os.path
import re
import time

# `crt` is injected by SecureCRT into this script's globals, not into the
# modules it imports - so those get it handed over explicitly in main().
crt = globals().get('crt')

import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import capture_l2s
import capture_l2s_bulk as bulk
import harden_l2s_bulk as pusher


OUTPUT_DIR = r'C:\Documents\netauto_hardening'
STOP_FILE = pusher.STOP_FILE
SESSIONS_SHOWN = pusher.SESSIONS_SHOWN

# Kept behaviourally identical to scripts/stig_common.py and
# scripts/l2_stig_harden_access_ports.py, which cannot be imported from here.
# tests/test_securecrt_access_ports.py runs both implementations over the same
# configs and asserts they answer the same, because two tools that disagree
# about which port is a trunk is the worst possible way to find that out.
SWITCHPORT_PREFIXES = (
    'GigabitEthernet', 'FastEthernet', 'TenGigabitEthernet', 'TwoGigabitEthernet',
    'FiveGigabitEthernet', 'TwentyFiveGigE', 'FortyGigabitEthernet', 'HundredGigE',
    'TwoHundredGigE', 'FourHundredGigE', 'Ethernet', 'Port-channel',
)

ACCESS_FIXES = [
    'switchport mode access',
    'spanning-tree portfast',
    'switchport block unicast',
]

STORM_CONTROL_BPS = {
    'TwoGigabitEthernet': 50000000,
    'FiveGigabitEthernet': 100000000,
    'TenGigabitEthernet': 200000000,
    'TwentyFiveGigE': 500000000,
    'FortyGigabitEthernet': 800000000,
    'HundredGigE': 2000000000,
    'TwoHundredGigE': 4000000000,
    'FourHundredGigE': 8000000000,
}
STORM_CONTROL_BPS_DEFAULT = 20000000

TEMPLATE_COMMAND_PREFIX = 'show template interface source user '
_TEMPLATE_METADATA = re.compile(r'[A-Z][A-Za-z ]{0,30}:')

LOG_COLUMNS = ('hostname', 'ip_address', 'outcome', 'access_ports', 'trunk_ports',
               'shut_ports', 'rejected', 'comment', 'session', 'timestamp')


def is_layer3_interface(block):
    """A switchport-capable interface *name* is not a switchport. A routed port
    carries `no switchport`, and a Catalyst's out-of-band management port
    (GigabitEthernet0/0, in Mgmt-vrf) is not switchport-capable hardware at all,
    so IOS XE writes no switchport line for it in either direction.

    Sending `switchport mode access` to a routed port converts it and takes its
    address with it, which is why this errs strict: anything ambiguous stays a
    switchport and simply gets configured as one."""
    if re.search(r'^\s*no switchport\s*$', block, re.M):
        return True
    if re.search(r'^\s*switchport\b', block, re.M):
        return False
    return bool(re.search(r'^\s*(?:ip|ipv6) address\b|^\s*vrf forwarding\b', block, re.M))


def switchport_names(cfg):
    """(access names, trunk names), in config order.

    An interface counts as trunk only if its block has `switchport mode trunk`;
    anything else switchport-capable - access mode, unset mode, dynamic
    negotiation - is host-facing. Feed this the template-EXPANDED config."""
    access, trunk = [], []
    for chunk in re.split(r'^(?=interface \S+)', cfg, flags=re.M):
        m = re.match(r'interface (\S+)', chunk)
        if not m or not m.group(1).startswith(SWITCHPORT_PREFIXES):
            continue
        if is_layer3_interface(chunk):
            continue
        if re.search(r'^\s*switchport mode trunk\s*$', chunk, re.M):
            trunk.append(m.group(1))
        else:
            access.append(m.group(1))
    return access, trunk


def sourced_template_names(running_config):
    """Distinct interface-template names a config sources, first appearance
    first. Empty for a switch that uses none, which then costs no extra
    commands at all."""
    names = []
    for name in re.findall(r'^\s*source template (\S+)\s*$', running_config, re.M):
        if name not in names:
            names.append(name)
    return names


def parse_interface_template(output):
    """The configuration lines out of `show template interface source user
    <name>` output. Empty if the switch had nothing to show for that name."""
    lines = []
    for line in str(output).splitlines():
        stripped = line.strip()
        if not stripped or stripped in ('!', 'end'):
            continue
        if set(stripped) <= set('-=_'):
            continue
        if stripped.lower().startswith('building configuration'):
            continue
        if stripped.startswith('%'):
            continue
        if _TEMPLATE_METADATA.match(stripped):
            continue
        lines.append(stripped)
    return lines


def expand_interface_templates(cfg, template_bodies):
    """cfg with each `source template <name>` line followed by that template's
    own commands, indented to match the block they join. The sourcing line is
    kept rather than replaced, so nothing about the switch's config is hidden
    by the expansion."""
    def splice(match):
        indent, name = match.group(1), match.group(2)
        body = template_bodies.get(name)
        if not body:
            return match.group(0)
        return '\n'.join([match.group(0)] + [indent + line for line in body])

    return re.sub(r'^([ \t]*)source template (\S+)[ \t]*$', splice, cfg, flags=re.M)


def read_interface_templates(running_config, prompt):
    """{name: [lines]} for every template the config sources.

    Raises CollectionError if a template the config sources cannot be read.
    Guessing is not an option here: an unread UPLINK template is a trunk this
    script would configure as an access port."""
    bodies = {}
    for name in sourced_template_names(running_config):
        output = capture_l2s.run_command(TEMPLATE_COMMAND_PREFIX + name, prompt)
        body = parse_interface_template(output)
        if not body:
            raise capture_l2s.CollectionError(
                'template {0} unreadable'.format(name),
                'The config sources interface template {0}, and the switch returned '
                'nothing usable for it. Ports configured by that template cannot be '
                'classified, and a trunk among them would be configured as an access '
                'port.'.format(name),
                'Template unreadable')
        bodies[name] = body
    return bodies


def storm_control_command(interface_name):
    """V-220636, scaled to ~2% of line rate from the interface-name prefix.
    FastEthernet ports get nothing: DISA's own Fix Text notes storm control is
    not supported on most of them, so a threshold there would just be rejected."""
    if interface_name.startswith('FastEthernet'):
        return None
    prefix_match = re.match(r'[A-Za-z-]+', interface_name)
    prefix = prefix_match.group(0) if prefix_match else ''
    bps = STORM_CONTROL_BPS.get(prefix, STORM_CONTROL_BPS_DEFAULT)
    return 'storm-control broadcast level bps {0}'.format(bps)


def shutdown_access_ports(cfg, access_names):
    """Which access ports are administratively shut, off the EXPANDED config.

    An explicit `no shutdown` in the block wins over a `shutdown` spliced in
    from a template, because that is what the switch does. Without that rule the
    expansion becomes a way to push the unused VLAN onto a port carrying
    traffic. IOS renders `no shutdown` only where it overrides something."""
    shutdown = []
    for chunk in re.split(r'^(?=interface \S+)', cfg, flags=re.M):
        m = re.match(r'interface (\S+)', chunk)
        if not m or m.group(1) not in access_names:
            continue
        if re.search(r'^\s*no shutdown\s*$', chunk, re.M):
            continue
        if re.search(r'^\s*shutdown\s*$', chunk, re.M):
            shutdown.append(m.group(1))
    return shutdown


def templated_ports(cfg, names):
    """Which of `names` source a template, off the RAW config. An explicit
    `switchport access vlan` on one of these overrides its template for that
    port and outlives the shutdown it was pushed for."""
    sourced = []
    for chunk in re.split(r'^(?=interface \S+)', cfg, flags=re.M):
        m = re.match(r'interface (\S+)', chunk)
        if m and m.group(1) in names and re.search(r'^\s*source template \S+\s*$', chunk, re.M):
            sourced.append(m.group(1))
    return sourced


def port_commands(access_ports, shut_ports, unused_vlan):
    """The whole config block for one switch, interface by interface."""
    commands = []
    for name in access_ports:
        commands.append('interface {0}'.format(name))
        commands += ACCESS_FIXES
        if unused_vlan and name in shut_ports:
            commands.append('switchport access vlan {0}'.format(unused_vlan))
        storm = storm_control_command(name)
        if storm:
            commands.append(storm)
    return commands


def inventory_unused_vlan(path=None):
    """inventory.yaml's `unused_vlan`, or None.

    Same reasoning as harden_l2s_bulk's syslog reader: nothing in this folder
    may import from the wider repository, but inventory.yaml is written as JSON,
    so the standard library opens it and a missing file is simply None."""
    import json
    try:
        with open(path or pusher.inventory_path(), encoding='utf-8') as handle:
            value = json.load(handle).get('unused_vlan')
    except Exception:
        return None
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return number if 1 <= number <= 4094 else None


class RunLog:
    """One row per session in the list, including the ones nothing answered
    from. A hardening run has to account for every switch it was pointed at."""

    def __init__(self, directory):
        self.path = bulk.unused_path(
            directory, 'access_ports_log_' + time.strftime('%Y%m%d_%H%M%S'), '.csv')
        self.counts = {}
        with open(self.path, 'w', encoding='utf-8') as handle:
            handle.write(','.join(LOG_COLUMNS) + '\n')

    def record(self, session_path, host, outcome, access_ports='', trunk_ports='',
               shut_ports='', rejected='', comment='', hostname=''):
        self.counts[outcome] = self.counts.get(outcome, 0) + 1
        row = (hostname or session_path, host, outcome, access_ports, trunk_ports,
               shut_ports, rejected, comment, session_path,
               time.strftime('%Y-%m-%d %H:%M:%S'))
        with open(self.path, 'a', encoding='utf-8') as handle:
            handle.write(','.join('"{0}"'.format(str(f).replace('"', "'")) for f in row) + '\n')

    def summary(self):
        return ', '.join('{0}: {1}'.format(name, self.counts[name])
                         for name in sorted(self.counts))


def main():
    folder = crt.Dialog.Prompt(
        'Session folder to harden, e.g. "Switches/Site A".\n'
        'Leave blank to harden every saved session.\n\n'
        'Folders are separated with a forward slash, the way SecureCRT\'s own\n'
        'session database writes them. This is a prefix match, so a session\'s\n'
        'full name scopes the run to that one switch.',
        'Access ports - scope', '', False)
    if folder is None:
        return

    sessions, duplicates = bulk.dedupe_by_host(bulk.find_sessions(folder.strip()))
    if not sessions:
        crt.Dialog.MessageBox(
            'No saved sessions found under:\n{0}\n\nFolder filter: {1}'
            .format(os.path.join(bulk.config_path(), 'Sessions'), folder or '(none)'),
            'Nothing to do')
        return

    output_dir = crt.Dialog.Prompt('Write the run log to:', 'Access ports - log folder',
                                   OUTPUT_DIR)
    if not output_dir:
        return
    try:
        if not os.path.isdir(output_dir):
            os.makedirs(output_dir)
    except OSError as error:
        crt.Dialog.MessageBox('Could not create {0}:\n{1}'.format(output_dir, error),
                              'Cannot write there')
        return

    # Read rather than asked for where the file answers, same as the syslog
    # collectors in harden_l2s_bulk.
    unused_vlan = inventory_unused_vlan()
    vlan_source = 'inventory.yaml'
    if unused_vlan is None:
        vlan_source = 'typed in'
        answer = crt.Dialog.Prompt(
            'VLAN ID for V-220641 - the unused VLAN that already-shut access ports\n'
            'get parked on. Leave blank to skip that fix; every other access-port\n'
            'command still goes out.\n\n'
            'This would have come from inventory.yaml. Looked at:\n  {0}\n  {1}\n\n'
            'The VLAN must already exist in the switch\'s VLAN database - this script\n'
            'does not create it.'
            .format(pusher.inventory_path(),
                    'file not found' if not os.path.exists(pusher.inventory_path())
                    else 'found the file, but `unused_vlan` is missing or not a VLAN ID'),
            'Access ports - unused VLAN', '', False)
        if answer is None:
            return
        answer = (answer or '').strip()
        if answer:
            try:
                number = int(answer)
                unused_vlan = number if 1 <= number <= 4094 else None
            except ValueError:
                unused_vlan = None
            if unused_vlan is None:
                crt.Dialog.MessageBox(
                    '`{0}` is not a VLAN ID between 1 and 4094.\n\nNothing was configured. '
                    'Run again with a valid ID, or blank to skip V-220641.'.format(answer),
                    'Access ports - check the VLAN ID')
                return

    listed = '\n'.join('  ' + path for path, _host in sessions[:SESSIONS_SHOWN])
    if len(sessions) > SESSIONS_SHOWN:
        listed += '\n  ...and {0} more'.format(len(sessions) - SESSIONS_SHOWN)

    preview = '\n'.join('  ' + command for command in ACCESS_FIXES)
    preview += '\n  storm-control broadcast level bps <scaled to the port speed>'
    preview += ('\n  switchport access vlan {0}   (only on ports already shut, from {1})'
                .format(unused_vlan, vlan_source) if unused_vlan
                else '\n  (no unused VLAN given, so V-220641 stays a finding)')

    if crt.Dialog.MessageBox(
            '{0} device(s) to configure{1}:\n{2}\n\n'
            'THIS WRITES TO running-config ON EVERY ONE OF THEM.\n\n'
            'To EVERY access/host-facing port on each switch:\n{3}\n\n'
            'No trunk port is entered and no trunk command is sent. Interface templates '
            'are read off each switch and expanded before any port is classified, so a '
            'trunk that gets its mode from a template is not treated as an access port.\n\n'
            'startup-config is NOT written, so a reload reverts any switch until you save '
            'it deliberately.\n\n'
            'To stop early, create a file named {4} in the log folder.\n\n'
            'Begin?'.format(len(sessions),
                            ' ({0} duplicate session(s) collapsed)'.format(len(duplicates))
                            if duplicates else '', listed, preview, STOP_FILE),
            'Access ports - confirm', 4 | 48) != 6:
        return

    connect_state = {}
    log = RunLog(output_dir)
    for session_path, host, kept in duplicates:
        log.record(session_path, host, 'duplicate', comment='Same address as ' + kept)
    stop_path = os.path.join(output_dir, STOP_FILE)
    stopped = False

    def visit_one(index, session_path, host):
        crt.Session.SetStatusText('Access ports {0}/{1}: {2}'
                                  .format(index, len(sessions), session_path))
        outcome, comment = bulk.connect_session(session_path, connect_state)
        if outcome:
            ip, label = bulk.session_name_parts(session_path)
            log.record(session_path, host or ip, outcome, comment=comment, hostname=label)
            return

        prompt = capture_l2s.read_prompt()
        if prompt.endswith('>'):
            log.record(session_path, host, 'refused', comment='Session is in user EXEC mode')
            return
        reply = capture_l2s.run_command('terminal length 0', prompt)
        wrong_device = capture_l2s.not_a_switch(reply)
        if wrong_device:
            log.record(session_path, host, 'refused',
                       comment='Not a Cisco switch: ' + wrong_device)
            return

        hostname = prompt.rstrip('#').strip()
        running_config = capture_l2s.run_command('show running-config', prompt)
        cut_short = capture_l2s.config_cut_short(running_config)
        if cut_short:
            log.record(session_path, host, 'refused', comment=cut_short, hostname=hostname)
            return

        # Templates first, classification second - see the docstring.
        bodies = read_interface_templates(running_config, prompt)
        effective = expand_interface_templates(running_config, bodies)
        access_ports, trunk_ports = switchport_names(effective)
        if not access_ports:
            log.record(session_path, host, 'no access ports', trunk_ports=len(trunk_ports),
                       comment='Nothing host-facing to configure', hostname=hostname)
            return

        shut_ports = shutdown_access_ports(effective, access_ports) if unused_vlan else []
        overridden = templated_ports(running_config, shut_ports)

        transcript = pusher.send_config(
            port_commands(access_ports, shut_ports, unused_vlan), prompt)
        rejected = pusher.rejected_lines(transcript)

        notes = []
        if bodies:
            notes.append('{0} template(s) expanded: {1}'.format(len(bodies),
                                                                ' '.join(sorted(bodies))))
        if overridden:
            notes.append('{0} shut port(s) had a template overridden by the VLAN line'
                         .format(len(overridden)))
        if not unused_vlan:
            notes.append('no unused VLAN given - V-220641 not addressed')

        log.record(session_path, host,
                   'hardened' if not rejected else 'hardened with rejections',
                   access_ports=len(access_ports), trunk_ports=len(trunk_ports),
                   shut_ports=len(shut_ports), rejected='; '.join(rejected)[:300],
                   comment='; '.join(notes)[:300], hostname=hostname)

    crt.Screen.Synchronous = True
    try:
        for index, (session_path, host) in enumerate(sessions, 1):
            if os.path.exists(stop_path):
                stopped = True
                break
            # Nothing that happens to one switch may end the walk.
            try:
                visit_one(index, session_path, host)
            except capture_l2s.CollectionError as refused:
                try:
                    log.record(session_path, host, 'refused', comment=refused.reason)
                except Exception:
                    pass
            except Exception as error:
                try:
                    log.record(session_path, host, 'error',
                               comment=bulk.first_line(str(error)))
                except Exception:
                    pass
            bulk.disconnect()
    finally:
        crt.Screen.Synchronous = False
        try:
            crt.Session.SetStatusText('')
        except Exception:
            pass

    crt.Dialog.MessageBox(
        '{0}\n\n{1}\n\nRun log:\n{2}\n\nOne row per session, with its access/trunk/shut port '
        'counts, so a switch whose ports were classified oddly is visible without opening it.'
        '\n\nStill findings after this run, deliberately: V-220642 (default access VLAN on '
        'live ports) and V-220623 (802.1x/MAB).\n\nstartup-config was NOT written on any '
        'switch. Re-audit, then save deliberately.'
        .format('Run stopped early by the STOP file.' if stopped else 'Run complete.',
                log.summary() or 'nothing configured', log.path),
        'Access ports finished')


# SecureCRT injects `crt` before running, so this is truthy there and None on a
# plain import, which is what lets the tests drive main() with a stand-in.
if crt is not None:
    capture_l2s.crt = crt
    bulk.crt = crt
    pusher.crt = crt
    main()
