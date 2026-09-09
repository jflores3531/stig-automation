#!/usr/bin/env python
"""Push the access/host-facing port fixes from the DISA Cisco IOS Switch L2S
STIG to a device.

Split from the trunk ports deliberately. The two halves of what used to be
l2_stig_harden_interfaces.py have nothing in common but a `show running-config`,
and they carry completely different risk: an access port serves one endpoint,
so a mistake there costs one desk and is fixed from the same session that made
it. A trunk port is the uplink, and the session doing the pushing is usually
riding it - see l2_stig_harden_trunk_ports.py, which is why that half now waits
for its own change window instead of going out with this one.

This script never sends a trunk command, and never touches a port classified as
trunk. It is safe to run in the middle of a working day on a switch whose
uplinks you have not planned an outage for.

Run l2_stig_harden_global.py first: it creates the unused/default-access VLANs
in the database (referenced here, not created here) and enables DHCP snooping
globally (V-220633).

WHAT IT PUSHES, per access port
  switchport mode access          V-220642/220645, as a side effect
  spanning-tree portfast          V-220630b - the global
                                  `spanning-tree portfast bpduguard default` in
                                  l2_stig_harden_global.py only activates BPDU
                                  Guard on ports that have PortFast, so without
                                  this that command is present and inert
                                  everywhere: a false PASS.
  switchport block unicast        V-220632 (UUFB). Rejected on the lab's
                                  vios_l2, kept for real hardware - netmiko does
                                  not treat a rejected command as fatal.
  switchport access vlan <n>      only on ports still on VLAN 1, and only when
                                  default_access_vlan is in inventory.yaml.
  storm-control broadcast ...     V-220636, threshold scaled to ~2% of line
                                  rate. FastEthernet ports are skipped entirely:
                                  DISA's own Fix Text notes storm control is not
                                  supported on most of them.

and, for access ports that are already shut down:
  switchport access vlan <unused> V-220641.

WHAT IT DOES NOT PUSH
V-220623 (802.1x/MAB) - see UNPUSHED_RULES, printed on every run.
V-220634 (IP Source Guard) and V-220635 (DAI) have their own scripts, both
split out because they trust only the DHCP snooping binding table, so a
statically addressed host with no lease has its traffic dropped once either
lands.
"""

import argparse
import re

import netauto
import stig_common

# V-220636 broadcast thresholds in bps, keyed by the alphabetic part of the
# interface name. DISA's Fix Text only enumerates ranges for Gigabit (10M-1G)
# and 10-Gigabit (100M-10G) ports; the faster Catalyst 9000 types below carry
# the same ~2%-of-line-rate rule forward rather than inventing a second one.
# Anything not listed - Port-channel, plain Ethernet - takes the Gigabit-range
# default, since a bundled or negotiated speed is not visible from the name.
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


def storm_control_command(interface_name):
    """V-220636: DISA's own Fix Text notes storm control is not supported on
    most FastEthernet interfaces - those are skipped entirely rather than given
    a threshold that would likely just be rejected. Everything else gets a
    threshold scaled to ~2% of link speed, looked up from the interface-name
    prefix (see STORM_CONTROL_BPS)."""
    if interface_name.startswith('FastEthernet'):
        return None
    prefix_match = re.match(r'[A-Za-z-]+', interface_name)
    prefix = prefix_match.group(0) if prefix_match else ''
    bps = STORM_CONTROL_BPS.get(prefix, STORM_CONTROL_BPS_DEFAULT)
    return f'storm-control broadcast level bps {bps}'


def shutdown_access_ports(cfg, access_names):
    """Return the subset of access_names whose interface block has 'shutdown' -
    used by V-220641 to reassign only ports that are already disabled."""
    shutdown = []
    for chunk in re.split(r'^(?=interface \S+)', cfg, flags=re.M):
        m = re.match(r'interface (\S+)', chunk)
        if m and m.group(1) in access_names and re.search(r'^\s*shutdown\s*$', chunk, re.M):
            shutdown.append(m.group(1))
    return shutdown


def unassigned_access_ports(cfg, access_names):
    """Return the subset of access_names still on the default VLAN - no
    explicit 'switchport access vlan' line, or an explicit VLAN 1. Only these
    get default_access_vlan pushed.

    A port already assigned to another VLAN was put there deliberately, and
    overwriting that assignment is not this script's job - V-220642 only
    requires host-facing ports off VLAN 1, not on any particular VLAN.
    Confirmed the hard way on the rebuilt lab (2026-08-28): S1's Gi0/0 carries
    the automation host on the management VLAN, and re-VLANing every access
    port moved it too - which cut the very session pushing the change (netmiko
    ReadTimeout mid-push) and left the switch unreachable until a console fixed
    it. The old topology never exposed this because its management path rode
    trunk ports, which this script never touches at all."""
    unassigned = []
    for chunk in re.split(r'^(?=interface \S+)', cfg, flags=re.M):
        m = re.match(r'interface (\S+)', chunk)
        if not m or m.group(1) not in access_names:
            continue
        vlan = re.search(r'^\s*switchport access vlan (\d+)\s*$', chunk, re.M)
        if vlan is None or vlan.group(1) == '1':
            unassigned.append(m.group(1))
    return unassigned


# Rules this script could push a command for and does not. Printed on every
# run: an unpushed fix the operator does not know about is one they find out
# about from an assessor.
UNPUSHED_RULES = [
    ('V-220623 (802.1x/MAB)',
     'no `authentication port-control auto`, `dot1x pae authenticator` or `mab` is '
     'pushed to any port. Without a reachable RADIUS authenticator and a supplicant '
     'on the endpoint, port-control auto blocks the port - an outage on an access '
     'switch, not a hardening step. Deploy 802.1x with a NAC design, then re-audit. '
     'l2_stig_harden_aaa.py still pushes the global prerequisites, which are inert '
     'while no port is set to authenticate.'),
]

# Rules satisfied as a side effect of the access-port mode/VLAN push, not by
# a dedicated command of their own.
SIDE_EFFECT_RULES = [
    'V-220642 (no default VLAN on host ports)',
    'V-220645 (user-facing ports as access)',
]

parser = argparse.ArgumentParser(
    description='Push access/host-facing port L2S STIG fixes to a device from inventory.yaml. '
                'Trunk ports are handled by l2_stig_harden_trunk_ports.py and are never '
                'touched here.')
parser.add_argument('device', help='Device name as it appears in inventory.yaml (e.g. S1)')
args = parser.parse_args()

device_name = args.device

all_devices = netauto.load_inventory()
device_info = netauto.require_devices(all_devices, [device_name])[device_name]
username, password = netauto.get_credentials()

net_connect = netauto.connect(device_name, device_info, username, password)
if net_connect is None:
    raise SystemExit(1)

running_config = str(net_connect.send_command('show running-config'))
access_ports, trunk_ports = stig_common.switchport_names(running_config)

# V-220641: already-shutdown access ports get reassigned to the designated
# unused VLAN (safe - they are not passing traffic). The VLAN's own database
# entry is created by l2_stig_harden_global.py, not here.
unused_vlan = netauto.load_unused_vlan()
disabled_ports = shutdown_access_ports(running_config, access_ports) if unused_vlan else []

# Default VLAN for host-facing ports, from inventory.yaml rather than a prompt.
# A freshly built port has no explicit switchport mode/VLAN at all, which
# silently breaks other access-port fixes that require the port to be in access
# mode first - confirmed live on a fresh S3 in GNS3.
default_access_vlan = netauto.load_default_access_vlan()
default_vlan_ports = unassigned_access_ports(running_config, access_ports) if default_access_vlan else []

access_fixes = ['switchport mode access', 'spanning-tree portfast', 'switchport block unicast']
storm_control_ports = {name: cmd for name in access_ports if (cmd := storm_control_command(name))}

commands = []
for name in access_ports:
    commands.append(f'interface {name}')
    commands += access_fixes
    if name in default_vlan_ports:
        commands.append(f'switchport access vlan {default_access_vlan}')
    if name in storm_control_ports:
        commands.append(storm_control_ports[name])
for name in disabled_ports:
    commands.append(f'interface {name}')
    commands.append(f'switchport access vlan {unused_vlan}')

applied_fixes = {}
if access_ports:
    applied_fixes['Default access mode/VLAN'] = (
        f'switchport mode access (on {len(access_ports)} access port(s))'
        + (f'; switchport access vlan {default_access_vlan} (on the {len(default_vlan_ports)} '
           'still on VLAN 1 - explicit assignments elsewhere kept)' if default_access_vlan else '')
    )
    applied_fixes['V-220630b (PortFast, required for BPDU Guard to activate)'] = \
        f'spanning-tree portfast (on {len(access_ports)} access port(s))'
    applied_fixes['V-220632 (UUFB)'] = (
        f'switchport block unicast (on {len(access_ports)} access port(s) - not supported on '
        'lab vios_l2, kept for real hardware)')
    if storm_control_ports:
        applied_fixes['V-220636 (storm control)'] = (
            f'storm-control broadcast level bps ... (speed-scaled, on {len(storm_control_ports)} '
            f'of {len(access_ports)} access port(s) - not supported on lab vios_l2, kept for '
            'real hardware)')
if disabled_ports:
    applied_fixes['V-220641a (disabled ports to unused VLAN)'] = (
        f'switchport access vlan {unused_vlan} (on {len(disabled_ports)} disabled port(s): '
        f'{", ".join(disabled_ports)})')

output = net_connect.send_config_set(commands) if commands else ''
net_connect.disconnect()
netauto.log_push('l2_stig_harden_access_ports.py', device_name, username, commands)

if commands:
    print(f'Access-port hardening commands pushed to {device_name}:')
    for command in commands:
        print('  ' + netauto.redact_secrets(command))
    print()
    print(netauto.redact_output(output))

print('\nRules addressed by this pass:')
for rule in applied_fixes:
    print('  - ' + rule)

if not access_ports:
    print('\nNo access/host-facing switchports found - nothing to push for V-220630b/632/636/641.')
elif not storm_control_ports:
    print("\nSkipped V-220636 (storm control) - every access port is FastEthernet, not "
          "supported per the STIG's own Fix Text note.")
if access_ports and not default_access_vlan:
    print('\nSkipped default access VLAN assignment - add default_access_vlan to inventory.yaml '
          'to include it. Access ports still get switchport mode access, just no explicit VLAN.')
if not unused_vlan:
    print('\nSkipped V-220641 (unused VLAN) - add unused_vlan to inventory.yaml to include it.')
elif not disabled_ports:
    print('\nNo disabled (shutdown) access ports found - nothing to reassign for V-220641.')

print(f'\n{len(trunk_ports)} trunk port(s) were classified and deliberately left alone. '
      'Run l2_stig_harden_trunk_ports.py for V-220629/633b/635b/640/643/646 - separately, '
      'because those are uplink commands and this session is probably riding one.')
print('V-220634 (IP Source Guard) is pushed separately by l2_stig_harden_ipsg.py.')
print('V-220635 (DAI) is pushed separately by l2_stig_harden_dai.py.')

print('\nDeliberately NOT pushed - a finding after this script runs, and meant to be:')
for rule, why in UNPUSHED_RULES:
    print(f'  - {rule}: {why}')

print('\nRules satisfied as a side effect of the access-port mode/VLAN push above, not by a '
      'dedicated command:')
for rule in SIDE_EFFECT_RULES:
    print('  - ' + rule)
