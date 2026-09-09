# $language = "Python3"
# $interface = "1.0"

"""Push the logging/audit and access-control STIG fixes to every saved
SecureCRT session, unattended.

READ THIS FIRST - THIS SCRIPT CONFIGURES DEVICES
Every other script in this folder is read-only and says so: capture_l2s.py,
capture_l2s_bulk.py and inventory_l2s.py send `show` commands and one
session-scoped `terminal length 0`, and each of their docstrings promises that
nothing is configured on any device. This one breaks that promise deliberately,
which is why it is a separate file with a separate name rather than a flag on
one of them. It logs into switches on its own authority and writes to their
running-config. That is a materially different thing to put in front of
whoever approved the audit tooling, and it deserves its own approval.

WHY IT EXISTS ALONGSIDE scripts/l2_stig_harden_logging_access.py
That script does the same job over netmiko, and netmiko cannot be installed on
the machine these switches are reachable from - which is the entire reason this
folder exists. Same fixes, same order, same rule numbers; different transport.
The command lists are duplicated rather than imported because nothing here may
import from the wider repository, and tests/test_securecrt_harden.py asserts
the two copies are identical so they cannot drift.

WHAT IT PUSHES
Logging/audit, access control, and the SSH transport crypto (V-220555/220556).
Nothing that changes how a switch forwards or converges: no spanning-tree mode,
no VLAN database, no `no <service>` lines, nothing per-interface. See the
netmiko script's docstring for the rule-by-rule breakdown.

The one thing the netmiko script reads from inventory.yaml is the syslog
collectors, and nothing in this folder may read that file, so the run asks for
them instead. Two or nothing, the same rule the netmiko script applies: a
switch logging to a single collector is a partial fix for V-220568/220620 that
reads in a report as a finished one.

WHAT IT DOES NOT DO
It never writes startup-config. That is the escape hatch and it is deliberate:
until someone runs `copy running-config startup-config`, a reload puts the
switch back exactly as it was. Re-audit first, then save.

It never aborts a run. A switch that is offline, refusing credentials or not a
Cisco switch is logged and skipped, the same as the read-only walks - on a
fleet of hundreds not all of them answer on a given night.

THE VTY LINES ARE OFF UNLESS ASKED FOR
Everything else here is reversible from any session that can still reach the
switch. The vty block decides how many sessions there can be, so a mistake in
it is the one mistake that takes away the means of fixing itself. The run asks
before including it, defaulting to no, and the range is read off each switch
rather than assumed. What caps inbound sessions is how many vty lines answer,
so a limit of 5 means vty 0-4 answer and everything above them does not. IOS XE
ships `line vty 0 4` AND `line vty 5 15`: configuring only the first range
there leaves eleven more answering on a switch whose row claims a five-session
limit.
"""

import json
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


# Where the run log is written. Created if missing.
OUTPUT_DIR = r'C:\Documents\netauto_hardening'

# Drop a file with this name in the output folder to stop a run cleanly at the
# end of the current switch.
STOP_FILE = 'STOP'

# How many session names the confirmation lists before it stops naming them.
SESSIONS_SHOWN = 12

# Kept identical to scripts/l2_stig_harden_logging_access.py, which cannot be
# imported from here - see this file's docstring, and the test that pins them
# equal. Order matters: the archive block descends two sub-modes and closes
# them again before anything after it is sent.
LOGGING_FIXES = [
    'service timestamps log datetime localtime',
    'logging buffered 64000 informational',
    'login on-failure log',
    'login on-success log',
    'logging userinfo',
    'logging trap critical',
    'file privilege 15',
]

ACCESS_CONTROL_FIXES = [
    'login block-for 900 attempts 3 within 120',
]

# V-220555/220607 and V-220556/220608 - SSH transport crypto. See the netmiko
# script for the full reasoning; the short version is that the MAC line is
# DISA's V-220555 example verbatim, the encryption line deliberately is not
# (`aes256-gcm aes256-ctr` rather than the example's `aes256-ctr aes192-ctr
# aes128-ctr` - both FIPS-approved, and this offers less than the example, not
# more), and both REPLACE the switch's algorithm list rather than adding to it.
# An image without `aes256-gcm` rejects the whole line and keeps what it had,
# which lands in this run's rejected column rather than passing unnoticed.
SSH_CRYPTO_FIXES = [
    'ip ssh version 2',
    'ip ssh server algorithm mac hmac-sha2-512 hmac-sha2-256',
    'ip ssh server algorithm encryption aes256-gcm aes256-ctr',
]

ARCHIVE_LOGGING_FIX = [
    'archive',
    'log config',
    'logging enable',
    'logging size 1000',
    'notify syslog contenttype plaintext',
    'hidekeys',
    'exit',
    'exit',
]

CONSOLE_FIX = ['line con 0', 'exec-timeout 5 0']

# The organization-defined number the rest of this project pushes. DISA's
# example says 2; the rule says "organization-defined" and its finding sentence
# only asks that a limit exist. Kept equal to the netmiko script's, which the
# test pins.
CONCURRENT_SESSIONS = 5
EXEC_TIMEOUT = 'exec-timeout 5 0'

# IOS answers a bad command with a line starting '%'. Collected per switch and
# reported rather than raised: one rejected line on an older image is worth
# knowing about and is not a reason to abandon the other fixes that landed.
ERROR_MARKER = '%'

LOG_COLUMNS = ('hostname', 'ip_address', 'outcome', 'rejected', 'comment',
               'session', 'timestamp')


def base_commands():
    """Everything that cannot change who may log in."""
    return list(LOGGING_FIXES) + list(ACCESS_CONTROL_FIXES) + list(SSH_CRYPTO_FIXES) \
        + list(ARCHIVE_LOGGING_FIX) + list(CONSOLE_FIX)


SYSLOG_MINIMUM = 2

_IPV4 = re.compile(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$')


def _is_ipv4(text):
    match = _IPV4.match(text)
    return bool(match) and all(0 <= int(part) <= 255 for part in match.groups())


def inventory_path():
    """The repository's inventory.yaml, if this folder is still inside it."""
    return os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        'inventory.yaml')


def inventory_syslog_servers(path=None):
    """The syslog collectors already written down in inventory.yaml, or [].

    Nothing in this folder may import from the wider repository - it gets
    copied to machines that do not have one - but inventory.yaml is written as
    JSON, so reading it takes the standard library and nothing else, and a
    missing file is just an empty list. The netmiko script takes these from the
    same place; asking someone to retype two addresses they have already
    written down is how one of them ends up with a digit wrong.

    Only real addresses come back. The file ships with `x.x.x.x` placeholders,
    and a placeholder offered as a default is worse than an empty box."""
    try:
        with open(path or inventory_path(), encoding='utf-8') as handle:
            services = json.load(handle).get('services') or {}
    except Exception:
        return []
    return [str(entry) for entry in (services.get('syslog_servers') or [])
            if _is_ipv4(str(entry))]


def syslog_fixes(answer):
    """`logging host` per collector, and the entries that were not addresses.

    The netmiko script takes these from inventory.yaml, which nothing here can
    read, so they are asked for once per run instead. Fewer than two produces
    no commands at all: DISA asks for two collectors and the netmiko script
    refuses to claim V-220568/220620 on one, because a switch logging to a
    single server is a partial fix that reads in a report as a finished one."""
    entries = [part for part in re.split(r'[,;\s]+', answer or '') if part]
    bad = [entry for entry in entries if not _is_ipv4(entry)]
    if bad or len(entries) < SYSLOG_MINIMUM:
        return [], entries, bad
    return ['logging host {0}'.format(ip) for ip in entries], entries, bad


def _line_range(first, last):
    return 'line vty {0} {1}'.format(first, last) if last > first else 'line vty {0}'.format(first)


def vty_fixes(highest_vty, sessions=CONCURRENT_SESSIONS):
    """The vty block, closing every line above the allowed count.

    `highest_vty` is read off the switch, not assumed - see highest_vty_line."""
    last_open = sessions - 1
    if last_open >= highest_vty:
        # Every line the switch has is inside the allowed count: nothing to
        # take out of service, and no second range to enter. On a switch with
        # only `line vty 0 4` and a limit of 5, this is DISA's own example.
        return [_line_range(0, highest_vty), 'session-limit {0}'.format(sessions),
                EXEC_TIMEOUT, 'transport input ssh']
    return [
        _line_range(0, highest_vty),
        'session-limit {0}'.format(sessions),
        EXEC_TIMEOUT,
        _line_range(0, last_open),
        'transport input ssh',
        _line_range(last_open + 1, highest_vty),
        'transport input none',
    ]


def highest_vty_line(prompt):
    """The highest vty line this switch has configured, and whether it was read.

    The second value is the one that matters: a wrong answer here means lines
    left answering that the run reports as closed, so the caller skips the vty
    block entirely rather than act on the 4 returned alongside a False."""
    try:
        output = capture_l2s.run_command('show running-config | include ^line vty', prompt)
    except Exception:
        return 4, False
    numbers = [int(n) for line in (output or '').splitlines() for n in re.findall(r'\d+', line)]
    return (max(numbers), True) if numbers else (4, False)


def send_config(commands, prompt):
    """Send a config block and return what the switch said back.

    One read at the end rather than one per command: the prompt changes as
    sub-modes are entered - `(config)#`, `(config-line)#` - so waiting for the
    base prompt after each line would hang on the first one. `end` returns to
    it, and everything the switch said arrives together."""
    crt.Screen.Send('configure terminal\r')
    for command in commands:
        crt.Screen.Send(command + '\r')
    crt.Screen.Send('end\r')
    output = crt.Screen.ReadString(prompt, capture_l2s.READ_TIMEOUT_SECONDS)
    if output is None:
        raise capture_l2s.CollectionError(
            'timed out in config mode',
            'Timed out waiting for the prompt after the configuration block.',
            'Config timeout')
    return output


def rejected_lines(output):
    """The switch's own complaints, one per rejected command."""
    return [line.strip() for line in (output or '').splitlines()
            if line.strip().startswith(ERROR_MARKER)]


class RunLog:
    """One row per session in the list, including the ones nothing answered
    from. A hardening run has to account for every switch it was pointed at as
    much as an audit does."""

    def __init__(self, directory):
        self.path = bulk.unused_path(
            directory, 'harden_log_' + time.strftime('%Y%m%d_%H%M%S'), '.csv')
        self.counts = {}
        with open(self.path, 'w', encoding='utf-8') as handle:
            handle.write(','.join(LOG_COLUMNS) + '\n')

    def record(self, session_path, host, outcome, rejected='', comment='', hostname=''):
        self.counts[outcome] = self.counts.get(outcome, 0) + 1
        row = (hostname or session_path, host, outcome, rejected, comment, session_path,
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
        'session database writes them.',
        'Harden - scope', '', False)
    if folder is None:
        return

    sessions, duplicates = bulk.dedupe_by_host(bulk.find_sessions(folder.strip()))
    if not sessions:
        crt.Dialog.MessageBox(
            'No saved sessions found under:\n{0}\n\nFolder filter: {1}'
            .format(os.path.join(bulk.config_path(), 'Sessions'), folder or '(none)'),
            'Nothing to do')
        return

    output_dir = crt.Dialog.Prompt('Write the run log to:', 'Harden - log folder', OUTPUT_DIR)
    if not output_dir:
        return
    try:
        if not os.path.isdir(output_dir):
            os.makedirs(output_dir)
    except OSError as error:
        crt.Dialog.MessageBox('Could not create {0}:\n{1}'.format(output_dir, error),
                              'Cannot write there')
        return

    known = inventory_syslog_servers()
    syslog_answer = crt.Dialog.Prompt(
        'Syslog server IP addresses, separated by commas. Leave blank to skip.\n\n'
        'DISA asks for two collectors (V-220568/220620), and one is not a partial pass,\n'
        'so a single address is not pushed.\n\n'
        + ('Filled in from inventory.yaml. Edit or clear it as you like.'
           if len(known) >= SYSLOG_MINIMUM else
           'inventory.yaml lists {0} usable address(es), so there is nothing to fill in\n'
           'from it - add a second collector there and this box fills itself next time.'
           .format(len(known))),
        'Harden - syslog servers', ', '.join(known), False)
    if syslog_answer is None:
        return
    syslog_commands, syslog_servers, not_addresses = syslog_fixes(syslog_answer)
    if not_addresses:
        # Stop before anything is configured rather than drop the typo quietly:
        # a dropped collector leaves the rule a finding on the whole fleet.
        crt.Dialog.MessageBox(
            'Not an IPv4 address:\n  {0}\n\nNothing was configured. Run the script again '
            'with the addresses corrected, or blank to skip the syslog fix.'
            .format('\n  '.join(not_addresses)),
            'Harden - check the syslog addresses')
        return
    if syslog_servers and not syslog_commands:
        crt.Dialog.MessageBox(
            'Only {0} syslog server given. DISA asks for {1}, so no `logging host` line will '
            'be pushed and V-220568/220620 stays a finding.\n\nNothing was configured. Run '
            'again with both addresses to include it.'
            .format(len(syslog_servers), SYSLOG_MINIMUM),
            'Harden - one syslog server is not a pass')
        return

    commands = base_commands() + syslog_commands
    # Asked rather than assumed, and defaulting to No: this is the only part of
    # the run that can leave a switch refusing the next login.
    with_vty = crt.Dialog.MessageBox(
        'Also limit concurrent sessions on the vty lines?\n\n'
        'This closes every vty line above the first {0}, so the switch will accept only {0} '
        'SSH session(s) afterwards and refuse the next one - including yours, if {0} are '
        'already open. The range is read from each switch, so `line vty 5 15` is closed too '
        'where it exists; on a switch whose only range is `line vty 0 4` there is nothing '
        'above it to close.\n\n'
        'Everything else in this run is reversible from any session that can reach the switch. '
        'This is not.\n\n'
        'No is the safe answer, and leaves V-220518/220570 a finding.'
        .format(CONCURRENT_SESSIONS),
        'Harden - include the vty session limit?', 4 | 48) == 6  # MB_YESNO | MB_ICONWARNING

    # Named, not just counted. The scope prompt is a prefix match, so a filter
    # meant for one switch quietly takes in its neighbours - `10.1.2.3` also
    # matches `10.1.2.30`. On a run that configures, the list is the check.
    listed = '\n'.join('  ' + path for path, _host in sessions[:SESSIONS_SHOWN])
    if len(sessions) > SESSIONS_SHOWN:
        listed += '\n  ...and {0} more'.format(len(sessions) - SESSIONS_SHOWN)

    preview = '\n'.join('  ' + command for command in commands)
    if with_vty:
        preview += '\n\n  ...then the vty block, its range read from each switch:\n' + \
                   '\n'.join('    ' + command for command in vty_fixes(4, CONCURRENT_SESSIONS))
    if crt.Dialog.MessageBox(
            '{0} device(s) to configure{1}:\n{4}\n\n'
            'THIS WRITES TO running-config ON EVERY ONE OF THEM.\n\n'
            'Commands:\n{2}\n\n'
            'startup-config is NOT written, so a reload reverts any switch until you save it '
            'deliberately.\n\n'
            'To stop early, create a file named {3} in the log folder.\n\n'
            'Begin?'.format(len(sessions),
                            ' ({0} duplicate session(s) collapsed)'.format(len(duplicates))
                            if duplicates else '', preview, STOP_FILE, listed),
            'Harden - confirm', 4 | 48) != 6:
        return

    connect_state = {}
    log = RunLog(output_dir)
    for session_path, host, kept in duplicates:
        log.record(session_path, host, 'duplicate', comment='Same address as ' + kept)
    stop_path = os.path.join(output_dir, STOP_FILE)
    stopped = False

    def visit_one(index, session_path, host):
        crt.Session.SetStatusText('Hardening {0}/{1}: {2}'
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
        pushed = list(commands)
        note = ''
        vty_skipped = False
        if with_vty:
            highest, read_ok = highest_vty_line(prompt)
            if read_ok:
                pushed += vty_fixes(highest, CONCURRENT_SESSIONS)
                note = ('vty 0-{0} left answering, {1}-{2} closed'
                        .format(CONCURRENT_SESSIONS - 1, CONCURRENT_SESSIONS, highest))
            else:
                # Falling back to 0-4 here would close five lines on a switch
                # that also ships `line vty 5 15`, leave eleven answering, and
                # write a row saying the session limit is set. A switch this
                # run could not read is one for a human, not a guess.
                vty_skipped = True
                note = ('vty block SKIPPED - `line vty` could not be read from this '
                        'switch. Closing an assumed 0-4 would leave `line vty 5 15` '
                        'answering while this row claimed a {0}-session limit. Set the '
                        'limit here by hand.'.format(CONCURRENT_SESSIONS))

        output = send_config(pushed, prompt)
        rejected = rejected_lines(output)
        outcome = 'hardened - vty skipped' if vty_skipped else 'hardened'
        if rejected:
            outcome += ' with rejections'
        log.record(session_path, host, outcome,
                   rejected='; '.join(rejected)[:300], comment=note, hostname=hostname)

    crt.Screen.Synchronous = True
    try:
        for index, (session_path, host) in enumerate(sessions, 1):
            if os.path.exists(stop_path):
                stopped = True
                break
            # Nothing that happens to one switch may end the walk - the same
            # rule the read-only walks run under, and for the same reason.
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
        '{0}\n\n{1}\n\nRun log:\n{2}\n\nOne row per session in the list, including the ones '
        'nothing answered from. Any switch whose row says `hardened with rejections` had a '
        'command its image does not have - the rejected line is in the row.\n\n'
        'startup-config was NOT written on any switch. Re-audit, then save deliberately.'
        .format('Run stopped early by the STOP file.' if stopped else 'Run complete.',
                log.summary() or 'nothing configured', log.path),
        'Harden finished')


# See capture_l2s.py's tail: SecureCRT injects `crt` before running, so this is
# truthy there and None on a plain import, which is what lets the tests drive
# main() with a stand-in and no terminal anywhere.
if crt is not None:
    capture_l2s.crt = crt
    bulk.crt = crt
    main()
