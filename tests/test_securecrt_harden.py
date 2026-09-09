#!/usr/bin/env python
"""Verification for securecrt/harden_l2s_bulk.py - the walk that configures.

Run it directly: `python3 tests/test_securecrt_harden.py`. No framework, no
SecureCRT, no devices.

Every other script in securecrt/ is read-only, and the suites for them mostly
guard against a run that finishes looking healthy while leaving switches out.
This one writes to running-config on a whole fleet, so what is guarded here is
different in kind:

  * that it pushes exactly what the netmiko script pushes, in the same order.
    The two lists are duplicated because nothing in securecrt/ may import from
    the wider repository, and duplicated constants drift - which here would
    mean two tools that both claim to apply the same STIG fixes and do not.

  * that the vty block is off unless asked for, and that when it is asked for
    the range comes off the switch. What caps inbound sessions is how many vty
    lines answer, so a limit of 5 means vty 0-4 answer and nothing above them
    does. IOS XE ships `line vty 0 4` AND `line vty 5 15`; configuring only the
    first leaves eleven answering under a row claiming a five-session limit.

  * that a switch which rejects a command is recorded as such and does not take
    the rest of the fleet down with it.
"""

import csv
import io
import os
import re
import sys
import tempfile

PROJECT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(PROJECT, 'scripts'))
sys.path.insert(0, os.path.join(PROJECT, 'securecrt'))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import capture_l2s
import capture_l2s_bulk as bulk
import harden_l2s_bulk as harden
from fixtures import OUTPUTS

failures = []


def check(name, condition, detail=''):
    print(f'  {"ok  " if condition else "FAIL"} {name}')
    if not condition:
        if detail:
            print(f'       {detail}')
        failures.append(name)


def netmiko_script_lists():
    """The command lists out of scripts/l2_stig_harden_logging_access.py.

    Read by executing the file's constant section rather than importing it:
    the script parses argv and connects at import, so importing it here would
    try to reach a switch."""
    path = os.path.join(PROJECT, 'scripts', 'l2_stig_harden_logging_access.py')
    source = open(path, encoding='utf-8').read().split('parser = argparse.ArgumentParser')[0]
    namespace = {}
    exec(compile(source, path, 'exec'), namespace)
    return namespace


class FakeScreen:
    def __init__(self, outputs, reject=()):
        self.outputs = outputs
        self.reject = reject
        self.Synchronous = False
        self.prompt = 'TESTSW01#'
        self.sent = []
        self._pending = ''
        self.events = []
        self.CurrentRow = 5
        self.CurrentColumn = len(self.prompt) + 1

    def Get(self, *_args):
        return self.prompt

    def Send(self, text):
        command = text.rstrip('\r\n')
        if not command:
            return
        self.sent.append(command)
        self.events.append(('send', command))
        if command == 'terminal length 0':
            self._pending += f'{command}\r\n'
            return
        body = self.outputs.get(command, '')
        # A switch answers a command its image does not have with a '%' line.
        if command in self.reject:
            body = f'% Invalid input detected at "^" marker.'
        self._pending += f'{command}\r\n{body}\r\n'

    def ReadString(self, _terminator, timeout=None):
        self.events.append(('read', _terminator))
        pending, self._pending = self._pending, ''
        return pending


class FakeSession:
    def __init__(self, crt_stub):
        self.crt = crt_stub
        self.Connected = False

    def Connect(self, connect_string, _suppress=False):
        session = connect_string.split('"')[1]
        self.crt.attempts.append(session)
        outcome = self.crt.behaviour.get(session, 'ok')
        if outcome != 'ok':
            self.crt.last_error = 'The connection attempt timed out. No response from host.'
            raise Exception(self.crt.last_error)
        self.Connected = True

    def Disconnect(self):
        self.Connected = False

    def SetStatusText(self, _text):
        pass


class FakeDialog:
    def __init__(self, crt_stub):
        self.crt = crt_stub

    def Prompt(self, _message, title='', default='', _password=False):
        if 'scope' in title.lower():
            return ''
        if 'syslog' in title.lower():
            self.crt.syslog_prompted = True
            self.crt.syslog_default = default
            return default if self.crt.syslog is None else self.crt.syslog
        return self.crt.output_dir

    def MessageBox(self, message, title='', flags=0):
        self.crt.messages.append((title, message))
        if 'vty session limit' in title.lower():
            return 6 if self.crt.with_vty else 7   # IDYES / IDNO
        return 6 if flags & 4 else 1


class FakeCRT:
    def __init__(self, output_dir, behaviour, outputs, with_vty=False, reject=(), syslog=''):
        self.output_dir = output_dir
        self.syslog = syslog
        self.syslog_default = None
        self.syslog_prompted = False
        self.behaviour = behaviour
        self.with_vty = with_vty
        self.attempts = []
        self.messages = []
        self.last_error = ''
        self.Screen = FakeScreen(outputs, reject)
        self.Session = FakeSession(self)
        self.Dialog = FakeDialog(self)

    def GetLastErrorMessage(self):
        return self.last_error

    def Sleep(self, _ms):
        pass


VTY_RANGES = 'line vty 0 4\nline vty 5 15'

# What `show running-config | include ^ip ssh` gives back after a clean push.
SSH_LINES = ('ip ssh version 2\n'
             'ip ssh server algorithm mac hmac-sha2-512 hmac-sha2-256\n'
             'ip ssh server algorithm encryption aes256-gcm aes256-ctr')


def run_harden(tmpdir, sessions, behaviour=None, with_vty=False, reject=(),
               vty_output=VTY_RANGES, syslog='', ssh_output=SSH_LINES, inventory=None):
    outputs = dict(OUTPUTS)
    outputs['show running-config | include ^line vty'] = vty_output
    outputs['show running-config | include ^ip ssh'] = ssh_output
    fake = FakeCRT(tmpdir, behaviour or {}, outputs, with_vty, reject, syslog)
    harden.crt = capture_l2s.crt = bulk.crt = fake
    original = bulk.find_sessions
    original_inventory = harden.inventory_path
    if inventory is not None:
        harden.inventory_path = lambda: inventory
    bulk.find_sessions = lambda _filter='': list(sessions)
    try:
        harden.main()
    finally:
        bulk.find_sessions = original
        harden.inventory_path = original_inventory
        harden.crt = capture_l2s.crt = bulk.crt = None
    return fake


def log_rows(tmpdir):
    """Every row written under tmpdir, across every log file in it.

    A test that runs the walk twice gets two files - `unused_path` keeps the
    second run from overwriting the first - so reading only one of them would
    silently drop half the rows this suite is checking."""
    paths = [os.path.join(tmpdir, n) for n in sorted(os.listdir(tmpdir))
             if n.startswith('harden_log_') and n.endswith('.csv')]
    rows = []
    for path in sorted(paths, key=os.path.getmtime):
        with io.open(path, encoding='utf-8', newline='') as handle:
            lines = handle.read().splitlines()
        if not lines:
            continue
        rows.extend(csv.DictReader(lines))
    return rows


def test_commands_match_the_netmiko_script():
    """The two copies exist because securecrt/ may not import from the wider
    repository. Duplicated constants drift, and drift here means two tools that
    both claim to apply the same STIG fixes and quietly do not."""
    print('the command lists match scripts/l2_stig_harden_logging_access.py')
    other = netmiko_script_lists()
    check('logging fixes, in order',
          harden.LOGGING_FIXES == list(other['LOGGING_FIXES'].values()),
          f"securecrt={harden.LOGGING_FIXES}\n       netmiko={list(other['LOGGING_FIXES'].values())}")
    check('access control fixes, in order',
          harden.ACCESS_CONTROL_FIXES == list(other['ACCESS_CONTROL_FIXES'].values()),
          harden.ACCESS_CONTROL_FIXES)
    check('ssh crypto fixes, in order',
          harden.SSH_CRYPTO_FIXES == list(other['SSH_CRYPTO_FIXES'].values()),
          f"securecrt={harden.SSH_CRYPTO_FIXES}\n       netmiko={list(other['SSH_CRYPTO_FIXES'].values())}")
    check('the archive block, including its two closing exits',
          harden.ARCHIVE_LOGGING_FIX == other['ARCHIVE_LOGGING_FIX'],
          harden.ARCHIVE_LOGGING_FIX)
    check('the console line', harden.CONSOLE_FIX == other['CONSOLE_FIX'], harden.CONSOLE_FIX)
    check('the session count', harden.CONCURRENT_SESSIONS == other['CONCURRENT_SESSIONS'])
    for highest in (4, 15):
        check(f'the vty block on a switch whose highest line is {highest}',
              harden.vty_fixes(highest) == other['vty_fixes'](highest),
              harden.vty_fixes(highest))


def test_the_default_run_touches_no_vty_line(tmpdir):
    """The one part of this that can leave a switch refusing the next login is
    the one part that has to be asked for."""
    print('\nby default it configures logging and access control, and no vty line')
    fake = run_harden(tmpdir, [('node-a/sw-1', '10.0.0.1')], with_vty=False)
    sent = fake.Screen.sent
    check('it entered config mode and left it', 'configure terminal' in sent and 'end' in sent,
          sent)
    check('the logging fixes were sent',
          all(command in sent for command in harden.LOGGING_FIXES), sent)
    check('and the ssh crypto lines',
          all(command in sent for command in harden.SSH_CRYPTO_FIXES), sent)
    check('so was the archive block, with its exits',
          sent.count('exit') >= 2 and 'hidekeys' in sent, sent)
    check('and the console timeout', 'line con 0' in sent, sent)
    check('no vty line was touched',
          not any(command.startswith('line vty') for command in sent), sent)
    check('and nothing was saved to startup-config',
          not any('startup' in command for command in sent), sent)
    check('the switch is logged as hardened',
          log_rows(tmpdir)[0]['outcome'] == 'hardened', log_rows(tmpdir))


def test_vty_range_comes_off_the_switch(tmpdir):
    """IOS XE ships `line vty 0 4` AND `line vty 5 15`. Configuring only the
    first leaves eleven lines answering while the run reports a five-session
    limit - the same false claim the netmiko script made before it read the
    range."""
    print('\nwith the vty block asked for, the range is read from the switch')
    fake = run_harden(tmpdir, [('node-a/sw-1', '10.0.1.1')], with_vty=True)
    sent = fake.Screen.sent
    check('it asked the switch which vty lines it has',
          'show running-config | include ^line vty' in sent, sent)
    check('the closing range is vty 5-15, the lines above the allowed 5',
          'line vty 5 15' in sent, [c for c in sent if c.startswith('line vty')])
    check('the first five lines are left answering ssh',
          'line vty 0 4' in sent and 'transport input ssh' in sent, sent)
    check('and the rest answer nothing', 'transport input none' in sent, sent)
    check('the log says which lines were left open',
          'vty 0-4' in log_rows(tmpdir)[0]['comment'], log_rows(tmpdir))

    # A switch that answers the question with nothing must not be assumed to
    # have only vty 0-4: that assumption is what leaves lines answering.
    unread = run_harden(tmpdir, [('node-b/sw-2', '10.0.1.2')], with_vty=True, vty_output='')
    row = [r for r in log_rows(tmpdir) if r['session'] == 'node-b/sw-2'][0]
    check('an unreadable range is flagged for a human rather than assumed away',
          'SKIPPED' in row['comment'] and 'by hand' in row['comment'], row)
    check('and no guessed vty range is pushed to it',
          not any(command.startswith('line vty') for command in unread.Screen.sent),
          unread.Screen.sent)
    check('while the logging and access control fixes still landed',
          all(command in unread.Screen.sent for command in harden.LOGGING_FIXES),
          unread.Screen.sent)
    check('and the row says so rather than reading as a full harden',
          row['outcome'] == 'hardened - vty skipped', row)


def test_a_five_line_switch_gets_disas_example_verbatim(tmpdir):
    """The limit is 5 and a switch with only `line vty 0 4` has exactly five
    lines, so there is nothing above them to take out of service. What is left
    is DISA's first Check Content example with the organization's number in
    it - and no `transport input none`, which would be closing lines that are
    inside the limit."""
    print('\na switch whose only range is vty 0-4 needs nothing closed')
    fake = run_harden(tmpdir, [('node-a/sw-1', '10.0.6.1')], with_vty=True,
                      vty_output='line vty 0 4')
    sent = fake.Screen.sent
    check('the range is entered once, not twice',
          sent.count('line vty 0 4') == 1, [c for c in sent if c.startswith('line vty')])
    check('the limit and ssh transport are set on it',
          'session-limit 5' in sent and 'transport input ssh' in sent, sent)
    check('and no line is taken out of service, because none is above the limit',
          'transport input none' not in sent, sent)


def test_a_rejected_command_is_recorded_not_fatal(tmpdir):
    """`file privilege 15` is rejected by images that do not have it - already
    seen on the lab's vios_l2. One rejected line is worth knowing about and is
    not a reason to abandon the fixes that landed, or the rest of the fleet."""
    print('\na command the image rejects is recorded, and the walk carries on')
    run_harden(tmpdir, [('node-a/sw-1', '10.0.2.1'), ('node-a/sw-2', '10.0.2.2')],
               reject=('file privilege 15',))
    rows = {row['session']: row for row in log_rows(tmpdir)}
    first = rows.get('node-a/sw-1', {})
    check('the switch is logged as hardened with rejections',
          first.get('outcome') == 'hardened with rejections', first)
    check("and the switch's own complaint is in the row",
          'Invalid input' in first.get('rejected', ''), first)
    # The stand-in rejects the line on every switch, so what this proves is
    # that the walk reached and configured the switch after the one that
    # complained - not that the second one came back clean.
    check('the switch after it was still reached and configured',
          rows.get('node-a/sw-2', {}).get('outcome', '').startswith('hardened'), rows)


def test_the_ssh_lines_are_read_back_off_the_switch(tmpdir):
    """A line the parser accepted is not the same as a line in running-config.

    `ip ssh version 2` is the one this bit on: some IOS XE trains no longer
    render it (v1 is gone, so v2-only is not a setting any more), and an image
    without `aes256-gcm` rejects that whole line and keeps the list it had.
    Neither shows up in the config block's own output, and a run that reports
    `hardened` for a switch missing all three SSH lines is the false clean
    result this project exists to avoid."""
    print('\nthe ip ssh lines are read back, not assumed')
    fake = run_harden(tmpdir, [('node-a/sw-1', '10.0.8.1')])
    check('the switch is asked what it actually has',
          'show running-config | include ^ip ssh' in fake.Screen.sent, fake.Screen.sent)
    row = log_rows(tmpdir)[0]
    check('a clean push records all three lines',
          row['ssh'].count('ip ssh') == 3 and 'MISSING' not in row['ssh'], row['ssh'])
    check('and the outcome is a plain harden', row['outcome'] == 'hardened', row)

    # The reported symptom: everything else lands, `ip ssh version 2` does not.
    partial = run_harden(
        tmpdir, [('node-b/sw-2', '10.0.8.2')],
        ssh_output=('ip ssh server algorithm mac hmac-sha2-512 hmac-sha2-256\n'
                    'ip ssh server algorithm encryption aes256-gcm aes256-ctr'))
    row = [r for r in log_rows(tmpdir) if r['session'] == 'node-b/sw-2'][0]
    check('a line that did not land is named in the row',
          'MISSING' in row['ssh'] and 'ip ssh version 2' in row['ssh'].split('MISSING')[1],
          row['ssh'])
    check('and the outcome says so rather than reading as a clean harden',
          'ssh crypto incomplete' in row['outcome'], row)
    check('the other two are still recorded as present',
          'hmac-sha2-512' in row['ssh'].split('MISSING')[0], row['ssh'])

    none = run_harden(tmpdir, [('node-c/sw-3', '10.0.8.3')], ssh_output='')
    row = [r for r in log_rows(tmpdir) if r['session'] == 'node-c/sw-3'][0]
    check('a switch with no ip ssh lines at all is flagged, not passed',
          row['ssh'].startswith('NONE') and 'ssh crypto incomplete' in row['outcome'], row)


def test_every_config_command_is_read_before_the_next_is_sent(tmpdir):
    """Flow control, not politeness. The walk sets Screen.Synchronous for its
    whole run, and in synchronous mode SecureCRT holds the incoming stream until
    the script consumes it. Sending the whole block and reading once at the end
    left twenty-odd command echoes backing up behind a buffer nothing was
    emptying - the same mechanism that lost the DoD banner in read_prompt, and
    here it loses commands: they go out, and the line is not on the switch."""
    print('\nevery config line is read back before the next one is sent')
    fake = run_harden(tmpdir, [('node-a/sw-1', '10.0.9.1')])
    sends = [event for event in fake.Screen.events if event[0] == 'send']
    reads = [event for event in fake.Screen.events if event[0] == 'read']
    check('there is a read for every send, not one at the end',
          len(reads) >= len(sends), (len(sends), len(reads)))
    pairs = list(zip(fake.Screen.events, fake.Screen.events[1:]))
    unread = [a[1] for a, b in pairs if a[0] == 'send' and b[0] == 'send']
    check('no command is sent while the previous one is still unread', not unread, unread)


def test_unreachable_switches_are_rows(tmpdir):
    print('\na switch nobody could reach is a row, not a gap')
    run_harden(tmpdir, [('node-a/10.0.3.1 - b100-52', '10.0.3.1'), ('node-a/sw-2', '10.0.3.2')],
               behaviour={'node-a/10.0.3.1 - b100-52': 'timeout'})
    rows = {row['session']: row for row in log_rows(tmpdir)}
    unreachable = rows.get('node-a/10.0.3.1 - b100-52', {})
    check('it is logged rather than dropped',
          unreachable.get('outcome') == 'unreachable', rows)
    check('named by its bldg/trailer, like the read-only walks',
          unreachable.get('hostname') == 'b100-52', unreachable)
    check('and the walk carried on', rows.get('node-a/sw-2', {}).get('outcome') == 'hardened',
          rows)


def test_syslog_servers_are_two_or_none(tmpdir):
    """The netmiko script reads the collectors from inventory.yaml and pushes
    them only in pairs, because a switch logging to one server is a partial fix
    for V-220568/220620 that reads in a report as a finished one. Nothing here
    can read that file, so the same rule has to hold on what is typed in."""
    print('\nthe syslog collectors are pushed in pairs, or not at all')
    two = run_harden(tmpdir, [('node-a/sw-1', '10.0.5.1')], syslog='10.1.1.1, 10.1.1.2')
    check('both collectors are configured',
          'logging host 10.1.1.1' in two.Screen.sent and 'logging host 10.1.1.2' in two.Screen.sent,
          two.Screen.sent)

    one = run_harden(tmpdir, [('node-a/sw-1', '10.0.5.1')], syslog='10.1.1.1')
    check('a single collector configures nothing at all, not even the rest',
          not any(command.startswith('logging host') for command in one.Screen.sent)
          and 'configure terminal' not in one.Screen.sent, one.Screen.sent)
    check('and the run says why rather than dropping it quietly',
          any('not a pass' in title.lower() for title, _ in one.messages), one.messages)

    typo = run_harden(tmpdir, [('node-a/sw-1', '10.0.5.1')], syslog='10.1.1.1, 10.1.1.256')
    check('a typo stops the run before any switch is touched',
          'configure terminal' not in typo.Screen.sent, typo.Screen.sent)
    check('and it names the entry that was not an address',
          any('10.1.1.256' in message for _, message in typo.messages), typo.messages)


def test_syslog_servers_come_off_inventory_yaml_when_it_is_there(tmpdir):
    """Retyping two addresses that are already written down is how one of them
    ends up with a digit wrong. Nothing in securecrt/ may import from the
    repository, but inventory.yaml is JSON, so reading it costs nothing and is
    empty-handed rather than broken when the folder has been copied away."""
    print('\nthe syslog box fills itself from inventory.yaml')
    good = os.path.join(tmpdir, 'good.yaml')
    io.open(good, 'w', encoding='utf-8').write(
        '{"services": {"syslog_servers": ["10.2.2.1", "10.2.2.2"], "ntp_servers": []}}')
    check('both collectors are read back',
          harden.inventory_syslog_servers(good) == ['10.2.2.1', '10.2.2.2'],
          harden.inventory_syslog_servers(good))

    placeholder = os.path.join(tmpdir, 'placeholder.yaml')
    io.open(placeholder, 'w', encoding='utf-8').write(
        '{"services": {"syslog_servers": ["x.x.x.x"]}}')
    check('the shipped x.x.x.x placeholder is not offered as an address',
          harden.inventory_syslog_servers(placeholder) == [],
          harden.inventory_syslog_servers(placeholder))

    check('a missing file is an empty list, not an exception',
          harden.inventory_syslog_servers(os.path.join(tmpdir, 'nope.yaml')) == [])
    unparseable = os.path.join(tmpdir, 'bad.yaml')
    io.open(unparseable, 'w', encoding='utf-8').write('devices:\n  - not json\n')
    check('and so is a file this cannot parse',
          harden.inventory_syslog_servers(unparseable) == [])

    # End to end: with the file readable the box does not appear at all. Being
    # asked each run for two addresses that are written down is how a digit
    # gets typed wrong on switch four hundred; the confirmation still lists the
    # `logging host` lines, so nothing goes out unseen.
    fake = run_harden(tmpdir, [('node-a/sw-1', '10.0.7.1')], syslog=None, inventory=good)
    check('the run does not ask for what the file already answers',
          fake.syslog_prompted is False)
    check('and both collectors are configured from it',
          'logging host 10.2.2.1' in fake.Screen.sent
          and 'logging host 10.2.2.2' in fake.Screen.sent, fake.Screen.sent)
    check('the confirmation says where they came from',
          any('inventory.yaml' in message for title, message in fake.messages
              if 'confirm' in title.lower()), fake.messages)

    # A file that cannot answer still gets a box, and the box names the path it
    # looked at - the difference between "wrong folder" and "wrong contents".
    asked = run_harden(tmpdir, [('node-a/sw-1', '10.0.7.1')], syslog='', inventory=placeholder)
    check('an unusable file still prompts', asked.syslog_prompted is True)
    check('and the prompt names the path it looked at',
          any(placeholder in message for title, message in asked.messages
              if 'syslog' in title.lower())
          or asked.syslog_default == '', asked.messages)


def test_the_confirmation_says_what_it_will_do(tmpdir):
    """This writes to running-config on a fleet. Whoever presses Begin should
    have read the commands and the count first."""
    print('\nthe run says what it is about to configure, before it does')
    fake = run_harden(tmpdir, [('node-a/sw-1', '10.0.4.1')])
    confirm = ' '.join(message for title, message in fake.messages
                       if 'confirm' in title.lower())
    check('the confirmation names the device count', '1 device(s)' in confirm, confirm)
    check('and says outright that it writes to running-config',
          'WRITES TO running-config' in confirm, confirm)
    check('and lists the commands', 'logging userinfo' in confirm, confirm)
    check('and says startup-config is not written, so a reload reverts',
          'startup-config is NOT written' in confirm, confirm)
    check('and names the switch, since a one-switch scope is a prefix match',
          'node-a/sw-1' in confirm, confirm)

    # A scope typed for one switch that quietly took in its neighbours has to
    # be visible in the box, not just as a count that reads plausibly.
    many = run_harden(tmpdir, [('node-a/sw-{0}'.format(n), '10.0.4.{0}'.format(n))
                               for n in range(1, 20)])
    big = ' '.join(message for title, message in many.messages if 'confirm' in title.lower())
    check('a long list is truncated rather than filling the screen',
          'and 7 more' in big, big)


if __name__ == '__main__':
    test_commands_match_the_netmiko_script()
    for test in (test_the_default_run_touches_no_vty_line,
                 test_vty_range_comes_off_the_switch,
                 test_a_five_line_switch_gets_disas_example_verbatim,
                 test_a_rejected_command_is_recorded_not_fatal,
                 test_the_ssh_lines_are_read_back_off_the_switch,
                 test_every_config_command_is_read_before_the_next_is_sent,
                 test_unreachable_switches_are_rows,
                 test_syslog_servers_are_two_or_none,
                 test_syslog_servers_come_off_inventory_yaml_when_it_is_there,
                 test_the_confirmation_says_what_it_will_do):
        with tempfile.TemporaryDirectory() as tmpdir:
            test(tmpdir)
    print('\n' + ('ALL CHECKS PASSED' if not failures
                  else f'{len(failures)} FAILED: {", ".join(failures)}'))
    sys.exit(1 if failures else 0)
