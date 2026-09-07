#!/usr/bin/env python
"""Verification for securecrt/inventory_l2s.py - the fleet inventory walk.

Run it directly: `python3 tests/test_securecrt_inventory.py`. No framework, no
SecureCRT, no devices.

This walk answers a different question from the STIG one beside it: what is out
there, rather than whether it complies. That difference is the whole point of
it being a separate script, and it shows up in what is asserted here - it sends
three short commands, not seven, and it produces one CSV and nothing else. A
walk that quietly wrote captures or checklists would be the STIG walk with a
different name, and would take hours rather than minutes.

A stack is one row per chassis. `show version` names the active member's serial
and no other, so a three-member stack read from it alone leaves two chassis
unaccounted for - which is why `show switch` and `show license udi` are asked
too, and why the join between them is worth testing.

The other half is the same property the bulk collector has: a switch nobody
could reach is a row saying why, not a gap. An inventory with three hundred
rows and no account of the other three hundred is not an inventory.
"""

import io
import os
import sys
import tempfile

PROJECT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(PROJECT, 'scripts'))
sys.path.insert(0, os.path.join(PROJECT, 'securecrt'))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import capture_l2s
import capture_l2s_bulk as bulk
import inventory_l2s as inventory
from fixtures import OUTPUTS, SHOW_VERSION

failures = []


def check(name, condition, detail=''):
    print(f'  {"ok  " if condition else "FAIL"} {name}')
    if not condition:
        if detail:
            print(f'       {detail}')
        failures.append(name)


class FakeScreen:
    def __init__(self, outputs):
        self.outputs = outputs
        self.Synchronous = False
        self.prompt = 'TESTSW01#'
        self.sent = []
        self._pending = ''
        self.CurrentRow = 5
        self.CurrentColumn = len(self.prompt) + 1

    def Get(self, *_args):
        return self.prompt

    def Send(self, text):
        command = text.rstrip('\r\n')
        # A bare carriage return is how read_prompt() asks for a fresh prompt.
        # It is not a command and a real switch treats it as none, so it is not
        # recorded as one here either.
        if not command:
            return
        self.sent.append(command)
        body = '' if command == 'terminal length 0' else self.outputs.get(command, '')
        self._pending = f'{command}\r\n{body}\r\n'

    def ReadString(self, _terminator, timeout=None):
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
            self.crt.last_error = {
                'offline': 'The remote system refused the connection.',
                'timeout': 'The connection attempt timed out. No response from host.',
                'rejected': 'Password authentication failed.',
            }[outcome]
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
        return '' if 'scope' in title.lower() else self.crt.output_dir

    def MessageBox(self, message, title='', flags=0):
        self.crt.messages.append((title, message))
        return 6 if flags & 4 else 1


class FakeCRT:
    def __init__(self, output_dir, behaviour, outputs):
        self.output_dir = output_dir
        self.behaviour = behaviour
        self.attempts = []
        self.messages = []
        self.last_error = ''
        self.Screen = FakeScreen(outputs)
        self.Session = FakeSession(self)
        self.Dialog = FakeDialog(self)

    def GetLastErrorMessage(self):
        return self.last_error


def run_inventory(tmpdir, sessions, behaviour=None, outputs=None):
    fake = FakeCRT(tmpdir, behaviour or {}, outputs if outputs is not None else OUTPUTS)
    inventory.crt = fake
    capture_l2s.crt = fake
    bulk.crt = fake
    original = bulk.find_sessions
    bulk.find_sessions = lambda _filter='': list(sessions)
    try:
        inventory.main()
    finally:
        bulk.find_sessions = original
        inventory.crt = capture_l2s.crt = bulk.crt = None
    return fake


def csv_rows(tmpdir):
    """The run's CSV as dicts keyed by column name."""
    paths = [os.path.join(tmpdir, name) for name in sorted(os.listdir(tmpdir))
             if name.startswith('inventory_') and name.endswith('.csv')]
    if not paths:
        return []
    with io.open(paths[-1], encoding='utf-8') as handle:
        lines = handle.read().splitlines()
    columns = [name.strip().strip('"') for name in lines[0].split(',')]
    return [dict(zip(columns, [f.strip().strip('"') for f in line.split(',')]))
            for line in lines[1:]]


def test_short_commands_only(tmpdir):
    """The reason this is not the STIG walk with a flag. `show running-config`
    is the slow command, and an inventory does not need it - so a fleet that
    takes hours to audit takes minutes to count, and can be re-run whenever
    somebody wants to know what is out there."""
    print('three short commands per switch, not the audit\'s seven')
    fake = run_inventory(tmpdir, [('sw-a', '10.20.0.1')])
    check('paging is disabled first', fake.Screen.sent[0] == 'terminal length 0',
          fake.Screen.sent)
    check('then `show version` and the two that describe a stack',
          fake.Screen.sent[1:] == ['show version', 'show switch', 'show license udi'],
          fake.Screen.sent[1:])
    check('the slow one is never sent',
          'show running-config' not in fake.Screen.sent, fake.Screen.sent)


def test_writes_one_csv_and_nothing_else(tmpdir):
    print('\nthe run leaves a CSV and nothing else')
    run_inventory(tmpdir, [('sw-a', '10.20.1.1')])
    written = sorted(os.listdir(tmpdir))
    check('exactly one file', len(written) == 1, written)
    check('and it is the inventory CSV',
          written and written[0].startswith('inventory_')
          and written[0].endswith('.csv'), written)
    check('no captures', not any(n.endswith('.capture') for n in written), written)
    check('no checklists', not any(n.endswith('.cklb') for n in written), written)


def test_columns(tmpdir):
    print('\nthe columns, and what fills them')
    run_inventory(tmpdir, [('site-a\\sw-1', '10.20.2.1')])
    check('the columns are the ones asked for, in order',
          inventory.CSV_COLUMNS == ('hostname', 'ip_address', 'switch_number', 'role',
                                    'model', 'serial_number', 'ios_version',
                                    'comment', 'session', 'timestamp'),
          inventory.CSV_COLUMNS)

    rows = csv_rows(tmpdir)
    check('one row for the one session', len(rows) == 1, rows)
    if not rows:
        return
    row = rows[0]
    # Everything but the address comes off `show version`; the address is the
    # saved session's, since the walk never asks the switch for one.
    check('hostname, from the switch itself', row['hostname'] == 'TESTSW01', row)
    check('ip_address, from the saved session', row['ip_address'] == '10.20.2.1', row)
    check('model', row['model'] == 'C9300-48P', row)
    check('serial_number', row['serial_number'] == 'FOC0000X0XX', row)
    check('ios_version', row['ios_version'] == '17.12.4', row)
    check('session, so a row can be traced back to what produced it',
          row['session'] == 'site-a\\sw-1', row)
    # A sentence saying "it worked" beside four columns of data is noise. The
    # comment column is for the rows that need explaining.
    check('and no comment on a switch that answered', not row['comment'], row)


SHOW_SWITCH = """Switch/Stack Mac Address : 0011.2233.4455 - Local Mac Address
                                             H/W   Current
Switch#   Role    Mac Address     Priority Version  State
-------------------------------------------------------------------------------
*1       Active   0011.2233.4455     15     V01     Ready
 2       Standby  0011.2233.4466     14     V01     Ready
 3       Member   0011.2233.4477     10     V01     Ready"""

SHOW_LICENSE_UDI = """UDI: PID:C9300-48P,VID:V01,SN:FOC1111X1XX

HA UDI LIST:
Switch/Slot Number    PID    VID    SN
Switch 1             C9300-48P    V01    FOC1111X1XX
Switch 2             C9300-24P    V01    FOC2222X2XX
Switch 3             C9300-24P    V01    FOC3333X3XX"""

STACK_VERSION = """Cisco IOS XE Software, Version 17.12.04

STACKSW01 uptime is 3 weeks, 2 days

Switch Ports Model              SW Version        SW Image              Mode
------ ----- -----              ----------        ----------            ----
*    1 48    C9300-48P          17.12.04          CAT9K_IOSXE           INSTALL
     2 24    C9300-24P          17.12.04          CAT9K_IOSXE           INSTALL
     3 24    C9300-24P          17.12.04          CAT9K_IOSXE           INSTALL"""


def test_stack_is_one_row_per_member(tmpdir):
    """`show version` names the active member's serial and no other, so a
    three-member stack read from it alone is two chassis unaccounted for. Each
    one is its own asset with its own serial on its own property record, which
    is why the walk asks `show switch` and `show license udi` too."""
    print('\na stack is one row per chassis, not one row per stack')
    run_inventory(tmpdir, [('sw-stack', '10.20.5.1')],
                  outputs={'show version': STACK_VERSION,
                           'show switch': SHOW_SWITCH,
                           'show license udi': SHOW_LICENSE_UDI})
    rows = csv_rows(tmpdir)
    check('three members, three rows', len(rows) == 3, rows)
    if len(rows) != 3:
        return

    check('every row names the same switch and address',
          all(r['hostname'] == 'STACKSW01' and r['ip_address'] == '10.20.5.1'
              for r in rows), rows)
    check('numbered and roled from `show switch`',
          [(r['switch_number'], r['role']) for r in rows]
          == [('1', 'Active'), ('2', 'Standby'), ('3', 'Member')], rows)
    # The serials are the point: `show version` knows only the first of these.
    check('each chassis carries its own serial, from `show license udi`',
          [r['serial_number'] for r in rows]
          == ['FOC1111X1XX', 'FOC2222X2XX', 'FOC3333X3XX'], rows)
    check('and its own model',
          [r['model'] for r in rows] == ['C9300-48P', 'C9300-24P', 'C9300-24P'], rows)
    check('with the release normalised the way the audit normalises it',
          all(r['ios_version'] == '17.12.4' for r in rows), rows)


def test_standalone_switch_is_still_one_row(tmpdir):
    """A platform that is not stackable answers `show switch` with an error and
    may have no `show license udi` at all. Neither is a reason to lose the row:
    the join falls back to what `show version` said about the one switch, which
    is exactly what it answered before either command was asked for."""
    print('\na switch that answers neither extra command still gets its row')
    run_inventory(tmpdir, [('sw-solo', '10.20.6.1')],
                  outputs={'show version': OUTPUTS['show version'],
                           'show switch': "% Invalid input detected at '^' marker.",
                           'show license udi': '% Invalid input detected'})
    rows = csv_rows(tmpdir)
    check('one row', len(rows) == 1, rows)
    if not rows:
        return
    check('with the model, serial and release `show version` gave',
          (rows[0]['model'] == 'C9300-48P' and rows[0]['serial_number'] == 'FOC0000X0XX'
           and rows[0]['ios_version'] == '17.12.4'), rows[0])
    check('and no member number invented for it',
          not rows[0]['role'], rows[0])


def test_unreachable_switches_are_rows(tmpdir):
    """An inventory with three hundred rows and no account of the other three
    hundred is not an inventory. And the two ways a switch fails to answer are
    different problems - nothing there, versus something there refusing - so
    they do not collapse into one word."""
    print('\na switch nobody could reach is a row saying why')
    sessions = [('sw-a', '10.20.3.1'), ('sw-b', '10.20.3.2'), ('sw-c', '10.20.3.3')]
    run_inventory(tmpdir, sessions, {'sw-b': 'timeout', 'sw-c': 'offline'})
    rows = {row['session']: row for row in csv_rows(tmpdir)}
    check('every session in the list has a row', len(rows) == 3, sorted(rows))

    timed_out = rows.get('sw-b', {})
    refused = rows.get('sw-c', {})
    check('nothing answering says so', timed_out.get('comment') == 'Connection timed out',
          timed_out)
    check('a host answering and saying no says that instead',
          refused.get('comment') == 'System refused connection', refused)
    check('an unreached switch is still identifiable',
          timed_out.get('hostname') == 'sw-b' and timed_out.get('ip_address') == '10.20.3.2',
          timed_out)
    check('with its data columns blank rather than guessed',
          not any(timed_out.get(f) for f in ('model', 'serial_number', 'ios_version')),
          timed_out)
    check('and the switch after it was still visited',
          rows.get('sw-a', {}).get('model') == 'C9300-48P', rows.get('sw-a'))


def test_unreachable_switch_is_named_from_its_session(tmpdir):
    """A switch nobody could reach has nothing to say who it is except its own
    session name, and this fleet folds the address and a bldg/trailer into
    that name - see bulk.session_name_parts. The bldg/trailer label is what
    goes in the hostname column; the address only backfills a session with no
    Hostname field of its own."""
    print('\nan unreachable switch is named for its bldg/trailer, not its session path')
    sessions = [('10.20.7.1 - 5-200', '10.20.7.1'), ('10.20.7.2 - 6', '')]
    run_inventory(tmpdir, sessions, {'10.20.7.1 - 5-200': 'offline',
                                     '10.20.7.2 - 6': 'timeout'})
    rows = {row['session']: row for row in csv_rows(tmpdir)}
    with_room = rows.get('10.20.7.1 - 5-200', {})
    check('the bldg/trailer-room label becomes the hostname',
          with_room.get('hostname') == '5-200', with_room)
    check('a Hostname field that was already set is kept as the address',
          with_room.get('ip_address') == '10.20.7.1', with_room)

    no_room = rows.get('10.20.7.2 - 6', {})
    check('a bldg/trailer with no room still becomes the hostname',
          no_room.get('hostname') == '6', no_room)
    check('a blank Hostname field is backfilled from the session name',
          no_room.get('ip_address') == '10.20.7.2', no_room)


def test_not_a_switch_is_refused(tmpdir):
    """A session list reaches a jump host eventually. root's prompt ends in '#'
    too, and bash answers every command with an error - which is not empty and
    not truncated, so the shape checks alone would let it through and write a
    row of blanks that looks like a switch nobody could read."""
    print('\na session that is not a Cisco switch is refused, not recorded as blank')
    run_inventory(tmpdir, [('jumphost', '10.20.4.1')],
                  outputs={'show version': 'bash: show: command not found'})
    rows = csv_rows(tmpdir)
    check('it still gets a row', len(rows) == 1, rows)
    if rows:
        check('but not one that looks like a switch',
              not rows[0]['model'] and not rows[0]['serial_number'], rows[0])
        check('and the comment says what was wrong',
              'cisco' in rows[0]['comment'].lower(), rows[0])


def test_readers_agree_with_the_audit():
    """The inventory and the checklist beside it must not disagree about which
    release a switch runs. Both read `show version` through capture_l2s, so
    this asserts the inventory uses those readers rather than a third copy."""
    print('\nthe inventory reads `show version` the way everything else does')
    check('model', capture_l2s.show_version_model(SHOW_VERSION) == 'C9300-48P')
    check('serial', capture_l2s.show_version_serial(SHOW_VERSION) == 'FOC0000X0XX')
    check('release', capture_l2s.show_version_release(SHOW_VERSION) == '17.12.4')
    check('hostname, from the `<name> uptime is` line',
          capture_l2s.show_version_hostname(SHOW_VERSION) == 'TESTSW01')
    # The name `show version` prints agrees with the config's `hostname`, which
    # is what the STIG walk and the checklist use. They have to: a switch
    # appearing under two names in two files is a switch nobody can match up.
    check('and it agrees with the name the STIG walk uses',
          capture_l2s.show_version_hostname(SHOW_VERSION)
          == capture_l2s.running_config_hostname(OUTPUTS['show running-config']))


if __name__ == '__main__':
    test_readers_agree_with_the_audit()
    for test in (test_short_commands_only,
                 test_stack_is_one_row_per_member,
                 test_writes_one_csv_and_nothing_else,
                 test_columns,
                 test_unreachable_switches_are_rows,
                 test_unreachable_switch_is_named_from_its_session,
                 test_standalone_switch_is_still_one_row,
                 test_not_a_switch_is_refused):
        with tempfile.TemporaryDirectory() as tmpdir:
            test(tmpdir)
    print('\n' + ('ALL CHECKS PASSED' if not failures
                  else f'{len(failures)} FAILED: {", ".join(failures)}'))
