#!/usr/bin/env python
"""Verification for securecrt/backup_l2s.py and backup_l2s_bulk.py.

Run directly: `python3 tests/test_securecrt_backup.py`. No framework, no
SecureCRT, no devices - a stand-in session answers the show commands.
"""

import os
import shutil
import sys
import tempfile

PROJECT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(PROJECT, 'securecrt'))

import capture_l2s
import capture_l2s_bulk as bulk
import backup_l2s
import backup_l2s_bulk

failures = []


def check(name, condition, detail=''):
    print(f'  {"ok  " if condition else "FAIL"} {name}')
    if not condition:
        if detail:
            print(f'       {detail}')
        failures.append(name)


CONFIG = """Building configuration...

Current configuration : 120 bytes
!
hostname ACCESS-SW01
!
interface GigabitEthernet1/0/1
 switchport access vlan 20
!
end"""

VLANS = """VLAN Name                             Status    Ports
---- -------------------------------- --------- -------------------------------
1    default                          active
20   USERS                            active    Gi1/0/1"""


class FakeScreen:
    def __init__(self, crt_stub):
        self.crt = crt_stub
        self.Synchronous = False
        self.CurrentRow = 5
        self._pending = ''
        self.sent = []

    @property
    def CurrentColumn(self):
        return len(self.crt.prompt) + 1

    def Get(self, *_args):
        return self.crt.prompt

    def Send(self, text):
        command = text.rstrip('\r\n')
        if not command:
            return
        self.sent.append(command)
        body = self.crt.answers.get(command, '')
        self._pending += f'{command}\r\n{body}\r\n{self.crt.prompt}'

    def ReadString(self, terminator, _timeout=None):
        # As SecureCRT does: everything up to the terminator, not including it.
        pending, self._pending = self._pending, ''
        return pending[:-len(terminator)] if pending.endswith(terminator) else pending


class FakeSession:
    Connected = True
    RemoteAddress = '192.0.2.11'


class FakeDialog:
    def __init__(self, crt_stub):
        self.crt = crt_stub

    def Prompt(self, _message, _title='', _default='', _password=False):
        return self.crt.output_dir

    def MessageBox(self, message, title='', _flags=0):
        self.crt.messages.append((title, message))
        return 1


class FakeCRT:
    def __init__(self, output_dir, prompt='SW01#', config=CONFIG, vlans=VLANS):
        self.output_dir = output_dir
        self.prompt = prompt
        self.answers = {'terminal length 0': '', 'show running-config': config,
                        'show vlan brief': vlans}
        self.messages = []
        self.Screen = FakeScreen(self)
        self.Session = FakeSession()
        self.Dialog = FakeDialog(self)

    def Sleep(self, _ms):
        pass


def run(tmpdir, **kwargs):
    fake = FakeCRT(tmpdir, **kwargs)
    capture_l2s.crt = backup_l2s.crt = fake
    try:
        backup_l2s.main()
    finally:
        capture_l2s.crt = backup_l2s.crt = None
    return fake


# ---------------------------------------------------------------------------
# The bulk run: a stand-in SecureCRT holding several switches, one per session.
# ---------------------------------------------------------------------------

class BulkSession:
    def __init__(self, crt_stub):
        self.crt = crt_stub
        self.Connected = False

    def Connect(self, connect_string, _suppress=False):
        session = connect_string.split('"')[1]
        if session not in self.crt.switches:
            self.crt.last_error = 'The connection attempt timed out. No response from host.'
            raise Exception(self.crt.last_error)
        prompt, config, vlans = self.crt.switches[session]
        self.crt.prompt = prompt
        self.crt.answers = {'terminal length 0': '', 'show running-config': config,
                            'show vlan brief': vlans}
        self.Connected = True

    def Disconnect(self):
        self.Connected = False

    def SetStatusText(self, _text):
        pass


class BulkDialog(FakeDialog):
    def Prompt(self, _message, title='', _default='', _password=False):
        return '' if 'scope' in title.lower() else self.crt.output_dir

    def MessageBox(self, message, title='', _flags=0):
        self.crt.messages.append((title, message))
        return 6 if 'confirm' in title.lower() else 1


class BulkCRT(FakeCRT):
    def __init__(self, output_dir, switches):
        FakeCRT.__init__(self, output_dir)
        self.switches = switches
        self.last_error = ''
        self.Session = BulkSession(self)
        self.Dialog = BulkDialog(self)

    def GetLastErrorMessage(self):
        return self.last_error


def run_bulk(tmpdir, switches, sessions):
    fake = BulkCRT(tmpdir, switches)
    original_find = bulk.find_sessions
    for module in (capture_l2s, bulk, backup_l2s, backup_l2s_bulk):
        module.crt = fake
    bulk.find_sessions = lambda _filter='': list(sessions)
    try:
        backup_l2s_bulk.main()
    finally:
        for module in (capture_l2s, bulk, backup_l2s, backup_l2s_bulk):
            module.crt = None
        bulk.find_sessions = original_find
    return fake


def log_rows(tmpdir):
    import csv
    rows = []
    for name in sorted(os.listdir(tmpdir)):
        if name.startswith('backup_log_') and name.endswith('.csv'):
            with open(os.path.join(tmpdir, name), encoding='utf-8', newline='') as handle:
                rows.extend(csv.DictReader(handle))
    return rows


def named(hostname, **changes):
    config = CONFIG.replace('ACCESS-SW01', hostname)
    for old, new in changes.items():
        config = config.replace(old, new)
    return config


def test_bulk(tmpdir):
    print('\nbulk: every session backed up, the rest accounted for, one verdict')
    switches = {
        'site/sw-1': ('SW1#', named('SW-ONE'), VLANS),
        'site/sw-2': ('SW2#', named('SW-TWO'), VLANS),
        'site/sw-3': ('SW3#', named('SW-THREE').rsplit('\nend', 1)[0], VLANS),
        'site/sw-4': ('SW4>', named('SW-FOUR'), VLANS),
        'site/sw-5': ('SW5#', named('SW-ONE', **{'vlan 20': 'vlan 99'}), VLANS),
    }
    sessions = [(name, f'192.0.2.{i}') for i, name in enumerate(sorted(switches), 1)]
    sessions.append(('site/sw-dead', '192.0.2.99'))
    sessions.append(('site/sw-1-copy', '192.0.2.1'))
    fake = run_bulk(tmpdir, switches, sessions)
    title, text = fake.messages[-1]
    check('the closing dialog is the verdict', title == 'Switch backup bulk - verdict', title)
    check('backed up 3 of 6 (the duplicate session is not a switch)',
          'Backed up 3 of 6 switch(es).' in text, text)
    check('the rest are counted by outcome', 'refused 2' in text and 'unreachable 1' in text, text)

    files = sorted(n for n in os.listdir(tmpdir) if n.endswith('.txt') and '_verdict' not in n)
    check('one file per switch backed up, named by hostname',
          files == ['SW-ONE.txt', 'SW-ONE_192.0.2.5.txt', 'SW-TWO.txt'], files)
    check('the first SW-ONE is not overwritten by the second',
          'vlan 20' in read(os.path.join(tmpdir, 'SW-ONE.txt'))
          and 'vlan 99' in read(os.path.join(tmpdir, 'SW-ONE_192.0.2.5.txt')))
    check('each has its VLANs', all('! --- show vlan brief ---' in read(os.path.join(tmpdir, f))
                                    for f in files))
    check('the header carries the session address',
          '! IP Address: 192.0.2.2' in read(os.path.join(tmpdir, 'SW-TWO.txt')))

    rows = {row['session']: row for row in log_rows(tmpdir)}
    check('a row for every session, the duplicate included', len(rows) == 7, sorted(rows))
    check('the clash is explained in its row',
          'hostname also used this run by site/sw-1' in rows['site/sw-5']['detail'],
          rows.get('site/sw-5'))
    check('the cut-short config is refused, with the reason',
          rows['site/sw-3']['outcome'] == 'refused'
          and 'Config not read' in rows['site/sw-3']['detail'], rows.get('site/sw-3'))
    check('user EXEC mode is refused', rows['site/sw-4']['outcome'] == 'refused'
          and 'enable' in rows['site/sw-4']['detail'], rows.get('site/sw-4'))
    check('nothing but reads were sent anywhere', set(fake.Screen.sent) <= {
        'terminal length 0', 'show running-config', 'show vlan brief'}, set(fake.Screen.sent))
    verdicts = [n for n in os.listdir(tmpdir) if n.endswith('_verdict.txt')]
    check('the verdict is written beside the log', len(verdicts) == 1, os.listdir(tmpdir))

    print('\nbulk, again: a switch that fails now keeps its last good backup')
    before = read(os.path.join(tmpdir, 'SW-TWO.txt'))
    switches['site/sw-2'] = ('SW2#', named('SW-TWO').rsplit('\nend', 1)[0], VLANS)
    run_bulk(tmpdir, switches, [('site/sw-1', '192.0.2.1'), ('site/sw-2', '192.0.2.2')])
    check('SW-TWO.txt is the earlier backup, untouched',
          read(os.path.join(tmpdir, 'SW-TWO.txt')) == before)
    latest = [r for r in log_rows(tmpdir) if r['session'] == 'site/sw-1'][-1]
    check('and SW-ONE was replaced, saying so', 'replaced the previous backup' in latest['detail'],
          latest)


def test_bulk_cancel(tmpdir):
    print('\nbulk: No at the confirmation connects to nothing')
    fake = BulkCRT(tmpdir, {'site/sw-1': ('SW1#', CONFIG, VLANS)})
    fake.Dialog.MessageBox = lambda message, title='', _flags=0: 7
    original_find = bulk.find_sessions
    for module in (capture_l2s, bulk, backup_l2s, backup_l2s_bulk):
        module.crt = fake
    bulk.find_sessions = lambda _filter='': [('site/sw-1', '192.0.2.1')]
    try:
        backup_l2s_bulk.main()
    finally:
        for module in (capture_l2s, bulk, backup_l2s, backup_l2s_bulk):
            module.crt = None
        bulk.find_sessions = original_find
    check('nothing sent', fake.Screen.sent == [], fake.Screen.sent)
    check('no backup written', not any(n.endswith('.txt') for n in os.listdir(tmpdir)),
          os.listdir(tmpdir))


def read(path):
    with open(path, encoding='utf-8') as handle:
        return handle.read()


def test_backup(tmpdir):
    print('a switch: running-config and VLANs, in a file named after the hostname')
    fake = run(tmpdir)
    path = os.path.join(tmpdir, 'ACCESS-SW01.txt')
    check('the file is <hostname>.txt, from the config\'s hostname line',
          os.listdir(tmpdir) == ['ACCESS-SW01.txt'], os.listdir(tmpdir))
    text = read(path) if os.path.exists(path) else ''
    check('the header names the switch and its address',
          text.startswith('! Hostname: ACCESS-SW01\n! IP Address: 192.0.2.11\n'), text[:80])
    check('the whole running-config is in it', 'switchport access vlan 20\n!\nend\n' in text)
    check('the VLAN database follows it', '! --- show vlan brief ---\n' in text
          and '20   USERS' in text and text.index('end\n') < text.index('show vlan brief'))
    check('nothing but show commands and terminal length were sent', fake.Screen.sent ==
          ['terminal length 0', 'show running-config', 'show vlan brief'], fake.Screen.sent)
    check('the dialog says where it went', fake.messages[-1][0] == 'Backup written'
          and path in fake.messages[-1][1], fake.messages)

    print('\nthe same switch again: the backup is replaced, not added to')
    fake = run(tmpdir, config=CONFIG.replace('vlan 20', 'vlan 30'))
    check('still one file', os.listdir(tmpdir) == ['ACCESS-SW01.txt'], os.listdir(tmpdir))
    check('with the new config', 'vlan 30' in read(path))
    check('and the dialog says it replaced one', 'replaced' in fake.messages[-1][1],
          fake.messages[-1])


def test_refusals(tmpdir):
    print('\na run that cannot read the switch properly writes nothing')
    path = os.path.join(tmpdir, 'ACCESS-SW01.txt')
    run(tmpdir)
    before = read(path)

    fake = run(tmpdir, config=CONFIG.rsplit('\nend', 1)[0])
    check('a config cut short is refused', fake.messages[-1][0] == 'Config not read',
          fake.messages[-1])
    check('and the earlier backup is untouched', read(path) == before)
    check('and no partial file is left', os.listdir(tmpdir) == ['ACCESS-SW01.txt'],
          os.listdir(tmpdir))

    fake = run(tmpdir, prompt='SW01>')
    check('user EXEC mode is refused before anything is sent',
          fake.messages[-1][0] == 'Not in enable mode' and fake.Screen.sent == [],
          (fake.messages, fake.Screen.sent))

    fake = run(tmpdir, vlans='')
    check('an empty VLAN answer is refused', fake.messages[-1][0] == 'VLANs not read',
          fake.messages[-1])
    check('and the earlier backup is still untouched', read(path) == before)


def test_router(tmpdir):
    print('\na device with no VLAN database: the running-config alone, as backup_config.py does')
    run(tmpdir, config=CONFIG.replace('ACCESS-SW01', 'EDGE-R1'),
        vlans="                ^\n% Invalid input detected at '^' marker.")
    text = read(os.path.join(tmpdir, 'EDGE-R1.txt'))
    check('backed up without a VLAN section', 'show vlan brief' not in text
          and text.rstrip().endswith('end'), text[-80:])


def main():
    for test in (test_backup, test_refusals, test_router, test_bulk, test_bulk_cancel):
        tmpdir = tempfile.mkdtemp()
        try:
            test(tmpdir)
        finally:
            shutil.rmtree(tmpdir)
    print()
    if failures:
        print(f'{len(failures)} FAILED: ' + ', '.join(failures))
        sys.exit(1)
    print('all checks passed')


if __name__ == '__main__':
    main()
