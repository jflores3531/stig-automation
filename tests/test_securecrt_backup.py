#!/usr/bin/env python
"""Verification for securecrt/backup_l2s.py.

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
import backup_l2s

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
    for test in (test_backup, test_refusals, test_router):
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
