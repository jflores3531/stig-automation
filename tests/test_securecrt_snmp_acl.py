#!/usr/bin/env python
"""Verification for securecrt/snmp_acl_l2s.py and snmp_acl_l2s_bulk.py.

Run directly: `python3 tests/test_securecrt_snmp_acl.py`. No framework, no
SecureCRT, no devices.

Three things are guarded:

  * the ACL logic answers exactly as scripts/snmp_host_acl.py's does. It is
    duplicated because securecrt/ may not import from the wider repository,
    and a duplicate that drifts is two tools disagreeing about where a permit
    goes - which here is the difference between a permit and dead config.

  * the verdict comes from the switch. The fake switch below keeps a real ACL:
    it applies `N permit ...`, appends an unnumbered permit at last + 10 the way
    IOS does, renumbers on resequence, and renders the list back the way IOS
    does. So "completed" is tested against a list that could genuinely have
    ended up wrong, not against an echo of what was sent.

  * the bulk walk counts every session and finishes after any one of them fails.
"""

import csv
import io
import json
import os
import re
import shutil
import sys
import tempfile

PROJECT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(PROJECT, 'scripts'))
sys.path.insert(0, os.path.join(PROJECT, 'securecrt'))

import capture_l2s
import capture_l2s_bulk as bulk
import harden_l2s_bulk as harden
import snmp_acl_l2s as crt_snmp
import snmp_acl_l2s_bulk as crt_bulk
import snmp_host_acl as netmiko_snmp

failures = []


def check(name, condition, detail=''):
    print(f'  {"ok  " if condition else "FAIL"} {name}')
    if not condition:
        if detail:
            print(f'       {detail}')
        failures.append(name)


# ---------------------------------------------------------------------------
# Parity with the netmiko script.
# ---------------------------------------------------------------------------

def outcome(module, call):
    """What a call returned, or that it raised the module's AclError - so the
    two copies can be compared without comparing their message wording, which
    differs on purpose (one names flags, the other names inventory keys)."""
    try:
        return ('ok', call(module))
    except module.AclError:
        return ('AclError',)


ACLS = {
    'managed': """Standard IP access list SNMP_ACCESS
    10 permit 192.0.2.10
    20 permit 192.0.2.64, wildcard bits 0.0.0.31 (4 matches)
    30 deny   any log""",
    'tight': """Standard IP access list SNMP_ACCESS
    10 permit 192.0.2.10
    11 permit 192.0.2.11
    12 deny   any log""",
    'no deny': """Standard IP access list SNMP_ACCESS
    10 permit 192.0.2.10""",
    'deny mid-list': """Standard IP access list SNMP_ACCESS
    10 permit 192.0.2.10
    20 deny   192.0.2.128, wildcard bits 0.0.0.127
    40 permit any""",
    'empty': 'Standard IP access list SNMP_ACCESS',
    'missing': '',
    'extended': """Extended IP access list SNMP_ACCESS
    10 permit ip any any""",
    'unnumbered': """Standard IP access list SNMP_ACCESS
    permit 192.0.2.10
    deny   any""",
}
PERMIT_SETS = [
    ['host 192.0.2.20', '192.0.2.21', '192.0.2.64 0.0.0.31'],
    ['host 192.0.2.10'],
    ['host 192.0.2.20'],
    ['192.0.2.0 0.0.0.255', 'host 192.0.2.20', 'host 192.0.2.21', 'host 192.0.2.22'],
]


def test_parity():
    print('the SecureCRT copy answers exactly as scripts/snmp_host_acl.py does')
    for label, text in ACLS.items():
        a = outcome(netmiko_snmp, lambda m: m.parse_acl(text, 'SNMP_ACCESS'))
        b = outcome(crt_snmp, lambda m: m.parse_acl(text, 'SNMP_ACCESS'))
        check(f'parse_acl on the {label} list', a == b, f'netmiko={a}\n       securecrt={b}')
        if a[0] != 'ok':
            continue
        entries = a[1]
        check(f'first_deny on the {label} list',
              netmiko_snmp.first_deny(entries) == crt_snmp.first_deny(entries))
        check(f'relog_plan on the {label} list',
              netmiko_snmp.relog_plan(entries) == crt_snmp.relog_plan(entries))
        relogged = netmiko_snmp.relog_plan(entries)
        check(f'check_relogged on the {label} list',
              netmiko_snmp.check_relogged(entries, relogged)
              == crt_snmp.check_relogged(entries, relogged))
        check(f'acl_commands with relogs on the {label} list',
              netmiko_snmp.acl_commands('A', [], relogged)
              == crt_snmp.acl_commands('A', [], relogged))
        for permits in PERMIT_SETS:
            for insert_at in (None, 1, 11, 12, 25, 31):
                a = outcome(netmiko_snmp, lambda m: m.plan_insert(entries, permits, insert_at))
                b = outcome(crt_snmp, lambda m: m.plan_insert(entries, permits, insert_at))
                check(f'plan_insert: {label}, {len(permits)} permit(s), insert_at={insert_at}',
                      a == b, f'netmiko={a}\n       securecrt={b}')
            check(f'check_applied: {label}, {len(permits)} permit(s)',
                  netmiko_snmp.check_applied(entries, permits)
                  == crt_snmp.check_applied(entries, permits))

    planned = [(11, 'permit host 192.0.2.20'), (None, 'permit 192.0.2.21')]
    check('acl_commands', netmiko_snmp.acl_commands('A', planned)
          == crt_snmp.acl_commands('A', planned))
    check('resequence_command', netmiko_snmp.resequence_command('A', 5, 7)
          == crt_snmp.resequence_command('A', 5, 7))
    check('snmp_host_command', netmiko_snmp.snmp_host_command('192.0.2.20', 'U')
          == crt_snmp.snmp_host_command('192.0.2.20', 'U'))
    run = ('ip access-list standard SNMP_ACCESS\nsnmp-server group G v3 priv access SNMP_ACCESS\n'
           ' access-class SNMP_ACCESS in')
    check('references', netmiko_snmp.references(run, 'SNMP_ACCESS')
          == crt_snmp.references(run, 'SNMP_ACCESS'))
    users = 'User name: SNMPV3_USER\nGroup-name: G'
    for name in ('SNMPV3_USER', 'SNMPV3_USE', 'SNMP_ACCESS'):
        check(f'snmp_user_present({name})', netmiko_snmp.snmp_user_present(users, name)
              == crt_snmp.snmp_user_present(users, name))

    sections = [
        {'acl_name': 'A', 'permits': ['host 192.0.2.20'], 'trap_hosts': {'192.0.2.20': 'U'},
         'insert_at': 11, 'resequence': {'start': 10, 'increment': 10}},
        {'acl_name': 'A', 'permits': ['host   192.0.2.20']},
        {'acl_name': 'A', 'permits': ['any'], 'insert_at': '12'},
        {}, {'acl_name': 'A', 'permits': 'host 192.0.2.20'}, {'acl_name': 'A', 'permits': []},
        {'acl_name': 'A', 'permits': ['  ']},
        {'acl_name': 'A', 'permits': ['any'], 'trap_hosts': {'192.0.2.20': None}},
        {'acl_name': 'A', 'permits': ['any'], 'trap_hosts': ['192.0.2.20']},
        {'acl_name': 'A', 'permits': ['any'], 'resequence': {'start': 'ten'}},
        {'acl_name': 'A', 'permits': ['any'], 'resequence': {'increment': 0}},
        {'acl_name': 'A', 'permits': ['any'], 'insert_at': 'eleven'},
        {'acl_name': 'A', 'permits': ['any'], 'insert_at': 0},
        {'acl_name': 'A', 'permits': ['any'], 'insert_at': True},
        {'acl_name': 'A', 'permits': ['any'], 'insert_at': 1.5},
    ]
    for section in sections:
        a = outcome(netmiko_snmp, lambda m: m.load_config(section))
        b = outcome(crt_snmp, lambda m: m.load_config(section))
        check(f'load_config({section})', a == b, f'netmiko={a}\n       securecrt={b}')


# ---------------------------------------------------------------------------
# A switch that keeps its ACL.
# ---------------------------------------------------------------------------

def ios_render(text):
    """How IOS shows a standard entry back: no `host`, wildcard split by a comma."""
    action, _, rest = text.partition(' ')
    rest = re.sub(r'^host\s+', '', rest.strip())
    rest, log = re.subn(r'\s+log$', '', rest)
    rest = re.sub(r'^(\S+)\s+(\d+\.\d+\.\d+\.\d+)$', r'\1, wildcard bits \2', rest)
    return f'{action} {rest}{" log" if log else ""}'.strip()


class Switch:
    def __init__(self, hostname='TESTSW01', acl=None, kind='Standard', refs=None,
                 users='User name: SNMPV3_USER\nGroup-name: SNMPV3_GROUP', reject=()):
        self.hostname = hostname
        # sequence -> entry text as typed; None means the ACL is not defined.
        self.acl = dict(acl) if acl is not None else None
        self.kind = kind
        self.refs = ('snmp-server group SNMPV3_GROUP v3 priv access SNMP_ACCESS'
                     if refs is None else refs)
        self.users = users
        self.reject = reject
        self.mode = 'exec'
        self.hosts = []
        self.configured = []
        self.saved = False

    def render_acl(self):
        if self.acl is None:
            return ''
        lines = [f'{self.kind} IP access list SNMP_ACCESS']
        for sequence in sorted(self.acl):
            lines.append(f'    {sequence} {ios_render(self.acl[sequence])}')
        return '\n'.join(lines)

    def answer(self, command):
        if command in self.reject or any(command.endswith(r) for r in self.reject):
            return '% Invalid input detected at \'^\' marker.'
        if self.mode == 'exec':
            if command == 'terminal length 0':
                return ''
            if command.startswith('show ip access-lists'):
                return self.render_acl()
            if command.startswith('show running-config | include'):
                return self.refs + ('\nip access-list standard SNMP_ACCESS'
                                    if self.acl is not None else '')
            if command == 'show snmp user':
                return self.users
            if command == 'write memory':
                self.saved = True
                return 'Building configuration...\n[OK]'
            if command == 'configure terminal':
                self.mode = 'config'
                return 'Enter configuration commands, one per line.'
            return ''
        self.configured.append(command)
        if command == 'end':
            self.mode = 'exec'
            return '%SYS-5-CONFIG_I: Configured from console by admin on vty0'
        if self.mode == 'acl':
            match = re.match(r'^(\d+)\s+((?:permit|deny)\s.*)$', command)
            removal = re.match(r'^no\s+(\d+)$', command)
            if match:
                self.acl[int(match.group(1))] = match.group(2)
            elif removal:
                self.acl.pop(int(removal.group(1)), None)
            elif command.startswith(('permit', 'deny')):
                self.acl[(max(self.acl) if self.acl else 0) + 10] = command
            elif command == 'exit':
                self.mode = 'config'
            return ''
        if command == 'ip access-list standard SNMP_ACCESS':
            if self.acl is None:
                self.acl = {}
            self.mode = 'acl'
            return ''
        match = re.match(r'^ip access-list resequence SNMP_ACCESS (\d+) (\d+)$', command)
        if match:
            start, step = int(match.group(1)), int(match.group(2))
            self.acl = {start + i * step: self.acl[seq] for i, seq in enumerate(sorted(self.acl))}
            return ''
        if command.startswith('snmp-server host'):
            self.hosts.append(command)
        return ''

    @property
    def prompt(self):
        return {'exec': f'{self.hostname}#', 'config': f'{self.hostname}(config)#',
                'acl': f'{self.hostname}(config-std-nacl)#'}[self.mode]


MANAGED = {10: 'permit 192.0.2.10', 20: 'permit 192.0.2.64 0.0.0.31', 30: 'deny any log'}


class FakeScreen:
    def __init__(self, crt_stub):
        self.crt = crt_stub
        self.Synchronous = False
        self.CurrentRow = 5
        self._pending = ''
        self.sent = []

    @property
    def CurrentColumn(self):
        return len(self.crt.switch.prompt) + 1

    def Get(self, *_args):
        return self.crt.switch.prompt

    def Send(self, text):
        command = text.rstrip('\r\n')
        if not command:
            return
        self.sent.append(command)
        body = self.crt.switch.answer(command)
        self._pending += f'{command}\r\n{body}\r\n{self.crt.switch.prompt}'

    def ReadString(self, _terminator, _timeout=None):
        pending, self._pending = self._pending, ''
        return pending


class FakeSession:
    def __init__(self, crt_stub):
        self.crt = crt_stub
        self.Connected = True

    def Connect(self, connect_string, _suppress=False):
        session = connect_string.split('"')[1]
        if session not in self.crt.switches:
            self.crt.last_error = 'The connection attempt timed out. No response from host.'
            raise Exception(self.crt.last_error)
        self.crt.switch = self.crt.switches[session]
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
        if 'inventory' in title.lower():
            return self.crt.inventory_answer
        return self.crt.output_dir

    def MessageBox(self, message, title='', flags=0):
        self.crt.messages.append((title, message, flags))
        lowered = title.lower()
        if 'confirm' in lowered:
            return 6 if self.crt.confirm else 7
        if 'renumber' in lowered or 'no room' in lowered:
            return 6 if self.crt.renumber else 7
        if 'save' in lowered:
            return 6 if self.crt.save else 7
        return 1


class FakeCRT:
    def __init__(self, output_dir, switch=None, switches=None, confirm=True, renumber=False,
                 save=False):
        self.output_dir = output_dir
        self.save = save
        self.switch = switch or Switch(acl=MANAGED)
        self.switches = switches or {}
        self.confirm = confirm
        self.renumber = renumber
        self.inventory_answer = ''
        self.messages = []
        self.last_error = ''
        self.Screen = FakeScreen(self)
        self.Session = FakeSession(self)
        self.Dialog = FakeDialog(self)

    def GetLastErrorMessage(self):
        return self.last_error

    def Sleep(self, _ms):
        pass


SNMP_SECTION = {
    'acl_name': 'SNMP_ACCESS',
    'trap_hosts': {'192.0.2.20': 'SNMPV3_USER'},
    'permits': ['host 192.0.2.20', '192.0.2.21', 'host 192.0.2.22'],
    'insert_at': None,
    'resequence': {'start': 10, 'increment': 10},
}


def with_inventory(tmpdir, section):
    path = os.path.join(tmpdir, 'inventory.yaml')
    with open(path, 'w', encoding='utf-8') as handle:
        json.dump({'devices': {}, 'snmp': section}, handle)
    return path


def install(fake, inventory):
    for module in (capture_l2s, bulk, harden, crt_snmp, crt_bulk):
        module.crt = fake
    crt_snmp.inventory_path = lambda: inventory


ORIGINAL_INVENTORY_PATH = crt_snmp.inventory_path
ORIGINAL_FIND = bulk.find_sessions
ORIGINAL_OUTPUT = crt_snmp.OUTPUT_DIR


def uninstall():
    for module in (capture_l2s, bulk, harden, crt_snmp, crt_bulk):
        module.crt = None
    crt_snmp.inventory_path = ORIGINAL_INVENTORY_PATH
    bulk.find_sessions = ORIGINAL_FIND
    crt_snmp.OUTPUT_DIR = ORIGINAL_OUTPUT


def run_single(tmpdir, switch, section=SNMP_SECTION, confirm=True, renumber=False):
    fake = FakeCRT(tmpdir, switch=switch, confirm=confirm, renumber=renumber)
    install(fake, with_inventory(tmpdir, section))
    crt_snmp.OUTPUT_DIR = tmpdir
    try:
        crt_snmp.main()
    finally:
        uninstall()
    return fake


def run_bulk(tmpdir, switches, sessions, section=SNMP_SECTION, renumber=False, confirm=True,
             save=False):
    fake = FakeCRT(tmpdir, switches=switches, confirm=confirm, renumber=renumber, save=save)
    install(fake, with_inventory(tmpdir, section))
    bulk.find_sessions = lambda _filter='': list(sessions)
    try:
        crt_bulk.main()
    finally:
        uninstall()
    return fake


def log_rows(tmpdir):
    rows = []
    for name in sorted(os.listdir(tmpdir)):
        if name.startswith('snmp_acl_') and name.endswith('.csv'):
            with io.open(os.path.join(tmpdir, name), encoding='utf-8', newline='') as handle:
                rows.extend(csv.DictReader(handle.read().splitlines()))
    return rows


def last_message(fake):
    return fake.messages[-1] if fake.messages else ('', '', 0)


# ---------------------------------------------------------------------------
# One switch.
# ---------------------------------------------------------------------------

def test_single_completed(tmpdir):
    print('\none switch: the permits land in front of the deny and the verdict says so')
    switch = Switch(acl=MANAGED)
    fake = run_single(tmpdir, switch)
    title, text, _ = last_message(fake)
    check('the verdict is COMPLETED', title == 'SNMP ACL - COMPLETED', f'{title}\n{text}')
    # 21, 22, 23 under the deny at 30, then renumbered 10/10 in order.
    check('the list ends renumbered with the permits before the deny',
          [switch.acl[s] for s in sorted(switch.acl)] == [
              'permit 192.0.2.10 log', 'permit 192.0.2.64 0.0.0.31 log',
              'permit host 192.0.2.20 log',
              'permit 192.0.2.21 log', 'permit host 192.0.2.22 log', 'deny any log'], switch.acl)
    check('the list is numbered 10/10 afterwards', sorted(switch.acl) == [10, 20, 30, 40, 50, 60])
    check('the trap host was pushed with the username',
          switch.hosts == ['snmp-server host 192.0.2.20 version 3 priv SNMPV3_USER'], switch.hosts)
    check('the inserts used the gap below the deny',
          '21 permit host 192.0.2.20 log' in switch.configured
          and '23 permit host 192.0.2.22 log' in switch.configured, switch.configured)
    check('the %SYS-5-CONFIG_I after `end` is not counted as a rejection',
          'rejected' not in text, text)
    check('nothing was saved', 'copy running-config startup-config' not in fake.Screen.sent
          and 'write memory' not in fake.Screen.sent)
    rows = log_rows(tmpdir)
    check('one log row, outcome completed',
          len(rows) == 1 and rows[0]['outcome'] == 'completed', rows)
    check('the row names what was inserted',
          rows and '21 permit host 192.0.2.20' in rows[0]['inserted'], rows)


def test_single_pinned(tmpdir):
    print('\none switch, pinned at 11: 11, 12, 13 exactly')
    switch = Switch(acl=MANAGED)
    section = dict(SNMP_SECTION, insert_at=11)
    fake = run_single(tmpdir, switch, section)
    check('11, 12 and 13 were sent',
          ['11 permit host 192.0.2.20 log', '12 permit 192.0.2.21 log',
           '13 permit host 192.0.2.22 log']
          == [c for c in switch.configured if re.match(r'^1[1-9] permit', c)], switch.configured)
    check('and they sit right after 10, before the old 20',
          [switch.acl[s] for s in sorted(switch.acl)][1] == 'permit host 192.0.2.20 log', switch.acl)
    check('completed', last_message(fake)[0] == 'SNMP ACL - COMPLETED')


def test_single_cancel(tmpdir):
    print('\none switch: No at the confirmation sends nothing')
    switch = Switch(acl=MANAGED)
    fake = run_single(tmpdir, switch, confirm=False)
    check('config mode was never entered', 'configure terminal' not in fake.Screen.sent,
          fake.Screen.sent)
    check('the list is untouched', switch.acl == MANAGED, switch.acl)
    check('the verdict says not changed', last_message(fake)[0] == 'SNMP ACL - not changed')
    confirm = [m for m in fake.messages if m[0] == 'SNMP ACL - confirm']
    check('the confirmation showed the exact sequence numbers',
          confirm and '21 permit host 192.0.2.20' in confirm[0][1], confirm)


def test_single_vty_defaults_to_no(tmpdir):
    print('\none switch: an ACL on the vty lines is flagged, and No is the default button')
    switch = Switch(acl=MANAGED, refs=' access-class SNMP_ACCESS in')
    fake = run_single(tmpdir, switch, confirm=False)
    confirm = [m for m in fake.messages if m[0] == 'SNMP ACL - confirm']
    check('the confirmation warns it grants SSH', confirm and 'grant' in confirm[0][1]
          and 'SSH' in confirm[0][1], confirm)
    check('the second button is the default', confirm and confirm[0][2] & 256, confirm)


def test_single_no_room(tmpdir):
    print('\none switch: no room under the deny - asked to renumber, then inserted')
    tight = {10: 'permit 192.0.2.10', 11: 'permit 192.0.2.11', 12: 'deny any log'}
    switch = Switch(acl=tight)
    fake = run_single(tmpdir, switch, renumber=True)
    check('it asked', any(m[0] == 'SNMP ACL - no room' for m in fake.messages), fake.messages)
    check('completed after renumbering', last_message(fake)[0] == 'SNMP ACL - COMPLETED',
          last_message(fake))
    check('the deny is still last', switch.acl[max(switch.acl)] == 'deny any log', switch.acl)

    switch = Switch(acl=tight)
    other = tempfile.mkdtemp()
    try:
        fake = run_single(other, switch, renumber=False)
    finally:
        shutil.rmtree(other)
    check('declined: nothing configured', 'configure terminal' not in fake.Screen.sent)
    check('declined: not changed', last_message(fake)[0] == 'SNMP ACL - not changed')


def test_single_missing_acl(tmpdir):
    print('\none switch: an ACL that is not there is not created')
    switch = Switch(acl=None)
    fake = run_single(tmpdir, switch)
    check('nothing configured', 'configure terminal' not in fake.Screen.sent, fake.Screen.sent)
    check('the dialog says it is not defined', 'not defined' in last_message(fake)[1],
          last_message(fake))


def test_single_failed_readback(tmpdir):
    print('\none switch: a permit the image rejects makes the verdict FAILED')
    switch = Switch(acl=MANAGED, reject=('permit 192.0.2.21 log',))
    fake = run_single(tmpdir, switch)
    title, text, _ = last_message(fake)
    check('the verdict is FAILED', title == 'SNMP ACL - FAILED', f'{title}\n{text}')
    check('it names the missing permit', '192.0.2.21' in text, text)


def test_single_missing_user_is_a_warning(tmpdir):
    print('\none switch: a missing SNMPv3 user is completed-with-warning, not hidden')
    switch = Switch(acl=MANAGED, users='')
    fake = run_single(tmpdir, switch)
    title, text, _ = last_message(fake)
    check('still completed', title == 'SNMP ACL - COMPLETED', title)
    check('the warning names the user and the receiver',
          'SNMPV3_USER' in text and '192.0.2.20' in text, text)


def test_single_bad_inventory(tmpdir):
    print('\none switch: a bad inventory stops the run before anything is sent')
    fake = run_single(tmpdir, Switch(acl=MANAGED), dict(SNMP_SECTION, permits='host 192.0.2.20'))
    check('nothing sent at all', fake.Screen.sent == [], fake.Screen.sent)
    check('the dialog says LIST', 'LIST' in last_message(fake)[1], last_message(fake))


# ---------------------------------------------------------------------------
# The fleet.
# ---------------------------------------------------------------------------

def test_bulk_verdict(tmpdir):
    print('\nbulk: the verdict counts completed against every session in the list')
    switches = {
        'site/sw-1': Switch('SW1', acl=MANAGED),
        'site/sw-2': Switch('SW2', acl=MANAGED),
        'site/sw-3': Switch('SW3', acl=None),
        'site/sw-4': Switch('SW4', acl=MANAGED, refs=' access-class SNMP_ACCESS in'),
        'site/sw-5': Switch('SW5', acl=MANAGED, reject=('permit 192.0.2.21 log',)),
        'site/sw-6': Switch('SW6', acl=MANAGED, users=''),
    }
    sessions = [(name, f'192.0.2.{i}') for i, name in enumerate(sorted(switches), 1)]
    sessions.append(('site/sw-dead', '192.0.2.99'))
    sessions.append(('site/sw-1-copy', '192.0.2.1'))
    fake = run_bulk(tmpdir, switches, sessions)
    title, text, _ = last_message(fake)
    check('the closing dialog is the verdict', title == 'SNMP ACL bulk - verdict', title)
    check('completed on 3 of 7 (the duplicate is not a switch)',
          'Completed on 3 of 7 switch(es).' in text, text)
    check('one of the three completed with a warning', '1 of those completed with a warning'
          in text, text)
    check('the failed one is named as failed', 'FAILED on 1' in text, text)
    check('the rest are not changed, by outcome', 'skipped 2' in text and 'unreachable 1' in text,
          text)
    rows = {row['session']: row for row in log_rows(tmpdir)}
    check('a row for every session, the duplicate included', len(rows) == 8, sorted(rows))
    check('the vty ACL was skipped and left alone',
          rows['site/sw-4']['outcome'] == 'skipped' and switches['site/sw-4'].acl == MANAGED,
          rows.get('site/sw-4'))
    check('the missing ACL was skipped, not created',
          rows['site/sw-3']['outcome'] == 'skipped' and switches['site/sw-3'].acl is None)
    check('the rejected permit is failed', rows['site/sw-5']['outcome'] == 'failed',
          rows.get('site/sw-5'))
    check('the warning is in its column', 'SNMPV3_USER' in rows['site/sw-6']['warnings'],
          rows.get('site/sw-6'))
    verdicts = [n for n in os.listdir(tmpdir) if n.endswith('_verdict.txt')]
    check('the verdict is written beside the log', len(verdicts) == 1, os.listdir(tmpdir))
    if verdicts:
        with open(os.path.join(tmpdir, verdicts[0]), encoding='utf-8') as handle:
            check('and says the same', 'Completed on 3 of 7' in handle.read())


def test_bulk_cancel(tmpdir):
    print('\nbulk: No at the confirmation connects to nothing')
    switches = {'site/sw-1': Switch('SW1', acl=MANAGED)}
    fake = run_bulk(tmpdir, switches, [('site/sw-1', '192.0.2.1')], confirm=False)
    check('nothing sent', fake.Screen.sent == [], fake.Screen.sent)
    check('the list untouched', switches['site/sw-1'].acl == MANAGED)


def test_bulk_renumber(tmpdir):
    print('\nbulk: a switch with no room is renumbered only when the run said so')
    tight = {10: 'permit 192.0.2.10', 11: 'permit 192.0.2.11', 12: 'deny any log'}
    switches = {'site/a': Switch('A', acl=tight)}
    run_bulk(tmpdir, switches, [('site/a', '192.0.2.1')], renumber=False)
    check('left alone when not', switches['site/a'].acl == tight, switches['site/a'].acl)
    other = tempfile.mkdtemp()
    try:
        switches = {'site/a': Switch('A', acl=tight)}
        fake = run_bulk(other, switches, [('site/a', '192.0.2.1')], renumber=True)
        check('completed when it did', 'Completed on 1 of 1' in last_message(fake)[1],
              last_message(fake))
    finally:
        shutil.rmtree(other)


def test_relog_existing(tmpdir):
    print('\none switch: every existing permit without log gets it, at its own number')
    acl = {10: 'permit 192.0.2.10', 20: 'permit 192.0.2.64 0.0.0.31',
           30: 'permit host 192.0.2.30 log', 40: 'deny any log'}
    switch = Switch(acl=acl)
    fake = run_single(tmpdir, switch)
    check('completed', last_message(fake)[0] == 'SNMP ACL - COMPLETED', last_message(fake))
    check('each was replaced in place, not the list cleared',
          ['no 10', '10 permit 192.0.2.10 log', 'no 20', '20 permit 192.0.2.64 0.0.0.31 log']
          == [c for c in switch.configured if re.match(r'^(no )?[12]0\b', c)], switch.configured)
    check('the one that already had log was not touched', 'no 30' not in switch.configured)
    check('the deny was not touched', 'no 40' not in switch.configured)
    check('every permit now ends in log',
          all(text.endswith(' log') for text in switch.acl.values()), switch.acl)
    check('the order is unchanged', [switch.acl[s] for s in sorted(switch.acl)][:3] == [
        'permit 192.0.2.10 log', 'permit 192.0.2.64 0.0.0.31 log', 'permit host 192.0.2.30 log'],
        switch.acl)
    rows = log_rows(tmpdir)
    check('the log says how many got log', rows and 'log added to 2 existing permit(s)'
          in rows[0]['reason'], rows)


def test_relog_rejected_is_failed(tmpdir):
    print('\none switch: a re-add the switch refuses leaves the verdict FAILED, not completed')
    switch = Switch(acl=MANAGED, reject=('10 permit 192.0.2.10 log',))
    fake = run_single(tmpdir, switch)
    title, text, _ = last_message(fake)
    check('the verdict is FAILED', title == 'SNMP ACL - FAILED', f'{title}\n{text}')
    check('and names the entry that is gone', 'GONE after adding log' in text, text)


def test_bulk_no_save_by_answer(tmpdir):
    print('\nbulk: No at the save question writes startup-config nowhere')
    switches = {'site/sw-1': Switch('SW1', acl=MANAGED)}
    fake = run_bulk(tmpdir, switches, [('site/sw-1', '192.0.2.1')], save=False)
    check('completed', 'Completed on 1 of 1' in last_message(fake)[1], last_message(fake))
    check('write memory never sent', 'write memory' not in fake.Screen.sent, fake.Screen.sent)
    check('the verdict says nothing was saved', 'NOT written' in last_message(fake)[1])


def test_bulk_save_completed_only(tmpdir):
    print('\nbulk: Yes at the save question saves completed switches and only those')
    switches = {
        'site/sw-1': Switch('SW1', acl=MANAGED),
        'site/sw-2': Switch('SW2', acl=MANAGED, reject=('permit 192.0.2.21 log',)),
        'site/sw-3': Switch('SW3', acl=None),
        'site/sw-4': Switch('SW4', acl=MANAGED, refs=' access-class SNMP_ACCESS in'),
        'site/sw-5': Switch('SW5', acl=MANAGED, reject=('write memory',)),
    }
    sessions = [(name, f'192.0.2.{i}') for i, name in enumerate(sorted(switches), 1)]
    fake = run_bulk(tmpdir, switches, sessions, save=True)
    text = last_message(fake)[1]
    check('the completed switch was saved', switches['site/sw-1'].saved)
    check('the failed switch was not', not switches['site/sw-2'].saved)
    check('the missing-ACL switch was not', not switches['site/sw-3'].saved)
    check('the vty switch was not', not switches['site/sw-4'].saved)
    check('the verdict counts the saves', 'Saved to startup-config on 1 of 2 completed.' in text,
          text)
    check('the unsaved completed one is named', '1 completed but NOT saved' in text, text)
    rows = {row['session']: row for row in log_rows(tmpdir)}
    check('the saved row says so', 'saved to startup-config' in rows['site/sw-1']['reason'],
          rows.get('site/sw-1'))
    check('the unsaved row warns', 'NOT saved' in rows['site/sw-5']['warnings'],
          rows.get('site/sw-5'))


def test_verdict_text():
    print('\nthe verdict reads the same however it is reached')
    text = crt_snmp.verdict({'completed': 5}, 5)
    check('a clean run', text == 'Completed on 5 of 5 switch(es).', text)
    text = crt_snmp.verdict({'completed': 2, 'unreachable': 1, 'duplicate': 1}, 3)
    check('the duplicate is reported but not counted against the total',
          'Completed on 2 of 3' in text and '1 duplicate' in text, text)
    check('nothing failed, so no FAILED line', 'FAILED' not in text, text)


def main():
    test_parity()
    test_verdict_text()
    for test in (test_single_completed, test_single_pinned, test_single_cancel,
                 test_single_vty_defaults_to_no, test_single_no_room, test_single_missing_acl,
                 test_single_failed_readback, test_single_missing_user_is_a_warning,
                 test_single_bad_inventory, test_bulk_verdict, test_bulk_cancel,
                 test_bulk_renumber, test_bulk_no_save_by_answer,
                 test_bulk_save_completed_only, test_relog_existing,
                 test_relog_rejected_is_failed):
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
