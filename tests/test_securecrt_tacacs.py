#!/usr/bin/env python
"""Verification for securecrt/tacacs_l2s.py and tacacs_l2s_bulk.py.

Run directly: `python3 tests/test_securecrt_tacacs.py`. No framework, no
SecureCRT, no devices.

The fake switch below keeps its own TACACS+ configuration - server blocks,
legacy `tacacs-server host` lines, server groups - applies what it is sent the
way IOS does, and renders it back for `show running-config | section tacacs`.
So "completed" is judged against a configuration that could genuinely have
ended up wrong, not against an echo of the commands. The key is checked to
reach the switch and to reach nothing else: no dialog, no log row.
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
sys.path.insert(0, os.path.join(PROJECT, 'securecrt'))
sys.path.insert(0, os.path.join(PROJECT, 'scripts'))
sys.path.insert(0, os.path.join(PROJECT, 'tests'))

import capture_l2s
import capture_l2s_bulk as bulk
import harden_l2s_bulk as harden
import snmp_acl_l2s as snmp
import snmp_acl_l2s_bulk as snmp_bulk
import tacacs_l2s as tacacs
import tacacs_l2s_bulk as tacacs_bulk
from test_securecrt_snmp_acl import FakeCRT

failures = []

KEY = 'S3cretTacKey!'


def check(name, condition, detail=''):
    print(f'  {"ok  " if condition else "FAIL"} {name}')
    if not condition:
        if detail:
            print(f'       {detail}')
        failures.append(name)


# ---------------------------------------------------------------------------
# The fake switch.
# ---------------------------------------------------------------------------

class Switch:
    def __init__(self, hostname='TESTSW01', servers=None, legacy=(), groups=None,
                 aaa=('aaa new-model', 'aaa authentication login default group TACGRP local'),
                 reject=()):
        self.hostname = hostname
        # name -> {'address': ip, 'key': key typed or None}
        self.servers = {name: dict(info) for name, info in (servers or {}).items()}
        self.legacy = list(legacy)
        # group -> ['server name X' | 'server 1.2.3.4' | 'server-private 1.2.3.4 key 7 x']
        self.groups = {name: list(lines) for name, lines in (groups or {}).items()}
        self.aaa = list(aaa)
        self.reject = reject
        self.mode = 'exec'
        self.context = None
        self.configured = []
        self.saved = False

    def render_section(self):
        lines = []
        for name, info in self.servers.items():
            lines.append(f'tacacs server {name}')
            if info.get('address'):
                lines.append(f' address ipv4 {info["address"]}')
            if info.get('key'):
                lines.append(' key 7 0822455D0A16544541')
        for ip in self.legacy:
            lines.append(f'tacacs-server host {ip} key 7 045802150C2E')
        for name, members in self.groups.items():
            lines.append(f'aaa group server tacacs+ {name}')
            lines += [' ' + member for member in members]
        lines += [line for line in self.aaa if 'tacacs' in line]
        return '\n'.join(lines)

    def answer(self, command):
        if command in self.reject or any(command.startswith(r) for r in self.reject):
            return '% Invalid input detected at \'^\' marker.'
        if self.mode == 'exec':
            if command == 'terminal length 0':
                return ''
            if command == 'show running-config | section tacacs':
                return self.render_section()
            if command == 'show running-config | include ^aaa':
                return '\n'.join(self.aaa + [f'aaa group server tacacs+ {g}' for g in self.groups])
            if command == 'write memory':
                self.saved = True
                return 'Building configuration...\n[OK]'
            if command == 'configure terminal':
                self.mode = 'config'
                return 'Enter configuration commands, one per line.'
            return ''
        self.configured.append(command)
        if command == 'end':
            self.mode, self.context = 'exec', None
            return '%SYS-5-CONFIG_I: Configured from console by admin on vty0'
        if command == 'exit':
            self.mode, self.context = 'config', None
            return ''
        if self.mode == 'server':
            info = self.servers[self.context]
            if command.startswith('address ipv4 '):
                info['address'] = command.split()[2]
            elif command.startswith('key '):
                info['key'] = command[4:]
            return ''
        if self.mode == 'group':
            members = self.groups[self.context]
            if command.startswith('no '):
                target = command[3:]
                for member in list(members):
                    if member == target or member.startswith(target + ' '):
                        members.remove(member)
            elif command not in members:
                members.append(command)
            return ''
        match = re.match(r'^tacacs server (\S+)$', command)
        if match:
            self.servers.setdefault(match.group(1), {'address': None, 'key': None})
            self.mode, self.context = 'server', match.group(1)
            return ''
        match = re.match(r'^no tacacs server (\S+)$', command)
        if match:
            self.servers.pop(match.group(1), None)
            return ''
        match = re.match(r'^no tacacs-server host (\S+)$', command)
        if match:
            self.legacy = [ip for ip in self.legacy if ip != match.group(1)]
            return ''
        match = re.match(r'^aaa group server tacacs\+ (\S+)$', command)
        if match:
            self.groups.setdefault(match.group(1), [])
            self.mode, self.context = 'group', match.group(1)
            return ''
        return ''

    @property
    def prompt(self):
        return {'exec': f'{self.hostname}#', 'config': f'{self.hostname}(config)#',
                'server': f'{self.hostname}(config-server-tacacs)#',
                'group': f'{self.hostname}(config-sg-tacacs+)#'}[self.mode]

    def addresses(self):
        return sorted({info['address'] for info in self.servers.values() if info['address']}
                      | set(self.legacy))


SECTION = {
    'group_name': 'TACGRP',
    'add': ['192.0.2.5', '192.0.2.6'],
    'remove': [],
    'remove_from_group': [],
    'server_name_prefix': 'TACACS',
    'timeout': None,
}


def with_files(tmpdir, section, key=KEY):
    path = os.path.join(tmpdir, 'inventory.yaml')
    with open(path, 'w', encoding='utf-8') as handle:
        json.dump({'devices': {}, 'tacacs': section}, handle)
    with open(os.path.join(tmpdir, 'secrets.yaml'), 'w', encoding='utf-8') as handle:
        handle.write('# secrets.yaml\nradius_key: other\n'
                     '# TACACS+ shared key\ntacacs_key: {0}   # comment\n'.format(key))
    return path


MODULES = (capture_l2s, bulk, harden, snmp, snmp_bulk, tacacs, tacacs_bulk)
ORIGINAL_INVENTORY_PATH = tacacs.inventory_path
ORIGINAL_FIND = bulk.find_sessions
ORIGINAL_OUTPUT = tacacs.OUTPUT_DIR


def install(fake, inventory):
    for module in MODULES:
        module.crt = fake
    tacacs.inventory_path = lambda: inventory


def uninstall():
    for module in MODULES:
        module.crt = None
    tacacs.inventory_path = ORIGINAL_INVENTORY_PATH
    bulk.find_sessions = ORIGINAL_FIND
    tacacs.OUTPUT_DIR = ORIGINAL_OUTPUT


def run_single(tmpdir, switch, section=SECTION, confirm=True, key=KEY):
    fake = FakeCRT(tmpdir, switch=switch, confirm=confirm)
    install(fake, with_files(tmpdir, section, key))
    tacacs.OUTPUT_DIR = tmpdir
    try:
        tacacs.main()
    finally:
        uninstall()
    return fake


def run_bulk(tmpdir, switches, sessions, section=SECTION, confirm=True, save=False):
    fake = FakeCRT(tmpdir, switch=Switch(), switches=switches, confirm=confirm, save=save)
    install(fake, with_files(tmpdir, section))
    bulk.find_sessions = lambda _filter='': list(sessions)
    try:
        tacacs_bulk.main()
    finally:
        uninstall()
    return fake


def log_text(tmpdir):
    text = ''
    for name in sorted(os.listdir(tmpdir)):
        if name.startswith('tacacs_') and name.endswith(('.csv', '.txt')):
            with io.open(os.path.join(tmpdir, name), encoding='utf-8') as handle:
                text += handle.read()
    return text


def log_rows(tmpdir):
    rows = []
    for name in sorted(os.listdir(tmpdir)):
        if name.startswith('tacacs_') and name.endswith('.csv'):
            with io.open(os.path.join(tmpdir, name), encoding='utf-8', newline='') as handle:
                rows.extend(csv.DictReader(handle.read().splitlines()))
    return rows


def last(fake):
    return fake.messages[-1] if fake.messages else ('', '', 0)


def key_leaked(fake, tmpdir):
    shown = '\n'.join(title + '\n' + text for title, text, _ in fake.messages)
    return KEY in shown or KEY in log_text(tmpdir)


# ---------------------------------------------------------------------------
# Settings and parsing.
# ---------------------------------------------------------------------------

def refused(section, key=KEY):
    try:
        tacacs.load_config(section, key)
    except tacacs.TacacsError as error:
        return str(error)
    return ''


def test_settings():
    print('\nsettings: bad shapes stop the run before anything is sent')
    settings = tacacs.load_config(SECTION, KEY)
    check('a good section loads', settings.add == ['192.0.2.5', '192.0.2.6'])
    check('a new server is TACACS1 on a switch with none',
          settings.next_name(set()) == 'TACACS1')
    check('the lowest free number is used',
          settings.next_name({'TACACS1', 'tacacs3'}) == 'TACACS2')
    check('a name differing only in case counts as taken',
          settings.next_name({'tacacs1'}) == 'TACACS2')
    check('a bare string is refused', 'LIST' in refused(dict(SECTION, add='192.0.2.5')))
    check('the x.x.x.x placeholder is refused',
          'not an IPv4' in refused(dict(SECTION, add=['x.x.x.x'])))
    check('an address in two lists is refused',
          'both' in refused(dict(SECTION, remove=['192.0.2.5'])))
    check('add without a key is refused', 'tacacs_key' in refused(SECTION, ''))
    check('the example CHANGE_ME key is refused', 'tacacs_key' in refused(SECTION, 'CHANGE_ME'))
    check('a key with a ? is refused', refused(SECTION, 'abc?def') != '')
    check('removing needs no key', refused(dict(SECTION, add=[], remove=['192.0.2.9']), '') == '')
    check('a group is needed to add', 'group_name' in refused(dict(SECTION, group_name='')))
    check('an empty declaration is refused',
          'nothing' in refused(dict(SECTION, add=[])))
    check('a bad timeout is refused', 'timeout' in refused(dict(SECTION, timeout=0)))


def test_read_secret(tmpdir):
    print('\nsecrets.yaml: read with the standard library, comments and quotes included')
    path = os.path.join(tmpdir, 'secrets.yaml')
    for content, expected in (('tacacs_key: abc123  # the key\n', 'abc123'),
                              ('vtp_password: x\ntacacs_key: "q w"\n', 'q w'),
                              ("tacacs_key: 'single'\n", 'single'),
                              ('{"tacacs_key": "json"}', 'json'),
                              ('radius_key: x\n', '')):
        with open(path, 'w', encoding='utf-8') as handle:
            handle.write(content)
        got = tacacs.read_secret(path, 'tacacs_key')
        check(f'{content.strip()!r} reads as {expected!r}', got == expected, got)
    check('a missing file reads as empty',
          tacacs.read_secret(os.path.join(tmpdir, 'nope.yaml'), 'tacacs_key') == '')


def test_parse():
    print('\nparsing: modern servers, legacy hosts, groups and method lists')
    state = tacacs.parse_state(
        'tacacs server ISE1\n address ipv4 192.0.2.10\n key 7 0822\n timeout 2\n'
        'tacacs server NOKEY\n address ipv4 192.0.2.11\n'
        'tacacs-server host 192.0.2.12 key 7 0458\n'
        'aaa group server tacacs+ TACGRP\n server name ISE1\n server 192.0.2.12\n'
        ' server-private 192.0.2.13 key 7 abc\n ip vrf forwarding Mgmt-vrf\n'
        'aaa authentication login default group tacacs+ local\n',
        'aaa new-model\naaa authentication login default group TACGRP local\n'
        'aaa authorization exec default group TACGRP if-authenticated\n')
    check('aaa new-model seen', state.new_model)
    check('the modern server and its address', state.servers['ISE1'] == {
        'address': '192.0.2.10', 'key': True}, state.servers)
    check('a server without a key is noticed', state.servers['NOKEY']['key'] is False)
    check('the legacy host', state.legacy == ['192.0.2.12'], state.legacy)
    check('every kind of group member', state.groups['TACGRP'] == [
        ('name', 'ISE1'), ('ip', '192.0.2.12'), ('private', '192.0.2.13')], state.groups)
    check('membership is found through the server name', state.in_group('TACGRP', '192.0.2.10'))
    check('the method lists name the group', state.method_groups == {'TACGRP'},
          state.method_groups)


# ---------------------------------------------------------------------------
# One switch.
# ---------------------------------------------------------------------------

def test_add_new(tmpdir):
    print('\none switch: two new servers defined with the key and put in the group')
    switch = Switch()
    fake = run_single(tmpdir, switch)
    title, text, _ = last(fake)
    check('completed', title == 'TACACS - COMPLETED', f'{title}\n{text}')
    check('both servers are defined', switch.addresses() == ['192.0.2.5', '192.0.2.6'],
          switch.servers)
    check('with the key from secrets.yaml',
          all(info['key'] == KEY for info in switch.servers.values()), switch.servers)
    check('and in the group', switch.groups.get('TACGRP') == [
        'server name TACACS1', 'server name TACACS2'], switch.groups)
    confirm = [m for m in fake.messages if m[0] == 'TACACS - confirm']
    check('the confirmation shows the masked key', confirm and 'key ********' in confirm[0][1],
          confirm)
    check('the key is in no dialog and no log', not key_leaked(fake, tmpdir))
    check('aaa method lists were not touched',
          not any(c.startswith('aaa authentication') for c in switch.configured))
    check('nothing was saved', not switch.saved)
    rows = log_rows(tmpdir)
    check('the row names what was added',
          rows and 'TACACS1 192.0.2.5' in rows[0]['added'], rows)


def test_timeout(tmpdir):
    print('\none switch: a declared timeout goes into each new server')
    switch = Switch()
    run_single(tmpdir, switch, dict(SECTION, timeout=3))
    check('timeout 3 sent twice', switch.configured.count('timeout 3') == 2, switch.configured)


def test_rerun_sends_nothing(tmpdir):
    print('\none switch: a second run finds everything in place and sends nothing')
    switch = Switch()
    run_single(tmpdir, switch)
    sent = len(switch.configured)
    other = tempfile.mkdtemp()
    try:
        fake = run_single(other, switch)
    finally:
        shutil.rmtree(other)
    check('completed', last(fake)[0] == 'TACACS - COMPLETED', last(fake))
    check('no further config', len(switch.configured) == sent, switch.configured[sent:])
    check('and says so', 'nothing sent' in last(fake)[1], last(fake))


def test_add_reuses_existing(tmpdir):
    print('\none switch: an address already defined under another name is reused')
    switch = Switch(servers={'ISE1': {'address': '192.0.2.5', 'key': 'old'}},
                    legacy=['192.0.2.6'])
    fake = run_single(tmpdir, switch)
    check('completed', last(fake)[0] == 'TACACS - COMPLETED', last(fake))
    check('no new server block', not any(c.startswith('tacacs server') for c in switch.configured),
          switch.configured)
    check('the existing key is left alone', switch.servers['ISE1']['key'] == 'old')
    check('joined by name and by address', switch.groups['TACGRP'] == [
        'server name ISE1', 'server 192.0.2.6'], switch.groups)
    check('the kept key is said out loud', 'key left as it was' in last(fake)[1], last(fake))


def test_remove(tmpdir):
    print('\none switch: remove takes a server out of every group, then deletes it')
    switch = Switch(
        servers={'ISE1': {'address': '192.0.2.9', 'key': 'k'},
                 'ISE2': {'address': '192.0.2.10', 'key': 'k'}},
        legacy=['192.0.2.11'],
        groups={'TACGRP': ['server name ISE1', 'server name ISE2', 'server 192.0.2.11'],
                'OTHER': ['server name ISE1']})
    section = dict(SECTION, add=[], remove=['192.0.2.9', '192.0.2.11'])
    fake = run_single(tmpdir, switch, section, key='')
    check('completed', last(fake)[0] == 'TACACS - COMPLETED', last(fake))
    check('both gone from the switch', switch.addresses() == ['192.0.2.10'], switch.addresses())
    check('and from both groups', switch.groups == {'TACGRP': ['server name ISE2'],
                                                    'OTHER': []}, switch.groups)
    order = switch.configured
    check('out of the group before the delete',
          order.index('no server name ISE1') < order.index('no tacacs server ISE1'), order)
    check('the legacy line is removed as a legacy line',
          'no tacacs-server host 192.0.2.11' in order, order)


def test_remove_from_group(tmpdir):
    print('\none switch: remove_from_group leaves the definition in place')
    switch = Switch(servers={'ISE1': {'address': '192.0.2.9', 'key': 'k'},
                             'ISE2': {'address': '192.0.2.10', 'key': 'k'}},
                    groups={'TACGRP': ['server name ISE1', 'server name ISE2'],
                            'OTHER': ['server name ISE1']})
    section = dict(SECTION, add=[], remove_from_group=['192.0.2.9'])
    fake = run_single(tmpdir, switch, section, key='')
    check('completed', last(fake)[0] == 'TACACS - COMPLETED', last(fake))
    check('out of TACGRP', switch.groups['TACGRP'] == ['server name ISE2'], switch.groups)
    check('still in the other group', switch.groups['OTHER'] == ['server name ISE1'])
    check('still defined', '192.0.2.9' in switch.addresses())


def test_lockout_guard(tmpdir):
    print('\none switch: emptying a group a login method uses is refused')
    switch = Switch(servers={'ISE1': {'address': '192.0.2.9', 'key': 'k'}},
                    groups={'TACGRP': ['server name ISE1']})
    fake = run_single(tmpdir, switch, dict(SECTION, add=[], remove=['192.0.2.9']), key='')
    check('not changed', last(fake)[0] == 'TACACS - not changed', last(fake))
    check('nothing configured', 'configure terminal' not in fake.Screen.sent, fake.Screen.sent)
    check('the reason names the group', 'TACGRP' in last(fake)[1], last(fake))

    other = tempfile.mkdtemp()
    try:
        switch = Switch(servers={'TACACS1': {'address': '192.0.2.9', 'key': 'k'}},
                        groups={'TACGRP': ['server name TACACS1']})
        fake = run_single(other, switch, dict(SECTION, add=['192.0.2.5'], remove=['192.0.2.9']))
    finally:
        shutil.rmtree(other)
    check('with a replacement in the same run it goes ahead',
          last(fake)[0] == 'TACACS - COMPLETED', last(fake))
    check('the replacement is the group now',
          switch.groups['TACGRP'] == ['server name TACACS2'], switch.groups)
    check('the removed TACACS1 name is not reused in the same run',
          'TACACS1' not in switch.servers
          and switch.servers.get('TACACS2', {}).get('address') == '192.0.2.5', switch.servers)

    other = tempfile.mkdtemp()
    try:
        switch = Switch(servers={'ISE1': {'address': '192.0.2.9', 'key': 'k'}},
                        aaa=('aaa new-model',
                             'aaa authentication login default group tacacs+ local'))
        fake = run_single(other, switch, dict(SECTION, add=[], remove=['192.0.2.9']), key='')
    finally:
        shutil.rmtree(other)
    check('`group tacacs+` counts every defined server',
          last(fake)[0] == 'TACACS - not changed', last(fake))


def test_no_new_model(tmpdir):
    print('\none switch: without aaa new-model nothing is sent')
    switch = Switch(aaa=())
    fake = run_single(tmpdir, switch)
    check('not changed', last(fake)[0] == 'TACACS - not changed', last(fake))
    check('nothing configured', 'configure terminal' not in fake.Screen.sent)
    check('aaa new-model is not pushed', 'aaa new-model' not in fake.Screen.sent)


def test_numbering(tmpdir):
    print('\none switch: new servers take the lowest numbers free on that switch')
    switch = Switch(servers={'TACACS1': {'address': '192.0.2.99', 'key': 'k'},
                             'TACACS3': {'address': '192.0.2.98', 'key': 'k'}})
    fake = run_single(tmpdir, switch)
    check('completed', last(fake)[0] == 'TACACS - COMPLETED', last(fake))
    check('192.0.2.5 is TACACS2 and 192.0.2.6 is TACACS4',
          switch.servers.get('TACACS2', {}).get('address') == '192.0.2.5'
          and switch.servers.get('TACACS4', {}).get('address') == '192.0.2.6', switch.servers)
    check('the existing servers keep their addresses',
          switch.servers['TACACS1']['address'] == '192.0.2.99'
          and switch.servers['TACACS3']['address'] == '192.0.2.98', switch.servers)
    check('no existing name was redefined',
          'tacacs server TACACS1' not in switch.configured
          and 'tacacs server TACACS3' not in switch.configured, switch.configured)


def test_rejected_key(tmpdir):
    print('\none switch: a rejected key line is FAILED, and the key stays masked')
    switch = Switch(reject=('key ',))
    fake = run_single(tmpdir, switch)
    title, text, _ = last(fake)
    check('failed', title == 'TACACS - FAILED', f'{title}\n{text}')
    check('it says the server has no key', 'has no key' in text, text)
    check('the key is in no dialog and no log', not key_leaked(fake, tmpdir))


def test_cancel(tmpdir):
    print('\none switch: No at the confirmation sends nothing')
    switch = Switch()
    fake = run_single(tmpdir, switch, confirm=False)
    check('config mode never entered', 'configure terminal' not in fake.Screen.sent)
    check('not changed', last(fake)[0] == 'TACACS - not changed')


def test_bad_inventory(tmpdir):
    print('\none switch: a bad inventory stops the run before anything is sent')
    fake = run_single(tmpdir, Switch(), dict(SECTION, add=['x.x.x.x']))
    check('nothing sent', fake.Screen.sent == [], fake.Screen.sent)
    check('the dialog says why', 'IPv4' in last(fake)[1], last(fake))


# ---------------------------------------------------------------------------
# The fleet.
# ---------------------------------------------------------------------------

def test_bulk(tmpdir):
    print('\nbulk: every session accounted for, completed ones saved, the key nowhere')
    switches = {
        'site/sw-1': Switch('SW1'),
        'site/sw-2': Switch('SW2', servers={'ISE1': {'address': '192.0.2.5', 'key': 'k'}}),
        'site/sw-3': Switch('SW3', aaa=()),
        'site/sw-4': Switch('SW4', reject=('key ',)),
    }
    sessions = [(name, f'198.51.100.{i}') for i, name in enumerate(sorted(switches), 1)]
    sessions.append(('site/sw-dead', '198.51.100.99'))
    fake = run_bulk(tmpdir, switches, sessions, save=True)
    title, text, _ = last(fake)
    check('the closing dialog is the verdict', title == 'TACACS bulk - verdict', title)
    check('completed on 2 of 5', 'Completed on 2 of 5 switch(es).' in text, text)
    check('the failed one is counted', 'FAILED on 1' in text, text)
    check('skipped and unreachable are counted', 'skipped 1' in text and 'unreachable 1' in text,
          text)
    check('the completed switches were saved',
          switches['site/sw-1'].saved and switches['site/sw-2'].saved)
    check('the failed and skipped were not',
          not switches['site/sw-3'].saved and not switches['site/sw-4'].saved)
    rows = {row['session']: row for row in log_rows(tmpdir)}
    check('a row for every session', len(rows) == 5, sorted(rows))
    check('the skipped one says why', 'aaa new-model' in rows['site/sw-3']['reason'],
          rows.get('site/sw-3'))
    check('the key is in no dialog and no log', not key_leaked(fake, tmpdir))
    check('the verdict file is written',
          any(n.endswith('_verdict.txt') for n in os.listdir(tmpdir)), os.listdir(tmpdir))


def test_bulk_cancel(tmpdir):
    print('\nbulk: No at the confirmation connects to nothing')
    switches = {'site/sw-1': Switch('SW1')}
    fake = run_bulk(tmpdir, switches, [('site/sw-1', '198.51.100.1')], confirm=False)
    check('nothing sent', fake.Screen.sent == [], fake.Screen.sent)
    check('nothing configured', switches['site/sw-1'].configured == [])


def main():
    test_settings()
    test_parse()
    for test in (test_read_secret, test_add_new, test_timeout, test_rerun_sends_nothing,
                 test_add_reuses_existing, test_remove, test_remove_from_group,
                 test_lockout_guard, test_no_new_model, test_numbering, test_rejected_key,
                 test_cancel, test_bad_inventory, test_bulk, test_bulk_cancel):
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
