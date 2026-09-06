#!/usr/bin/env python
"""Verification for securecrt/capture_l2s.py.

Run directly: `python3 tests/test_securecrt_script.py`. No framework, no
SecureCRT, no device.

The script is standalone by necessity - it runs inside SecureCRT's embedded
Python on a machine that may have nothing else installed - so it duplicates
capture.py's delimiter format and command list instead of importing them. That
duplication is the risk this file exists to control: the two could drift and
nothing would notice until a capture taken at work failed to parse at home.
So the constants are asserted equal, and a stubbed SecureCRT drives the real
main() to produce a real file, which capture.load() then has to accept.
"""

import json
import os
import re
import sys
import tempfile

PROJECT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(PROJECT, 'securecrt'))

import capture
import capture_l2s
import fixtures
from fixtures import OUTPUTS

failures = []


def check(name, condition, detail=''):
    print(f'  {"ok  " if condition else "FAIL"} {name}')
    if not condition:
        if detail:
            print(f'       {detail}')
        failures.append(name)


class FakeScreen:
    """Stands in for crt.Screen, replaying fixture output command by command.

    Emulates the two behaviours the script depends on: ReadString returns
    everything since the last send up to the prompt, and the switch echoes the
    command back first."""

    def __init__(self, prompt, outputs, paginate=None, empty=None, timeout_on=None):
        self.prompt = prompt
        self.outputs = outputs
        self.paginate = paginate
        self.empty = empty
        self.timeout_on = timeout_on
        self.Synchronous = False
        self.sent = []
        self._pending = ''
        self.CurrentRow = 5
        self.CurrentColumn = len(prompt) + 1

    def Get(self, row1, col1, row2, col2):
        return self.prompt

    def Send(self, text):
        command = text.rstrip('\r\n')
        self.sent.append(command)
        if command == self.timeout_on:
            self._pending = None
            return
        if command == 'terminal length 0':
            body = ''
        elif command == self.empty:
            body = ''
        elif command == self.paginate:
            body = ' --More-- \nsome truncated output'
        else:
            body = self.outputs.get(command, '')
        # The device echoes the command, then its output, then the prompt.
        self._pending = f'{command}\r\n{body}\r\n'

    def ReadString(self, terminator, timeout=None):
        pending, self._pending = self._pending, ''
        return pending


class FakeDialog:
    def __init__(self, path):
        self.path = path
        self.messages = []

    def MessageBox(self, message, title='', flags=0):
        self.messages.append((title, message))
        return 1

    def Prompt(self, message, title='', default=''):
        return self.path


class FakeCRT:
    def __init__(self, prompt='TESTSW01#', outputs=None, path='', connected=True, **kwargs):
        self.Screen = FakeScreen(prompt, outputs if outputs is not None else OUTPUTS, **kwargs)
        self.Dialog = FakeDialog(path)
        self.Session = type('Session', (), {'Connected': connected})()


def run_script(**kwargs):
    """Drive the real main() with a stubbed SecureCRT."""
    fake = FakeCRT(**kwargs)
    capture_l2s.crt = fake
    try:
        capture_l2s.main()
    finally:
        capture_l2s.crt = None
    return fake


# l2_stig_audit.py parses argv and runs an audit at import, so its readers
# cannot simply be imported here. They are lifted out of its source instead -
# ugly, and much less ugly than a second hand-written copy of what they are
# supposed to agree with.
def audit_version_readers():
    """The audit's `show version` readers, executed out of its source."""
    with open(os.path.join(PROJECT, 'l2_stig_audit.py'), encoding='utf-8') as handle:
        source = handle.read()
    start = source.index('_SWITCH_TABLE_HEADER = ')
    end = source.index('def _ios_release_supported_check')
    namespace = {'re': __import__('re')}
    exec(compile(source[start:end], 'l2_stig_audit.py', 'exec'), namespace)
    return namespace


# A `show version` with no version banner and no `Model Number` line, where the
# switch table is the only place either fact appears. Both readers have to
# agree there too, not just on the easy shape.
SHOW_VERSION_TABLE_ONLY = """Cisco IOS Software [Dublin], Catalyst L3 Switch Software (CAT9K_IOSXE)

Switch Ports Model              SW Version        SW Image              Mode
------ ----- -----              ----------        ----------            ----
*    1 52    C9300-48P          17.12.04          CAT9K_IOSXE           INSTALL"""


def test_constants_match_capture_module():
    print('standalone copies match capture.py')
    check('delimiter prefix identical',
          capture_l2s.DELIMITER_PREFIX == capture.DELIMITER_PREFIX,
          f'{capture_l2s.DELIMITER_PREFIX!r} vs {capture.DELIMITER_PREFIX!r}')
    check('delimiter suffix identical',
          capture_l2s.DELIMITER_SUFFIX == capture.DELIMITER_SUFFIX)
    check('delimiter line identical for a sample command',
          capture_l2s.format_delimiter('show vtp password')
          == capture.format_delimiter('show vtp password'))
    # The collector sends the required commands and the optional ones alike -
    # it is the only chance to read the switch, so a command left out here is
    # one no later audit of that capture can ever have.
    check('command list identical',
          tuple(capture_l2s.COMMANDS)
          == tuple(capture.AUDIT_COMMANDS_L2S) + tuple(capture.OPTIONAL_COMMANDS_L2S),
          f'{capture_l2s.COMMANDS} vs '
          f'{capture.AUDIT_COMMANDS_L2S + capture.OPTIONAL_COMMANDS_L2S}')
    check('empty-is-an-answer list identical',
          tuple(capture_l2s.EMPTY_IS_AN_ANSWER) == tuple(capture.EMPTY_IS_AN_ANSWER),
          f'{capture_l2s.EMPTY_IS_AN_ANSWER} vs {capture.EMPTY_IS_AN_ANSWER}')
    # The per-device sixth command. The collector spells it, the loader demands
    # it by the same spelling, and a capture whose section headers disagree with
    # what the audit asks for is one the audit refuses.
    check('interface template command identical',
          capture_l2s.template_command('USER_PORT') == capture.template_command('USER_PORT'),
          capture_l2s.template_command('USER_PORT'))
    sourcing = ' source template A\n source template A\n source template B\n'
    check('and both find the same names in a config, in order and without repeats',
          capture_l2s.sourced_template_names(sourcing)
          == capture.sourced_template_names(sourcing) == ['A', 'B'],
          capture_l2s.sourced_template_names(sourcing))

    # The bulk walker's run log names each switch's hostname, model and release,
    # and cannot import the audit's readers for them - nothing in securecrt/ may
    # import from the repository. So they are duplicated, and a log that
    # disagreed with the checklist beside it about which switch or which
    # release would be worse than no log at all. Asserted against the audit's
    # own readers on the same output, rather than against a hand-written
    # expectation that could go stale with both of them.
    audit = audit_version_readers()
    for name, ours, theirs, expected in (
            ('model', capture_l2s.show_version_model,
             audit['_show_version_model'], 'C9300-48P'),
            ('release', capture_l2s.show_version_release,
             audit['_show_version_release'], '17.12.4')):
        for label, output in (('the Catalyst form', fixtures.SHOW_VERSION),
                              ('the switch table alone', SHOW_VERSION_TABLE_ONLY)):
            check(f'{name} from {label} is what the audit reads',
                  ours(output) == theirs(output), f'{ours(output)!r} vs {theirs(output)!r}')
        check(f'{name} is right on the fixture', ours(fixtures.SHOW_VERSION) == expected,
              ours(fixtures.SHOW_VERSION))
    check('and the hostname is the config\'s, which is what names the checklist',
          capture_l2s.running_config_hostname(fixtures.RUNNING_CONFIG) == 'TESTSW01',
          capture_l2s.running_config_hostname(fixtures.RUNNING_CONFIG))


def test_render_round_trips():
    print('\nrendered text parses back through capture.py')
    parsed = capture.parse(capture_l2s.render(OUTPUTS))
    check('every section recovered', set(parsed) == set(OUTPUTS), sorted(parsed))
    for command, original in OUTPUTS.items():
        check(f'{command!r} verbatim', parsed.get(command) == original.strip('\n'))


def test_strip_echo():
    print('\ncommand echo removed, indentation kept')
    text = 'show running-config\r\nBuilding configuration...\r\n!\r\n hostname X\r\n'
    stripped = capture_l2s.strip_echo(text, 'show running-config')
    check('echo line dropped', not stripped.startswith('show running-config'))
    check('first real line kept', stripped.startswith('Building configuration...'))
    check('indentation preserved', ' hostname X' in stripped)
    check('a command whose output starts with its own text is safe',
          capture_l2s.strip_echo('show vtp password\r\nshow vtp password is unset\r\n',
                                 'show vtp password') == 'show vtp password is unset')


def test_full_run(tmpdir):
    print('\nfull run against a stubbed SecureCRT (audit auto-runs, folder opening suppressed)')
    out = os.path.join(tmpdir, 'run')
    os.makedirs(out, exist_ok=True)
    capture_l2s.OPEN_OUTPUT_FOLDER = False
    fake = run_script(path=out)
    check('paging disabled first', fake.Screen.sent[0] == 'terminal length 0',
          fake.Screen.sent[:2])
    check('every command sent',
          fake.Screen.sent[1:] == list(capture_l2s.COMMANDS), fake.Screen.sent[1:])
    check('synchronous mode restored', fake.Screen.Synchronous is False)
    check('reported success', any('written' in t.lower() for t, _ in fake.Dialog.messages),
          fake.Dialog.messages)

    # One file, and it is the checklist. The capture is the audit's input and
    # is cleaned up once the checklist exists; no report .txt is written at
    # all, because the checklist carries every verdict and its reason.
    written = sorted(os.listdir(out))
    checklists = [name for name in written if name.endswith('.cklb')]
    check('exactly one file is left behind', len(written) == 1, written)
    check('and it is the checklist', len(checklists) == 1, written)
    check('no capture kept', not any(name.endswith('.capture') for name in written), written)
    check('no report .txt written', not any(name.endswith('.txt') for name in written), written)

    if checklists:
        # TESTSW01 is the fixture's own `hostname`, and the versions are read
        # out of the checklist the audit ran against - so the name says which
        # switch, when, and against which benchmark revision.
        name = checklists[0]
        check('named for the switch, the date, and the STIG revisions',
              re.match(r'^TESTSW01_\d{2}[A-Z]{3}\d{4}_L2S_V\d+R\d+_NDM_V\d+R\d+\.cklb$', name),
              name)
        check('and carries no time of day', not re.search(r'\d{2}[-_:]\d{2}[-_:]\d{2}', name), name)

        with open(os.path.join(out, name), encoding='utf-8') as checklist_file:
            checklist = json.load(checklist_file)
        rules = [rule for stig in checklist['stigs'] for rule in stig['rules']]
        # 64 rules = the IOS XE checklist. The script passes no --checklist, so
        # this asserts it inherits the audit's IOS XE default - the whole point
        # of removing the AUDIT_CHECKLIST setting.
        check('audited against the IOS XE checklist by default', len(rules) == 64, len(rules))
        check('checklist carries verdicts',
              any(rule['status'] == 'not_a_finding' for rule in rules))
        check('dialog carries the summary line',
              any('out of' in m for _, m in fake.Dialog.messages), fake.Dialog.messages)

        # The asset block: what a reviewer would otherwise re-derive per switch.
        target = checklist['target_data']
        check('host name from the switch', target['host_name'] == 'TESTSW01', target['host_name'])
        check('IP address from the management SVI', target['ip_address'] == '192.0.2.5',
              target['ip_address'])
        check('MAC address from `show version`', target['mac_address'] == '00:1A:2B:3C:4D:5E',
              target['mac_address'])
        check('FQDN as <hostname>.<domain name>', target['fqdn'] == 'TESTSW01.example.test',
              target['fqdn'])


def test_interface_templates_are_collected(tmpdir):
    """A capture is only as complete as the commands that were sent, and on an
    IOS XE switch that templates its user ports the fixed six are not all of
    them: the port's own block says `source template <name>` and nothing else.
    Collected here or the audit never sees that configuration - and since it
    refuses a capture that sources a template it does not carry, a collector
    that skipped this would produce files that cannot be audited at all."""
    print('\ntemplates the config sources are collected in a second pass')
    templated = OUTPUTS['show running-config'].replace(
        ' description user port\n', ' description user port\n source template USER_PORT\n')
    template_command = capture_l2s.template_command('USER_PORT')
    outputs = {**OUTPUTS, 'show running-config': templated,
               template_command: 'Template Name : USER_PORT\n switchport mode access'}

    out = os.path.join(tmpdir, 'templated')
    os.makedirs(out, exist_ok=True)
    capture_l2s.OPEN_OUTPUT_FOLDER = False
    fake = run_script(path=out, outputs=outputs)
    check('the template command is sent, after the fixed ones',
          fake.Screen.sent[1:] == list(capture_l2s.COMMANDS) + [template_command],
          fake.Screen.sent[1:])
    check('and the run still produces a checklist',
          any(name.endswith('.cklb') for name in os.listdir(out)), os.listdir(out))

    # And nothing extra on a switch that uses no templates - the fixture config
    # sources none, so test_full_run's exact-command assertion still holds.
    plain_out = os.path.join(tmpdir, 'plain')
    os.makedirs(plain_out, exist_ok=True)
    plain = run_script(path=plain_out)
    check('a switch with no templates is asked nothing extra',
          plain.Screen.sent[1:] == list(capture_l2s.COMMANDS), plain.Screen.sent[1:])


def test_refusals(tmpdir):
    print('\nthe script refuses rather than writing a bad capture')

    def wrote_nothing(name, **kwargs):
        out = os.path.join(tmpdir, name)
        os.makedirs(out, exist_ok=True)
        fake = run_script(path=out, **kwargs)
        titles = ' '.join(t for t, _ in fake.Dialog.messages).lower()
        return (not os.listdir(out)), titles

    ok, titles = wrote_nothing('usermode', prompt='TESTSW01>')
    check('user EXEC mode refused', ok and 'enable' in titles, titles)

    ok, titles = wrote_nothing('disconnected', connected=False)
    check('disconnected session refused', ok and 'connected' in titles, titles)

    ok, titles = wrote_nothing('paged', paginate='show vlan brief')
    check('pager output refused', ok and 'truncated' in titles, titles)

    ok, titles = wrote_nothing('empty', empty='show vtp password')
    check('empty command output refused', ok and 'empty' in titles, titles)

    # The prompt character is not proof of a Cisco switch: root's shell prompt
    # ends in '#' too, so the enable-mode check passes on a Linux box. A walker
    # driving saved sessions will meet a jump host eventually, and bash answers
    # every command with an error - nothing empty, nothing truncated, so every
    # other guard here waves it through.
    ok, titles = wrote_nothing('bash', outputs={
        command: 'bash: {0}: command not found'.format(command.split()[0])
        for command in capture_l2s.COMMANDS})
    check('a bash session with a root # prompt is refused',
          ok and 'cisco' in titles, titles)

    # ...but not for the one command whose empty output is the answer. A switch
    # with no SNMPv3 users prints nothing, and that is the V-220604/605 finding
    # itself - abandoning the capture there would throw away the whole
    # collection over the very thing it was sent to find.
    out = os.path.join(tmpdir, 'noSnmpUsers')
    os.makedirs(out, exist_ok=True)
    fake = run_script(path=out, empty='show snmp user')
    titles = ' '.join(t for t, _ in fake.Dialog.messages).lower()
    written = [name for name in os.listdir(out) if name.endswith('.cklb')]
    check('empty `show snmp user` still produces a checklist',
          written and 'empty' not in titles, titles or os.listdir(out))
    if written:
        with open(os.path.join(out, written[0]), encoding='utf-8') as checklist_file:
            rules = {rule['group_id']: rule for stig in json.load(checklist_file)['stigs']
                     for rule in stig['rules']}
        # V-220604/605 (IOS XE: V-220552/553) are the rules empty output is the
        # answer to, and 'open' is the answer.
        check('and the SNMPv3 rules are answered from it, not skipped',
              rules['V-220552']['status'] == 'open', rules['V-220552']['status'])

    ok, titles = wrote_nothing('timeout', timeout_on='show running-config')
    check('read timeout refused', ok and 'failed' in titles, titles)

    before = set(os.listdir(tmpdir))
    fake = FakeCRT(path='')
    capture_l2s.crt = fake
    try:
        capture_l2s.main()
    finally:
        capture_l2s.crt = None
    check('cancelling the save dialog writes nothing', set(os.listdir(tmpdir)) == before)


if __name__ == '__main__':
    test_constants_match_capture_module()
    test_render_round_trips()
    test_strip_echo()
    with tempfile.TemporaryDirectory() as tmpdir:
        test_full_run(tmpdir)
        test_interface_templates_are_collected(tmpdir)
        test_refusals(tmpdir)
    print('\n' + ('ALL CHECKS PASSED' if not failures
                  else f'{len(failures)} FAILED: {", ".join(failures)}'))
    sys.exit(1 if failures else 0)
