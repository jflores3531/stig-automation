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

import os
import sys
import tempfile

PROJECT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(PROJECT, 'securecrt'))

import capture
import capture_l2s
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
    check('command list identical',
          tuple(capture_l2s.COMMANDS) == tuple(capture.AUDIT_COMMANDS_L2S),
          f'{capture_l2s.COMMANDS} vs {capture.AUDIT_COMMANDS_L2S}')
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


def test_render_round_trips():
    print('\nrendered text parses back through capture.py')
    parsed = capture.parse(capture_l2s.render(OUTPUTS))
    check('all five sections recovered', set(parsed) == set(OUTPUTS), sorted(parsed))
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
    print('\nfull run against a stubbed SecureCRT (audit auto-runs, report opens suppressed)')
    path = os.path.join(tmpdir, 'run.capture')
    capture_l2s.OPEN_REPORT = False
    fake = run_script(path=path)
    check('paging disabled first', fake.Screen.sent[0] == 'terminal length 0',
          fake.Screen.sent[:2])
    check('all five commands sent',
          fake.Screen.sent[1:] == list(capture_l2s.COMMANDS), fake.Screen.sent[1:])
    check('synchronous mode restored', fake.Screen.Synchronous is False)
    check('capture file written', os.path.exists(path))
    check('reported success', any('complete' in t.lower() for t, _ in fake.Dialog.messages),
          fake.Dialog.messages)

    # The script now runs the real audit itself and writes the report next to
    # the capture - the linear flow the work machine gets.
    report = path[:-len('.capture')] + '_report.txt'
    check('audit auto-ran, report written next to the capture', os.path.exists(report))
    check('report is a clean .txt, not .capture_report.txt',
          not os.path.exists(path + '_report.txt'))
    if os.path.exists(report):
        text = open(report, encoding='utf-8').read()
        # 64 rules = the IOS XE checklist. The script passes no --checklist,
        # so this asserts it inherits the audit's IOS XE default - the whole
        # point of removing the AUDIT_CHECKLIST setting.
        check('audited against the IOS XE checklist by default',
              '64 rules' in text, [l for l in text.splitlines() if 'rules' in l][:2])
        check('report carries verdicts', 'passed,' in text)
        check('dialog carries the summary line',
              any('out of' in m for _, m in fake.Dialog.messages), fake.Dialog.messages)

    if os.path.exists(path):
        session = capture.load(path)
        check('capture.load accepts it', session is not None)
        for command, original in OUTPUTS.items():
            check(f'{command!r} survives the whole path',
                  session.send_command(command) == original.strip('\n'))


def test_interface_templates_are_collected(tmpdir):
    """A capture is only as complete as the commands that were sent, and on an
    IOS XE switch that templates its user ports the fixed five are not all of
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

    path = os.path.join(tmpdir, 'templated.capture')
    capture_l2s.OPEN_REPORT = False
    fake = run_script(path=path, outputs=outputs)
    check('the template command is sent, after the fixed five',
          fake.Screen.sent[1:] == list(capture_l2s.COMMANDS) + [template_command],
          fake.Screen.sent[1:])
    if os.path.exists(path):
        session = capture.load_l2s(path)
        check('the two-pass loader accepts the capture',
              'switchport mode access' in session.send_command(template_command))

    # And nothing extra on a switch that uses no templates - the fixture config
    # sources none, so test_full_run's exact-command assertion still holds.
    plain = run_script(path=os.path.join(tmpdir, 'plain.capture'))
    check('a switch with no templates is asked nothing extra',
          plain.Screen.sent[1:] == list(capture_l2s.COMMANDS), plain.Screen.sent[1:])


def test_refusals(tmpdir):
    print('\nthe script refuses rather than writing a bad capture')

    def wrote_nothing(name, **kwargs):
        path = os.path.join(tmpdir, name + '.capture')
        fake = run_script(path=path, **kwargs)
        titles = ' '.join(t for t, _ in fake.Dialog.messages).lower()
        return (not os.path.exists(path)), titles

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
    path = os.path.join(tmpdir, 'noSnmpUsers.capture')
    fake = run_script(path=path, empty='show snmp user')
    titles = ' '.join(t for t, _ in fake.Dialog.messages).lower()
    check('empty `show snmp user` still writes the capture',
          os.path.exists(path) and 'empty' not in titles, titles)
    if os.path.exists(path):
        session = capture.load(path)
        check('and the audit loads it, serving empty snmp output',
              session.send_command('show snmp user') == '')

    ok, titles = wrote_nothing('timeout', timeout_on='show running-config')
    check('read timeout refused', ok and 'failed' in titles, titles)

    path = os.path.join(tmpdir, 'cancelled.capture')
    fake = FakeCRT(path='')
    capture_l2s.crt = fake
    try:
        capture_l2s.main()
    finally:
        capture_l2s.crt = None
    check('cancelling the save dialog writes nothing', not os.path.exists(path))


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
