#!/usr/bin/env python
"""Every rule's report and checklist entry names what was read to decide it.

Run it directly: `python3 tests/test_inspection_commands.py`.

This is evidence about evidence, and it fails differently from the rest of the
project. A wrong verdict can be caught by looking harder at the switch. A rule
whose checklist says `Inspected with: show snmp user` when nothing of the sort
was run cannot be - the claim is about the audit itself, it is signed, and there
is nothing left to compare it against.

So two things are pinned:

  * every command any rule claims is one the collector actually runs. A map
    naming a command that is not in the capture is the failure above, made by
    a typo.
  * a rule with no check claims nothing. NOT AUTOMATED means nothing looked at
    it, and "Inspected with: show running-config" under that verdict would be
    a checklist saying a rule was examined when it was skipped.
"""

import os
import re
import subprocess
import sys
import tempfile

PROJECT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(PROJECT, 'scripts'))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import capture
import fixtures
import stig_common

failures = []


def check(name, condition, detail=''):
    print(f'  {"ok  " if condition else "FAIL"} {name}')
    if not condition:
        if detail:
            print(f'       {detail}')
        failures.append(name)


def audit_source():
    """l2_stig_audit.py's head, up to where it starts parsing argv."""
    path = os.path.join(PROJECT, 'scripts', 'l2_stig_audit.py')
    return open(path, encoding='utf-8').read()


def report(tmpdir, name, outputs=None, extra_args=()):
    path = capture.write(os.path.join(tmpdir, name + '.capture'),
                         outputs or dict(fixtures.OUTPUTS))
    result = subprocess.run(
        [sys.executable, os.path.join(PROJECT, 'scripts', 'l2_stig_audit.py'), 'TESTSW01',
         '--from-capture', path, '--non-user-vlans', '999,1000',
         '--management-subnet', '192.0.2.0/24', *extra_args],
        capture_output=True, text=True, cwd=PROJECT, timeout=180)
    return result.stdout + result.stderr


def blocks(report_text):
    """{rule id: [its lines]} for every rule the report answered.

    The rule id is matched, not counted off by position: `[HIGH  ]` splits into
    two tokens where `[MEDIUM]` splits into one, so a positional read silently
    parsed only the medium-severity rules and reported everything else as
    missing."""
    found, current = {}, None
    for line in report_text.splitlines():
        if line.startswith('['):
            m = re.search(r'\b(V-\d+)\b', line)
            current = m.group(1) if m else None
            if current:
                found[current] = [line]
        elif current and line.startswith('    '):
            found[current].append(line.strip())
        elif not line.strip():
            current = None
    return found


def test_no_rule_claims_a_command_the_collector_does_not_run():
    """A map naming an uncollected command is the one failure mode here that a
    reader cannot detect: the checklist reads perfectly and is wrong."""
    print('every command a rule claims is one the audit actually runs')
    source = audit_source()
    start = source.index('RULE_COMMANDS = {')
    end = source.index('}', source.index("'V-220608'", start)) + 1
    namespace = {}
    exec(compile(source[start:end], 'RULE_COMMANDS', 'exec'), namespace)
    rule_commands = namespace['RULE_COMMANDS']

    collected = set(capture.AUDIT_COMMANDS_L2S) | set(capture.OPTIONAL_COMMANDS_L2S)
    claimed = {command for commands in rule_commands.values() for command in commands}
    check('the map is not empty', bool(claimed), rule_commands)
    unrunnable = sorted(claimed - collected)
    check('no rule names a command outside the collected set', not unrunnable, unrunnable)
    check('and `show running-config` is among the collected ones',
          'show running-config' in collected)


def test_the_report_says_what_each_rule_was_read_from(tmpdir):
    print('\nthe report names the commands under every answered rule')
    text = report(tmpdir, 'plain')
    answered = blocks(text)
    check('the report answered a good number of rules', len(answered) > 40, len(answered))

    inspected = {rule: [line for line in lines if line.startswith('Inspected with:')]
                 for rule, lines in answered.items()}
    automated = [rule for rule, lines in answered.items()
                 if 'NOT AUTOMATED' not in lines[0]]
    missing = [rule for rule in automated if not inspected[rule]]
    check('every rule that was checked says what it was read from', not missing, missing)

    # The point of the exercise: rules whose evidence is not running-config.
    for rule, expected in (('V-220552', 'show snmp user'),
                           ('V-220650', 'show vtp password'),
                           ('V-220569', 'show version'),
                           ('V-220555', 'show ip ssh'),
                           ('V-220655', 'show spanning-tree'),
                           ('V-220659', 'show vlan brief')):
        line = (inspected.get(rule) or [''])[0]
        check(f'{rule} names `{expected}`', expected in line, line or f'{rule} not in report')

    check('and an ordinary config rule names running-config',
          'show running-config' in (inspected.get('V-220518') or [''])[0],
          inspected.get('V-220518'))


def test_an_unautomated_rule_claims_nothing(tmpdir):
    """NOT AUTOMATED is two different situations and only one of them read
    anything.

    A rule with no entry in CHECKS was skipped: nothing ran, so a command line
    under it would be the checklist saying a rule was examined when it was not.
    A check that *returns* 'NOT AUTOMATED' - `_user_facing_trunk_check`, say -
    did read the config and decided the rule needs a human, and naming what it
    read is exactly as useful there as on a PASS.

    The two are told apart by the reason: run_stig_audit leaves it None when
    there was no check to produce one."""
    print('\na rule nothing checked claims no command; one that looked does')
    answered = blocks(report(tmpdir, 'unautomated'))
    unautomated = [rule for rule, lines in answered.items() if 'NOT AUTOMATED' in lines[0]]
    check('the run really did leave some rules unautomated', unautomated, unautomated)

    def claims(rule):
        return any(line.startswith('Inspected with:') for line in answered[rule][1:])

    def has_reason(rule):
        return any(not line.startswith('Inspected with:') for line in answered[rule][1:])

    skipped = [rule for rule in unautomated if not has_reason(rule)]
    looked = [rule for rule in unautomated if has_reason(rule)]
    check('no skipped rule names a command',
          not [rule for rule in skipped if claims(rule)],
          [rule for rule in skipped if claims(rule)])
    check('a check that looked and then deferred to a human still says what it read',
          looked and all(claims(rule) for rule in looked),
          [r for r in looked if not claims(r)] or 'no such rule in this run')

    # Every rule in this checklist happens to have a check, so the skipped case
    # above can be vacuous. Proven directly instead: an audit with no checks at
    # all must claim no commands at all, whatever map it was handed.
    import io as _io
    import contextlib
    session = capture.load(capture.write(
        os.path.join(tmpdir, 'nochecks.capture'), dict(fixtures.OUTPUTS)))
    buffer = _io.StringIO()
    with contextlib.redirect_stdout(buffer):
        stig_common.run_stig_audit(
            'TESTSW01', {}, os.path.join(PROJECT, 'checklists', 'IOS-XE Checklist.cklb'),
            {}, title='probe', username='u', password='p', session=session,
            rule_commands={'V-220518': ('show running-config',)})
    text = buffer.getvalue()
    check('an audit with no checks reports every rule NOT AUTOMATED',
          text.count('NOT AUTOMATED') > 40, text.count('NOT AUTOMATED'))
    check('and names no command anywhere, even one the map offered',
          'Inspected with' not in text,
          [line for line in text.splitlines() if 'Inspected with' in line][:3])


def test_the_line_reaches_the_exported_checklist(tmpdir):
    print('\nthe same line lands in the exported .cklb, in the box for that verdict')
    import json
    out = os.path.join(tmpdir, 'export')
    os.makedirs(out, exist_ok=True)
    report(tmpdir, 'export', extra_args=('--to-cklb', out))
    written = [os.path.join(out, n) for n in os.listdir(out) if n.endswith('.cklb')]
    check('a checklist was written', written, os.listdir(out))
    if not written:
        return
    checklist = json.load(open(written[0], encoding='utf-8'))
    rules = {r['group_id']: r for stig in checklist['stigs'] for r in stig['rules']}

    def box(rule_id):
        rule = rules[rule_id]
        return (rule.get('finding_details') or '') + (rule.get('comments') or '')

    check('a passing rule carries it in Comments',
          'Inspected with: `show snmp user`' in box('V-220552'), box('V-220552')[:160])
    check('a failing rule carries it in Finding Details, under the reason',
          'Inspected with: `show vtp password`' in box('V-220650')
          and box('V-220650').index('Inspected with') > 0, box('V-220650')[:200])
    check('an unautomated rule carries no such claim',
          not any('Inspected with' in box(rule_id) for rule_id, rule in rules.items()
                  if rule.get('status') == 'not_reviewed'
                  and not (rule.get('finding_details') or rule.get('comments'))))


def test_templates_are_named_on_every_rule_that_read_them(tmpdir):
    """When a config sources interface templates, every check reads the
    expanded config - so every rule really was decided partly from the
    template's own body, and the command that produced it belongs beside the
    verdict."""
    print('\nwhere templates were expanded, the rules say which ones they read')
    outputs = dict(fixtures.OUTPUTS)
    config = outputs['show running-config']
    templated = config.replace('interface GigabitEthernet1/0/1\n',
                               'interface GigabitEthernet1/0/1\n source template USER-PORT\n', 1)
    assert 'source template USER-PORT' in templated, 'fixture interface name changed'
    outputs['show running-config'] = templated
    outputs['show template interface source user USER-PORT'] = (
        'Template Name  : USER-PORT\n----------\n switchport mode access\nend\n')

    answered = blocks(report(tmpdir, 'templated', outputs=outputs))
    lines = [line for rule, block in answered.items() for line in block
             if line.startswith('Inspected with:')]
    check('the report still answered its rules', len(answered) > 40, len(answered))
    check('and names the template command it read',
          all('show template interface source user USER-PORT' in line for line in lines),
          lines[:3])


if __name__ == '__main__':
    test_no_rule_claims_a_command_the_collector_does_not_run()
    with tempfile.TemporaryDirectory() as tmpdir:
        test_the_report_says_what_each_rule_was_read_from(tmpdir)
        test_an_unautomated_rule_claims_nothing(tmpdir)
        test_the_line_reaches_the_exported_checklist(tmpdir)
        test_templates_are_named_on_every_rule_that_read_them(tmpdir)
    print('\n' + ('ALL CHECKS PASSED' if not failures
                  else f'{len(failures)} FAILED: {", ".join(failures)}'))
    sys.exit(1 if failures else 0)
