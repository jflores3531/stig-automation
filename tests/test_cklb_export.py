#!/usr/bin/env python
"""`--to-cklb`: the report, as a file STIG Viewer 3 opens.

Run directly: `python3 tests/test_cklb_export.py`. No framework, no device.

Retyping 64 verdicts into STIG Viewer by hand is where this whole exercise
loses its accuracy, so the audit writes them itself. That makes the status
mapping load-bearing in a way a printed report never was: a wrong entry in
`CKLB_STATUS` is a compliance claim in a signed artifact rather than a line
someone misreads. The mapping is asserted here rule by rule against the report
the same run printed, and `NOT AUTOMATED -> not_reviewed` is asserted on its
own, because that is the one whose failure mode is silent - "nothing looked at
this" becoming "a reviewer confirmed it complies".

The other half is what a second run does. A checklist is a statement about what
one capture said, so the new capture wins outright: status, finding_details and
comments are all re-derived, and the box a verdict does not use is cleared
rather than left holding the previous run's sentence. Nothing is read back out
of the file being replaced at all, so an export is the blank checklist plus one
capture's findings and nothing else.

That means nothing typed into STIG Viewer survives the next run over the same
path - a Comments answer on a not_reviewed rule, a severity override and its
justification, all of it. It is the intended trade, and it is asserted below
rather than left to be discovered.
"""

import json
import os
import re
import subprocess
import sys
import tempfile

PROJECT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT)
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


def run_audit(tmpdir, capture_path, *extra):
    result = subprocess.run(
        [sys.executable, os.path.join(PROJECT, 'l2_stig_audit.py'), 'TESTSW01',
         '--from-capture', capture_path, '--non-user-vlans', '1,10,999,1000', *extra],
        capture_output=True, text=True, cwd=PROJECT, timeout=120)
    return result


def reported_statuses(report):
    """{group_id: status} as the report printed them."""
    return {group_id: status.strip() for status, group_id in
            re.findall(r'\]\s+(PASS|FAIL|NOT APPLICABLE|NOT AUTOMATED)\s+(V-\d+)', report)}


def rules_of(path):
    with open(path, encoding='utf-8') as checklist_file:
        checklist = json.load(checklist_file)
    return checklist, {rule['group_id']: rule
                       for stig in checklist['stigs'] for rule in stig['rules']}


def test_export(tmpdir, capture_path):
    print('the exported checklist says what the report said')
    out = os.path.join(tmpdir, 'TESTSW01.cklb')
    result = run_audit(tmpdir, capture_path, '--to-cklb', out)
    check('the audit exits cleanly', result.returncode == 0, result.stderr[-500:])
    check('and says where it wrote the checklist',
          out in result.stdout and 'STIG Viewer 3' in result.stdout,
          result.stdout.splitlines()[-1] if result.stdout else '')
    check('the file exists', os.path.exists(out))
    if not os.path.exists(out):
        return None

    checklist, rules = rules_of(out)
    printed = reported_statuses(result.stdout)
    check('every rule in the checklist got a verdict',
          len(printed) == len(rules) and len(rules) == 64, f'{len(printed)} printed, {len(rules)} in file')

    wrong = [f'{group_id}: report {status} -> file {rules[group_id]["status"]}'
             for group_id, status in printed.items()
             if rules[group_id]['status'] != stig_common.CKLB_STATUS[status]]
    check('every status maps as CKLB_STATUS says', not wrong, wrong[:5])

    not_automated = [group_id for group_id, status in printed.items() if status == 'NOT AUTOMATED']
    check('there is a NOT AUTOMATED rule to test the dangerous mapping on', not_automated)
    check('NOT AUTOMATED is not_reviewed, never not_a_finding',
          all(rules[group_id]['status'] == 'not_reviewed' for group_id in not_automated),
          [rules[g]['status'] for g in not_automated])
    check('and it still carries what the audit did determine, so the reviewer starts somewhere',
          all(rules[group_id]['comments'].strip() for group_id in not_automated),
          [rules[g]['comments'] for g in not_automated[:1]])

    # Which box the audit's note lands in follows the verdict: a finding is
    # evidenced in Finding Details, a pass or a not-applicable is justified in
    # Comments, where a reviewer would otherwise have typed the justification
    # themselves. V-220567 is NOT APPLICABLE on this fixture; V-220604 is a
    # FAIL (no SNMPv3 privacy) - one of each.
    na = rules['V-220567']
    check('a NOT APPLICABLE rule is justified in Comments',
          'Not Applicable' in na['comments'], na['comments'])
    check('and leaves Finding Details empty, since there is nothing to evidence',
          not na['finding_details'].strip(), na['finding_details'])
    check('the Comments justification still says where the evidence came from',
          'capture' in na['comments'] and 'x.capture' in na['comments'], na['comments'])

    failing = [group_id for group_id, status in printed.items() if status == 'FAIL']
    check('there is a FAIL to test the other direction on', failing)
    if failing:
        finding = rules[failing[0]]
        check('a finding is evidenced in Finding Details, not Comments',
              finding['finding_details'].strip() and 'Reported FAIL' in finding['finding_details'],
              finding['finding_details'])
        check('and its Comments box is left empty',
              not finding['comments'].strip(), finding['comments'])

    passing = [group_id for group_id, status in printed.items() if status == 'PASS']
    check('a PASS is justified in Comments too',
          passing and all(rules[g]['comments'].strip()
                          and not rules[g]['finding_details'].strip() for g in passing),
          [(g, rules[g]['finding_details'], rules[g]['comments'][:60]) for g in passing[:2]])

    check('the target is named', checklist['target_data']['host_name'] == 'TESTSW01',
          checklist['target_data'])
    return out


def test_rerun_overwrites_what_was_there(tmpdir, capture_path, out):
    """A checklist is a statement about what one capture said, so the new
    capture wins outright and nothing is read back out of the file being
    replaced - not the two text boxes, not a severity override. An export is
    the blank checklist plus this capture's findings, and nothing else."""
    print('\na second run re-derives everything from the new capture')
    checklist, rules = rules_of(out)
    typed = 'Confirmed with the backup admins 2026-09-06: SCP to the config server, weekly.'
    override = {'severity': {'severity': 'low', 'justification': 'compensating control'}}
    for stig in checklist['stigs']:
        for rule in stig['rules']:
            if rule['group_id'] == 'V-220566':      # NOT AUTOMATED
                rule['comments'] = typed
                rule['overrides'] = override
            if rule['group_id'] == 'V-220651':      # PASS, edited by hand
                rule['status'] = 'open'
                rule['comments'] = 'Reviewed by hand.'
                rule['finding_details'] = 'Left over from an earlier run.'
    with open(out, 'w', encoding='utf-8') as checklist_file:
        json.dump(checklist, checklist_file, indent=2)

    result = run_audit(tmpdir, capture_path, '--to-cklb', out)
    check('the second run exits cleanly', result.returncode == 0, result.stderr[-500:])

    _, rules = rules_of(out)
    unreviewed = rules['V-220566']['comments']
    check('a comment typed into STIG Viewer is replaced, not merged',
          typed not in unreviewed and 'Reported NOT AUTOMATED' in unreviewed, unreviewed)
    check('and it is the new run that wrote it, only once',
          unreviewed.count('Reported') == 1, unreviewed)

    passing = rules['V-220651']
    check('a hand-edited comment is replaced too',
          'Reviewed by hand.' not in passing['comments'], passing['comments'])
    check('the status is re-derived, not inherited',
          passing['status'] == 'not_a_finding', passing['status'])
    check('and the box this verdict does not use is cleared',
          not passing['finding_details'].strip(), passing['finding_details'])

    # Including the fields the audit never writes to. There is no exception:
    # an export is the blank checklist plus this capture, so a severity
    # override set in STIG Viewer goes the same way as a typed comment.
    check('a severity override does not survive either',
          rules['V-220566']['overrides'] == {}, rules['V-220566']['overrides'])
    check('and the run claims to keep nothing',
          'keeping' not in result.stdout,
          [l for l in result.stdout.splitlines() if 'keeping' in l])

    # The whole property in one line, and the one worth keeping if the checks
    # above ever get in the way: re-running over a file somebody has marked up
    # every way STIG Viewer allows produces the same bytes as exporting the
    # same capture to a path that never existed. Nothing carries over because
    # nothing is read.
    fresh = os.path.join(tmpdir, 'never-existed.cklb')
    run_audit(tmpdir, capture_path, '--to-cklb', fresh)
    with open(out, encoding='utf-8') as a, open(fresh, encoding='utf-8') as b:
        check('a re-run over an annotated file is byte-for-byte a fresh export',
              a.read() == b.read())


def test_refuses_the_template(tmpdir, capture_path):
    print('\nthe blank checklist every audit reads is not a place to write results')
    template = os.path.join(PROJECT, 'checklists', 'IOS-XE Checklist.cklb')
    before = open(template, 'rb').read()
    result = run_audit(tmpdir, capture_path, '--to-cklb', template)
    check('the run refuses', result.returncode != 0, result.stdout[-300:])
    check('and says why', 'Refusing to write over the blank checklist' in result.stdout,
          result.stdout[-300:])
    check('the template is untouched', open(template, 'rb').read() == before)
    check('and the report was still printed in full',
          'out of 64 rules' in result.stdout)


def test_no_flag_writes_nothing(tmpdir, capture_path):
    print('\nno flag, no file')
    before = set(os.listdir(tmpdir))
    result = run_audit(tmpdir, capture_path)
    check('the audit still runs', result.returncode == 0, result.stderr[-300:])
    check('and writes no checklist', set(os.listdir(tmpdir)) == before,
          sorted(set(os.listdir(tmpdir)) - before))


if __name__ == '__main__':
    with tempfile.TemporaryDirectory() as tmp:
        path = capture.write(os.path.join(tmp, 'x.capture'), fixtures.OUTPUTS)
        exported = test_export(tmp, path)
        if exported:
            test_rerun_overwrites_what_was_there(tmp, path, exported)
        test_refuses_the_template(tmp, path)
        test_no_flag_writes_nothing(tmp, path)
    print('\n' + ('ALL CHECKS PASSED' if not failures
                  else f'{len(failures)} FAILED: {", ".join(failures)}'))
    sys.exit(1 if failures else 0)
