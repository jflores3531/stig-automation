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

The other half is what a second run does. A checklist that has been opened is
no longer only this tool's output: the audit owns `status` and
`finding_details` and re-derives both, the reviewer owns `comments`. A re-run
that wiped the reviewer's notes would take exactly the rules that needed a
human with it.
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
          all(rules[group_id]['finding_details'].strip() for group_id in not_automated))

    detail = rules['V-220567']['finding_details']
    check('finding_details carries the reason the report printed',
          'self-signed' in detail, detail)
    check('and where the evidence came from',
          'capture' in detail and 'x.capture' in detail, detail)

    check('the target is named', checklist['target_data']['host_name'] == 'TESTSW01',
          checklist['target_data'])
    return out


def test_rerun_keeps_reviewer_comments(tmpdir, capture_path, out):
    print('\na second run refreshes verdicts and keeps the reviewer\'s notes')
    checklist, rules = rules_of(out)
    note = 'Confirmed with the backup admins 2026-09-06: SCP to the config server, weekly.'
    for stig in checklist['stigs']:
        for rule in stig['rules']:
            if rule['group_id'] == 'V-220566':
                rule['comments'] = note
            if rule['group_id'] == 'V-220651':
                # A verdict a reviewer disagreed with and edited by hand. The
                # audit owns this field, so the re-run is expected to take it
                # back - the comment beside it is what must survive.
                rule['status'] = 'open'
                rule['comments'] = 'Reviewed by hand.'
    with open(out, 'w', encoding='utf-8') as checklist_file:
        json.dump(checklist, checklist_file, indent=2)

    result = run_audit(tmpdir, capture_path, '--to-cklb', out)
    check('the second run exits cleanly', result.returncode == 0, result.stderr[-500:])
    check('and says how many comments it kept',
          'keeping reviewer comments on 2 rule(s)' in result.stdout,
          result.stdout.splitlines()[-1] if result.stdout else '')

    _, rules = rules_of(out)
    check('the reviewer\'s comment survives', rules['V-220566']['comments'] == note,
          rules['V-220566']['comments'])
    check('so does one on a rule the audit answered itself',
          rules['V-220651']['comments'] == 'Reviewed by hand.', rules['V-220651']['comments'])
    check('but the status is re-derived, not inherited',
          rules['V-220651']['status'] == 'not_a_finding', rules['V-220651']['status'])


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
            test_rerun_keeps_reviewer_comments(tmp, path, exported)
        test_refuses_the_template(tmp, path)
        test_no_flag_writes_nothing(tmp, path)
    print('\n' + ('ALL CHECKS PASSED' if not failures
                  else f'{len(failures)} FAILED: {", ".join(failures)}'))
    sys.exit(1 if failures else 0)
