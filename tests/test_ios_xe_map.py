#!/usr/bin/env python
"""Verification for ios_xe_rule_map.py and l2_stig_audit.py --checklist ios-xe.

Run directly: `python3 tests/test_ios_xe_map.py`. No framework, no device.

The map claims that one predicate correctly answers two differently-numbered
STIG rules. That claim is only as good as the finding condition behind it, so
the central test re-derives the "... this is a finding" clause from both
checklists and fails any mapping whose two clauses have drifted apart. A wrong
mapping does not crash - it silently reports a confident verdict against the
wrong requirement, which is the failure this file exists to prevent.
"""

import difflib
import json
import os
import re
import subprocess
import sys
import tempfile

PROJECT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(PROJECT, 'scripts'))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import capture
import ios_xe_rule_map
from fixtures import OUTPUTS

failures = []


def check(name, condition, detail=''):
    print(f'  {"ok  " if condition else "FAIL"} {name}')
    if not condition:
        if detail:
            print(f'       {detail}')
        failures.append(name)


def load(name):
    with open(os.path.join(PROJECT, 'checklists', name), encoding='utf-8') as f:
        return {r['group_id']: r for stig in json.load(f)['stigs'] for r in stig['rules']}


def finding_condition(rule):
    """The 'If <condition>, this is a finding.' clause. Anchored on the last
    'If' rather than a sentence boundary because the config examples inside
    check_content carry no punctuation."""
    text = re.sub(r'\s+', ' ', rule.get('check_content') or '')
    low = text.lower()
    idx = low.rfind('this is a finding')
    if idx == -1:
        return ''
    starts = [m.start() for m in re.finditer(r'\bif\b', low[:idx])]
    start = starts[-1] if starts else max(0, idx - 160)
    return re.sub(r'\s+', ' ', text[start:idx + len('this is a finding')].lower()).strip()


XE = load('IOS-XE Checklist.cklb')
IOS = load('New Layer 2 switch Checklist.cklb')


def test_ids_are_real():
    print('every mapped ID exists in its checklist')
    bad_xe = sorted(set(ios_xe_rule_map.RULE_MAP) - set(XE))
    bad_ios = sorted(set(ios_xe_rule_map.RULE_MAP.values()) - set(IOS))
    check('all IOS XE keys exist in the IOS XE checklist', not bad_xe, bad_xe)
    check('all IOS values exist in the IOS checklist', not bad_ios, bad_ios)
    bad_excl = sorted(set(ios_xe_rule_map.EXCLUDED) - set(XE))
    check('all EXCLUDED ids exist in the IOS XE checklist', not bad_excl, bad_excl)


def test_no_double_mapping():
    print('\nno IOS rule answers two IOS XE rules')
    values = list(ios_xe_rule_map.RULE_MAP.values())
    dupes = sorted({v for v in values if values.count(v) > 1})
    check('IOS rule IDs are used at most once', not dupes, dupes)
    overlap = sorted(set(ios_xe_rule_map.EXCLUDED) & set(ios_xe_rule_map.RULE_MAP))
    check('EXCLUDED and RULE_MAP are disjoint', not overlap, overlap)


# Pairs whose finding conditions legitimately differ, each with the reason.
# The 0.90 gate below stays strict for everything else - an exception has to
# be argued here rather than by lowering the threshold, so a future bad
# mapping still fails loudly.
DOCUMENTED_EXCEPTIONS = {
    'V-220670': (
        "IOS V-220644's Check Content is a byte-identical copy of its own "
        'V-220643 (trunk pruning), including the finding sentence - the IOS book '
        'carries two differently-titled rules with one check text between them, '
        'and the IOS XE book fixes it. Both rules are about a management SVI on '
        'the default VLAN, which is what the shared predicate tests.'
    ),
}


def test_finding_conditions_agree():
    print('\nmapped pairs share their finding condition')
    worst, drifted = ('', 1.0), []
    for xe_id, ios_id in sorted(ios_xe_rule_map.RULE_MAP.items()):
        a, b = finding_condition(XE[xe_id]), finding_condition(IOS[ios_id])
        if not a or not b:
            drifted.append(f'{xe_id}->{ios_id} (no finding clause)')
            continue
        score = difflib.SequenceMatcher(None, a, b).ratio()
        if xe_id in DOCUMENTED_EXCEPTIONS:
            continue
        if score < worst[1]:
            worst = (f'{xe_id}->{ios_id}', score)
        if score < 0.90:
            drifted.append(f'{xe_id}->{ios_id} ({score:.2f})')
    check('no undocumented pair has drifted below 0.90', not drifted, drifted)
    print(f'       weakest accepted pair: {worst[0]} at {worst[1]:.2f}')

    # The exceptions must still be real mappings, and must still be exceptional -
    # if DISA ever fixes the IOS text, this stops being needed and should go.
    for xe_id, reason in DOCUMENTED_EXCEPTIONS.items():
        check(f'{xe_id} is actually mapped', xe_id in ios_xe_rule_map.RULE_MAP)
        if xe_id in ios_xe_rule_map.RULE_MAP:
            ios_id = ios_xe_rule_map.RULE_MAP[xe_id]
            score = difflib.SequenceMatcher(
                None, finding_condition(XE[xe_id]), finding_condition(IOS[ios_id])).ratio()
            check(f'{xe_id} still needs its exception (would fail the gate at {score:.2f})',
                  score < 0.90,
                  'conditions now agree - drop it from DOCUMENTED_EXCEPTIONS')
    check('V-220644 and V-220643 really do share IOS check text (the reason for the exception)',
          difflib.SequenceMatcher(None, finding_condition(IOS['V-220644']),
                                  finding_condition(IOS['V-220643'])).ratio() > 0.99)


def test_translate():
    print('\ntranslate() re-keys and drops correctly')
    checks = {ios_id: (lambda cfg, _i=ios_id: (True, _i))
              for ios_id in ios_xe_rule_map.RULE_MAP.values()}
    checks['V-220999'] = lambda cfg: (True, 'unmapped')
    out = ios_xe_rule_map.translate(checks)
    check('every mapped rule carries over', len(out) == len(ios_xe_rule_map.RULE_MAP))
    check('keys are IOS XE ids', set(out) <= set(XE))
    check('an IOS check with no IOS XE counterpart is dropped',
          all(key in ios_xe_rule_map.RULE_MAP for key in out))
    sample_xe = 'V-220656'
    check('predicate is preserved, not rebuilt',
          out[sample_xe]('')[1] == ios_xe_rule_map.RULE_MAP[sample_xe])
    check('excluded rules get no entry',
          not (set(ios_xe_rule_map.EXCLUDED) & set(out)))
    partial = ios_xe_rule_map.translate({'V-220630': checks['V-220630']})
    check('a missing IOS check simply yields no IOS XE entry', set(partial) == {'V-220656'})


def test_end_to_end(tmpdir):
    print('\nend-to-end: the IOS XE checklist, exercised as the DEFAULT (no flag)')
    path = capture.write(os.path.join(tmpdir, 'xe.capture'), OUTPUTS)
    result = subprocess.run(
        [sys.executable, os.path.join(PROJECT, 'scripts', 'l2_stig_audit.py'), 'TESTSW01',
         '--from-capture', path, '--non-user-vlans', '1,10,999,1000'],
        capture_output=True, text=True, cwd=PROJECT, timeout=120)
    check('script exits cleanly', result.returncode == 0, result.stderr[-1500:])
    check('audits the IOS XE checklist', '64 rules' in result.stdout,
          [l for l in result.stdout.splitlines() if 'rules' in l][:2])
    check('titled as IOS XE', 'IOS XE' in result.stdout)
    check('reports IOS XE rule ids', 'V-220656' in result.stdout)
    check('does not report IOS rule ids', 'V-220630' not in result.stdout)

    summary = [l for l in result.stdout.splitlines() if 'out of' in l]
    if summary:
        print(f'       {summary[0].strip()}')
    not_automated = int(re.search(r'(\d+) not automated', result.stdout).group(1))
    check('most rules are actually checked, not NOT AUTOMATED', not_automated <= 10,
          f'{not_automated} not automated')
    for excluded in ios_xe_rule_map.EXCLUDED:
        check(f'{excluded} reports NOT AUTOMATED as intended',
              re.search(rf'NOT AUTOMATED\s+{excluded}\b', result.stdout) is not None)

    # IOS XE-only checks: rules with no IOS counterpart to re-key, wired
    # through l2_stig_audit.IOS_XE_ONLY_CHECKS rather than the map.
    check('V-220554 gets a real verdict, not the IOS permanent finding',
          re.search(r'(PASS|FAIL)\s+V-220554\b', result.stdout) is not None
          and 'NOT AUTOMATED  V-220554' not in result.stdout)
    check('V-220567 gets a real verdict', 'NOT AUTOMATED  V-220567' not in result.stdout)

    print('\n  --checklist ios still audits the IOS checklist unchanged')
    baseline = subprocess.run(
        [sys.executable, os.path.join(PROJECT, 'scripts', 'l2_stig_audit.py'), 'TESTSW01',
         '--checklist', 'ios',
         '--from-capture', path, '--non-user-vlans', '1,10,999,1000'],
        capture_output=True, text=True, cwd=PROJECT, timeout=120)
    check('--checklist ios selects the IOS checklist', '65 rules' in baseline.stdout)
    check('IOS run reports IOS ids', 'V-220630' in baseline.stdout)


if __name__ == '__main__':
    coverage = len(ios_xe_rule_map.RULE_MAP)
    print(f'IOS XE rules: {len(XE)}   mapped: {coverage}   '
          f'deliberately excluded: {len(ios_xe_rule_map.EXCLUDED)}\n')
    test_ids_are_real()
    test_no_double_mapping()
    test_finding_conditions_agree()
    test_translate()
    with tempfile.TemporaryDirectory() as tmpdir:
        test_end_to_end(tmpdir)
    print('\n' + ('ALL CHECKS PASSED' if not failures
                  else f'{len(failures)} FAILED: {", ".join(failures)}'))
    sys.exit(1 if failures else 0)
