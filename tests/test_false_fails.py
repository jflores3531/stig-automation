#!/usr/bin/env python
"""Shapes a compliant switch takes that the audit used to call findings.

Run directly: `python3 tests/test_false_fails.py`. No framework, no device.
Driven through the CLI, like the other audit suites: l2_stig_audit.py parses
argv at import, so a report is the only way to read its verdicts.

Both were found by reading a real report against the switch that produced it,
and both were the audit being wrong about a device that is doing the right
thing - the direction that costs an engineer a morning proving a finding is not
real, and the direction that eventually gets a tool ignored:

  * V-220650 (VTP): `show vtp password` has three wordings, and the one the
    work fleet answers with - "VTP Password is configured", set but not
    disclosed - matched neither the "VTP Password: <value>" form nor the "not
    set" form, so it fell through to "unexpected output" and reported FAIL on a
    switch with a VTP password.

  * V-220523 (management ACL): the rule was read as `permit ip <source> any`
    only. An ACL written to let the management network reach SSH and nothing
    else says `permit tcp <source> <wildcard> any eq 22 log` - narrower than
    what DISA's own fix text builds - and was read as an ACL with no permit
    entries at all.

The subnet these ACLs are written against is passed to the audit with
--management-subnet rather than read from inventory.yaml, so the suite pins
the audit's behaviour rather than whatever the local inventory happens to say
- including a placeholder like x.x.x.0/24, which is what the example ships so
that no real addressing is committed. RFC 5737 documentation space here, same
as fixtures.py.
"""

import os
import subprocess
import sys
import tempfile

PROJECT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import capture
import fixtures

failures = []


def check(name, condition, detail=''):
    print(f'  {"ok  " if condition else "FAIL"} {name}')
    if not condition:
        if detail:
            print(f'       {detail}')
        failures.append(name)


MANAGEMENT = '192.0.2.0/24'      # RFC 5737 documentation space, passed in per run
NETWORK = '192.0.2.0'
INSIDE_HOST = '192.0.2.25'
OUTSIDE = '203.0.113.0'          # a different documentation range - never inside MANAGEMENT


def report_for(tmpdir, name, running_config=None, vtp_password=None):
    outputs = dict(fixtures.OUTPUTS)
    if running_config is not None:
        outputs['show running-config'] = running_config
    if vtp_password is not None:
        outputs['show vtp password'] = vtp_password
    path = capture.write(os.path.join(tmpdir, name + '.capture'), outputs)
    result = subprocess.run(
        [sys.executable, os.path.join(PROJECT, 'l2_stig_audit.py'), 'TESTSW01',
         '--from-capture', path, '--non-user-vlans', '999,1000',
         '--management-subnet', MANAGEMENT],
        capture_output=True, text=True, cwd=PROJECT, timeout=120)
    return result.stdout + result.stderr


def verdict(report, rule_id):
    """The status line and its reason for one rule, as one string."""
    lines = report.splitlines()
    for i, line in enumerate(lines):
        if rule_id in line:
            return ' | '.join(part.strip() for part in lines[i:i + 2])
    return f'{rule_id} not in report'


def config_with_acl(acl_lines):
    """The fixture config with a vty management ACL spliced in."""
    body = '\n'.join(' ' + line for line in acl_lines)
    return fixtures.RUNNING_CONFIG.replace(
        'line vty 0 4\n exec-timeout 5 0',
        f'ip access-list extended MGMT-VTY\n{body}\n!\n'
        'line vty 0 4\n access-class MGMT-VTY in\n exec-timeout 5 0')


def test_vtp_wordings(tmpdir):
    print('`show vtp password` says one of three things')
    configured = report_for(tmpdir, 'vtpset', vtp_password='VTP Password is configured')
    check('"is configured" is a password, so the rule passes',
          'PASS' in verdict(configured, 'V-220650'), verdict(configured, 'V-220650'))

    not_configured = report_for(tmpdir, 'vtpunset',
                                vtp_password='The VTP password is not configured.')
    check('"is not configured" is still a finding',
          'FAIL' in verdict(not_configured, 'V-220650'), verdict(not_configured, 'V-220650'))

    with_value = report_for(tmpdir, 'vtpvalue', vtp_password='VTP Password: Sup3rSecret!')
    line = verdict(with_value, 'V-220650')
    check('a disclosed password passes', 'PASS' in line, line)
    check('and is reported by length, never printed',
          'Sup3rSecret!' not in with_value and '12 characters' in line, line)


def test_management_acl_shapes(tmpdir):
    print('\nthe management ACL is about its sources, not its protocol')
    ssh_only = report_for(tmpdir, 'acltcp', running_config=config_with_acl([
        f'permit tcp {NETWORK} 0.0.0.255 any eq 22 log',
        'deny ip any any log-input',
    ]))
    check('an ACL narrower than the fix text passes',
          'PASS' in verdict(ssh_only, 'V-220523'), verdict(ssh_only, 'V-220523'))

    host = report_for(tmpdir, 'aclhost', running_config=config_with_acl([
        f'permit tcp host {INSIDE_HOST} any eq 22 log',
        'deny ip any any log-input',
    ]))
    check('so does a single management host', 'PASS' in verdict(host, 'V-220523'),
          verdict(host, 'V-220523'))

    outside = report_for(tmpdir, 'acloutside', running_config=config_with_acl([
        f'permit tcp {NETWORK} 0.0.0.255 any eq 22 log',
        f'permit tcp {OUTSIDE} 0.0.0.255 any eq 22 log',
        'deny ip any any log-input',
    ]))
    line = verdict(outside, 'V-220523')
    check('a source outside the management subnet is still a finding',
          'FAIL' in line and OUTSIDE in line, line)

    permit_any = report_for(tmpdir, 'aclany', running_config=config_with_acl([
        'permit tcp any any eq 22 log',
        'deny ip any any log-input',
    ]))
    check('and so is permitting any source', 'FAIL' in verdict(permit_any, 'V-220523'),
          verdict(permit_any, 'V-220523'))


def test_standard_acl_with_logging(tmpdir):
    """The IOS XE book's own fix text for V-220523 builds a standard ACL, whose
    entries carry no protocol and no destination - and often a trailing `log`,
    which is a logging keyword rather than part of the source."""
    print('\na standard ACL is read as a standard ACL, log keyword and all')
    acl = ['ip access-list standard MGMT-VTY',
           f' permit {NETWORK} 0.0.0.255 log',
           ' deny any log',
           '!',
           'line vty 0 4',
           ' access-class MGMT-VTY in',
           ' exec-timeout 5 0']
    logged = report_for(tmpdir, 'aclstd', running_config=fixtures.RUNNING_CONFIG.replace(
        'line vty 0 4\n exec-timeout 5 0', '\n'.join(acl)))
    check('an in-subnet permit with a log keyword passes',
          'PASS' in verdict(logged, 'V-220523'), verdict(logged, 'V-220523'))


def test_unreadable_source_is_not_reported_as_out_of_subnet(tmpdir):
    print('\na source this cannot resolve is said to be unresolved, not out of subnet')
    grouped = report_for(tmpdir, 'aclgroup', running_config=config_with_acl([
        'permit tcp object-group MGMT-HOSTS any eq 22 log',
        'deny ip any any log-input',
    ]))
    line = verdict(grouped, 'V-220523')
    check('the object-group is not claimed to be outside the subnet',
          'outside' not in line, line)
    check('the report says it needs reading by hand',
          'cannot resolve' in line and 'object-group' in line, line)


if __name__ == '__main__':
    with tempfile.TemporaryDirectory() as tmpdir:
        test_vtp_wordings(tmpdir)
        test_management_acl_shapes(tmpdir)
        test_standard_acl_with_logging(tmpdir)
        test_unreadable_source_is_not_reported_as_out_of_subnet(tmpdir)
    print('\n' + ('ALL CHECKS PASSED' if not failures
                  else f'{len(failures)} FAILED: {", ".join(failures)}'))
    sys.exit(1 if failures else 0)
