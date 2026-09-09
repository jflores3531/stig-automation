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
import re
import subprocess
import sys
import tempfile

PROJECT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(PROJECT, 'scripts'))
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


def report_for(tmpdir, name, running_config=None, vtp_password=None, management=None,
               ip_ssh=None):
    outputs = dict(fixtures.OUTPUTS)
    if running_config is not None:
        outputs['show running-config'] = running_config
    if vtp_password is not None:
        outputs['show vtp password'] = vtp_password
    if ip_ssh is not None:
        outputs['show ip ssh'] = ip_ssh
    path = capture.write(os.path.join(tmpdir, name + '.capture'), outputs)
    result = subprocess.run(
        [sys.executable, os.path.join(PROJECT, 'scripts', 'l2_stig_audit.py'), 'TESTSW01',
         '--from-capture', path, '--non-user-vlans', '999,1000',
         '--management-subnet', management or MANAGEMENT],
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


SECOND_MANAGEMENT = '198.51.100.0/24'    # RFC 5737 too - a second admin range
SECOND_NETWORK = '198.51.100.0'


def test_management_network_of_several_prefixes(tmpdir):
    """A management network is not always one prefix. A site whose out-of-band
    addressing grew a second range, or that manages from a jump network as well
    as an admin VLAN, writes a permit for each - every one of them inside "the
    management network" as the site defines it - and a single CIDR could not
    say so, so the second permit was reported as a source outside it."""
    print('\nthe management network can be more than one prefix')
    two_ranges = config_with_acl([
        f'permit tcp {NETWORK} 0.0.0.255 any eq 22 log',
        f'permit tcp {SECOND_NETWORK} 0.0.0.255 any eq 22 log',
        'deny ip any any log-input',
    ])
    both = report_for(tmpdir, 'acltwo', running_config=two_ranges,
                      management=f'{MANAGEMENT},{SECOND_MANAGEMENT}')
    check('an ACL permitting each declared range passes',
          'PASS' in verdict(both, 'V-220523'), verdict(both, 'V-220523'))

    # The point of the check is that the ACL is compared against a management
    # network declared independently of it. Declaring only one range must still
    # fail the permit that leaves it, or the list is just a way of agreeing
    # with whatever the ACL already says.
    one = report_for(tmpdir, 'aclone', running_config=two_ranges)
    line = verdict(one, 'V-220523')
    check('and a range the inventory does not declare is still a finding',
          'FAIL' in line and SECOND_NETWORK in line, line)


def test_session_limit_by_reducing_vty_lines(tmpdir):
    """V-220518/570 gives three ways to limit concurrent management sessions,
    and DISA's Fix Text leads with the one this used to miss: leave vty 0-1
    answering SSH and give vty 2-4 `transport input none`. A switch hardened
    exactly as that Fix Text shows carries neither `session-limit` nor
    `ip http max-connections`, and was reported as having no limit at all.

    It matters most on a hardened switch, where `no ip http server` is pushed:
    a limit on a server that is not running is not the control, the vty lines
    are."""
    print('\ntaking vty lines out of service is a session limit, per DISA')
    reduced = fixtures.RUNNING_CONFIG.replace('ip http max-connections 2\n', '')
    reduced = reduced.replace(
        'line vty 0 4\n exec-timeout 5 0',
        'line vty 0 1\n exec-timeout 5 0\n transport input ssh\n!\n'
        'line vty 2 4\n transport input none\n!\nline vty 0 4\n exec-timeout 5 0')
    report = report_for(tmpdir, 'vtyreduced', running_config=reduced)
    line = verdict(report, 'V-220518')
    check('the switch is not reported as having no session limit',
          'PASS' in line, line)
    check('and the reason says how many lines were taken out of service',
          'transport input none' in line and '3 vty line(s) taken out of service' in line, line)
    check('and how many can still answer, which is the number that matters',
          '2 vty line(s) can still answer' in line, line)

    # Still a finding when nothing limits anything - the point is to recognise
    # a third shape, not to stop failing.
    none_at_all = reduced.replace(' transport input none\n', ' transport input ssh\n')
    none_at_all = re.sub(r'^\s*session-limit \d+\n', '', none_at_all, flags=re.M)
    line = verdict(report_for(tmpdir, 'nolimit', running_config=none_at_all), 'V-220518')
    check('a switch with no limit of any kind is still a finding', 'FAIL' in line, line)

    # The direction that matters more, because a false PASS on a compliance
    # tool is worse than a false FAIL. IOS XE ships `line vty 0 4` AND
    # `line vty 5 15`, so a switch hardened only on the first range answers on
    # eleven more - and a check that stops at "some lines were closed" calls
    # that a session limit. It cannot be failed outright: the rule's number is
    # organization-defined and 13 is a number. What it must not do is stay
    # silent about how many lines can still answer.
    with_high_range = reduced.replace(
        'line vty 2 4\n transport input none',
        'line vty 2 4\n transport input none\n!\nline vty 5 15\n transport input ssh')
    line = verdict(report_for(tmpdir, 'vty515', running_config=with_high_range), 'V-220518')
    check('lines left answering beyond vty 0-4 are counted, not overlooked',
          'can still answer' in line, line)
    check('and the count is the real one, not the five DISA\'s example shows',
          '13 vty line(s) can still answer' in line, line)
    check('with the reason pointing at the range that is easy to miss',
          'line vty 0 4' in line, line)


def test_a_wildcard_this_cannot_read_is_not_a_finding(tmpdir):
    """A non-contiguous wildcard - `0.0.255.0` - is a legal ACL mask that names
    no CIDR network, so there is no prefix to compare against the management
    one. Answering "outside the management network" there is a finding
    invented out of not being able to read the line, which is the direction
    that costs an engineer a morning proving it is not real."""
    print('\na wildcard this cannot read goes to a human, not into a finding')
    odd = report_for(tmpdir, 'aclodd', running_config=config_with_acl([
        f'permit tcp {NETWORK} 0.0.255.0 any eq 22 log',
        'deny ip any any log-input',
    ]))
    line = verdict(odd, 'V-220523')
    check('it is reported as needing review by hand',
          'review by hand' in line, line)
    check('and not as a source outside the management network',
          'outside' not in line, line)


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



def test_sshv2_is_read_from_show_ip_ssh_when_the_config_will_not_say(tmpdir):
    """V-220555/220556 print `ip ssh version 2` in their Check Content, and a
    Catalyst 9300 or 3850 never writes that line: SSHv1 is gone on those trains,
    so v2-only is not a non-default setting and running-config is silent about
    it. `show ip ssh` says `SSH Enabled - version 2.0`.

    Requiring the line failed both rules on a switch doing exactly what they
    ask - a false FAIL on the whole fleet, since these are 9300s."""
    print('\nSSHv2 is established from show ip ssh where the config will not say')
    without_line = fixtures.RUNNING_CONFIG.replace('ip ssh version 2\n', '')
    check('the fixture really has no `ip ssh version 2` left',
          'ip ssh version 2' not in without_line)

    report = report_for(tmpdir, 'ssh9300', running_config=without_line)
    for rule in ('V-220555', 'V-220556'):
        check(f'{rule} passes on the evidence the switch actually gives',
              'PASS' in verdict(report, rule), verdict(report, rule))
    check('and the report says which evidence it used',
          'show ip ssh' in verdict(report, 'V-220555'), verdict(report, 'V-220555'))

    # 1.99 is IOS reporting compatibility mode - the switch still answers
    # SSHv1. Reading it as v2 would be the false PASS that matters more than
    # the false FAIL this test exists for.
    compat = report_for(tmpdir, 'sshcompat', running_config=without_line,
                        ip_ssh='SSH Enabled - version 1.99\n')
    check('version 1.99 is not accepted as SSHv2',
          'FAIL' in verdict(compat, 'V-220555'), verdict(compat, 'V-220555'))
    check('and the reason says why',
          'compatibility' in verdict(compat, 'V-220555'), verdict(compat, 'V-220555'))

    off = report_for(tmpdir, 'sshoff', running_config=without_line,
                     ip_ssh='SSH Disabled - version 2.0\n')
    check('SSH Disabled is not accepted either',
          'FAIL' in verdict(off, 'V-220555'), verdict(off, 'V-220555'))

    # running-config is intent; `show ip ssh` is what the switch is running.
    # Where they disagree the running switch wins, or a stale line outvotes
    # live output saying SSHv1 is still answered.
    stale = report_for(tmpdir, 'sshstale', ip_ssh='SSH Enabled - version 1.99\n')
    check('the config line does not outvote live output that contradicts it',
          'FAIL' in verdict(stale, 'V-220555'), verdict(stale, 'V-220555'))

    # The config line still stands on its own, for switches that do write it.
    classic = report_for(tmpdir, 'sshclassic', ip_ssh='')
    check('a config carrying the line passes with no `show ip ssh` at all',
          'PASS' in verdict(classic, 'V-220555'), verdict(classic, 'V-220555'))

if __name__ == '__main__':
    with tempfile.TemporaryDirectory() as tmpdir:
        test_vtp_wordings(tmpdir)
        test_management_acl_shapes(tmpdir)
        test_management_network_of_several_prefixes(tmpdir)
        test_session_limit_by_reducing_vty_lines(tmpdir)
        test_a_wildcard_this_cannot_read_is_not_a_finding(tmpdir)
        test_standard_acl_with_logging(tmpdir)
        test_unreadable_source_is_not_reported_as_out_of_subnet(tmpdir)
        test_sshv2_is_read_from_show_ip_ssh_when_the_config_will_not_say(tmpdir)
    print('\n' + ('ALL CHECKS PASSED' if not failures
                  else f'{len(failures)} FAILED: {", ".join(failures)}'))
    sys.exit(1 if failures else 0)
