#!/usr/bin/env python
"""An interface's configuration is not always in the interface's block.

Run directly: `python3 tests/test_interface_templates.py`. No framework, no
device.

An IOS XE port can be configured from an interface template: running-config
shows `source template USER_PORT` and nothing else, while the access VLAN, the
switchport mode, PortFast, BPDU Guard and 802.1x live in the template. Every
per-port rule in l2_stig_audit.py reads the interface block, so on a fleet that
templates its user ports those rules were answering against an empty block -
four rules reporting a finding against a port that is configured correctly
(V-220649/656/668/671 on the work switches, checked by hand against the
running-config that produced them).

The fix reads the template with `show template interface source user <name>`
and splices its commands into every block that sources it, before any check
runs. That is only safe if it cuts both ways, so the second test here pins the
opposite direction: a template missing a required command must still produce
the finding, or the expansion would have turned a real gap into a silent pass -
the failure this project cares most about.
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
import stig_common

failures = []


def check(name, condition, detail=''):
    print(f'  {"ok  " if condition else "FAIL"} {name}')
    if not condition:
        if detail:
            print(f'       {detail}')
        failures.append(name)


# What running-config shows for a templated port: one line standing in for
# everything the STIG asks about.
TEMPLATED_PORT = """interface GigabitEthernet1/0/5
 description user port
 source template USER_PORT
!
"""

# ...and what the switch says when asked for that template. Header shape from
# IOS XE: capitalised `Label : value` lines and a separator rule around the
# body, which is why parse_interface_template drops lines by that shape rather
# than by position.
TEMPLATE_OUTPUT = """Building configuration...

Template Name       : USER_PORT
Template Type       : Interface
Template Source     : User
--------------------------------------------------
 description user access port
 switchport mode access
 switchport access vlan 20
 spanning-tree portfast
 spanning-tree bpduguard enable
 switchport block unicast
 ip verify source
 storm-control broadcast level bps 20000000
 dot1x pae authenticator
 authentication port-control auto
!
--------------------------------------------------
"""

# The same template with BPDU Guard taken out - the port is genuinely missing
# it, and the report has to say so even though everything else it needs is
# there.
TEMPLATE_WITHOUT_BPDUGUARD = TEMPLATE_OUTPUT.replace(' spanning-tree bpduguard enable\n', '')

TEMPLATE_COMMAND = capture.template_command('USER_PORT')


def report_for(tmpdir, name, template_output=TEMPLATE_OUTPUT, interfaces=TEMPLATED_PORT):
    """Audit a config whose user port is templated, returning (report, exit code)."""
    cfg = 'hostname TESTSW01\n!\n' + interfaces + 'end'
    outputs = {**fixtures.OUTPUTS, 'show running-config': cfg}
    if template_output is not None:
        outputs[TEMPLATE_COMMAND] = template_output
    path = capture.write(os.path.join(tmpdir, name + '.capture'), outputs)
    result = subprocess.run(
        [sys.executable, os.path.join(PROJECT, 'l2_stig_audit.py'), 'TESTSW01',
         '--from-capture', path, '--non-user-vlans', '999,1000'],
        capture_output=True, text=True, cwd=PROJECT, timeout=120)
    return result.stdout + result.stderr, result.returncode


def findings_naming(report, needle):
    return ' | '.join(line.strip() for line in report.splitlines() if needle in line)


def test_parse_drops_metadata_not_commands():
    print('the template body is read, its header is not')
    body = stig_common.parse_interface_template(TEMPLATE_OUTPUT)
    check('every command is kept in order',
          body[:3] == ['description user access port', 'switchport mode access',
                       'switchport access vlan 20'], body[:3])
    check('the header lines are dropped',
          not [line for line in body if line.startswith('Template')], body)
    check('separator rules and ! are dropped',
          not [line for line in body if set(line) <= set('-!')], body)
    check('a switch that has nothing to show yields nothing',
          stig_common.parse_interface_template('% Template not found') == [])


def test_expansion_keeps_the_evidence():
    print('\nthe sourcing line stays, the commands join the block')
    expanded = stig_common.expand_interface_templates(
        TEMPLATED_PORT, {'USER_PORT': ['switchport mode access', 'switchport access vlan 20']})
    check('the source template line is still there',
          ' source template USER_PORT' in expanded, expanded)
    check('the template commands are indented into the block',
          ' switchport access vlan 20' in expanded, expanded)
    check('they land inside the interface block, not after it',
          expanded.strip().endswith('!'), expanded)
    check('a template that could not be read changes nothing',
          stig_common.expand_interface_templates(TEMPLATED_PORT, {'USER_PORT': []})
          == TEMPLATED_PORT)


def test_templated_port_draws_no_findings(tmpdir):
    print('\na port configured entirely by template is audited on what the template says')
    report, code = report_for(tmpdir, 'templated')
    check('the audit ran', code == 0, report[-400:])
    check('the templated port is named by no finding',
          'GigabitEthernet1/0/5' not in findings_naming(report, 'FAIL'),
          findings_naming(report, 'GigabitEthernet1/0/5'))
    check('the report says which template it read and how far it reached',
          'USER_PORT' in report and 'sourced by 1 interface' in report,
          findings_naming(report, 'USER_PORT'))
    # The four rules the work fleet saw this on, by their IOS XE ids - the
    # default checklist here.
    for rule in ('V-220649', 'V-220656', 'V-220668', 'V-220671'):
        line = findings_naming(report, rule)
        check(f'{rule} passes on the templated port', 'FAIL' not in line, line)


def test_a_gap_in_the_template_is_still_a_finding(tmpdir):
    print('\nexpansion is not a pass: a command missing from the template is still missing')
    report, code = report_for(tmpdir, 'gap', template_output=TEMPLATE_WITHOUT_BPDUGUARD)
    check('the audit ran', code == 0, report[-400:])
    check('BPDU Guard is reported against the templated port',
          'GigabitEthernet1/0/5' in findings_naming(report, 'BPDU Guard not functionally active'),
          findings_naming(report, 'BPDU Guard'))
    check('and the rules the template does satisfy still pass',
          'FAIL' not in findings_naming(report, 'V-220671'),
          findings_naming(report, 'V-220671'))


def test_capture_without_the_template_is_refused(tmpdir):
    print('\na capture that sources a template but does not carry it is refused')
    report, code = report_for(tmpdir, 'incomplete', template_output=None)
    check('the audit refuses rather than reporting', code == 1, report[-400:])
    check('and names the command to go back for', TEMPLATE_COMMAND in report, report[-400:])
    check('no verdicts were printed', 'passed,' not in report, report[-200:])


def test_a_switch_without_templates_asks_for_nothing_extra(tmpdir):
    print('\na switch that uses no templates is unaffected')
    plain = """interface GigabitEthernet1/0/5
 description user port
 switchport mode access
 switchport access vlan 20
!
"""
    report, code = report_for(tmpdir, 'plain', template_output=None, interfaces=plain)
    check('the audit runs on the five commands it always needed', code == 0, report[-400:])
    check('and says nothing about templates',
          'Interface templates' not in report, findings_naming(report, 'template'))


if __name__ == '__main__':
    with tempfile.TemporaryDirectory() as tmpdir:
        test_parse_drops_metadata_not_commands()
        test_expansion_keeps_the_evidence()
        test_templated_port_draws_no_findings(tmpdir)
        test_a_gap_in_the_template_is_still_a_finding(tmpdir)
        test_capture_without_the_template_is_refused(tmpdir)
        test_a_switch_without_templates_asks_for_nothing_extra(tmpdir)
    print('\n' + ('ALL CHECKS PASSED' if not failures
                  else f'{len(failures)} FAILED: {", ".join(failures)}'))
    sys.exit(1 if failures else 0)
