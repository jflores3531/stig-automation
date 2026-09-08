#!/usr/bin/env python
"""A switchport-capable interface *name* is not a switchport.

Every per-access-port rule in l2_stig_audit.py - BPDU Guard, UUFB, IP Source
Guard, storm control, 802.1x/MAB, the access-VLAN rule, the explicit-mode rule -
reads its port list from parse_switchports(). That list was built from the
interface name alone, so two kinds of Layer 3 interface fell into the access
bucket and drew a finding from every one of those rules at once:

  * a routed port, carrying 'no switchport', and
  * a Catalyst's out-of-band management port - GigabitEthernet0/0, in Mgmt-vrf -
    which is not switchport-capable hardware, so IOS XE writes no switchport
    line for it in either direction.

Neither can take a switchport command, so each of those findings was a false
FAIL: the recognition-side mirror of the Fix Text false FAILs this project
already fixed, and one that would have shown up first on a production switch.

Excluding by name is not available. The lab's vios_l2 image carries a real
switchport called GigabitEthernet0/0 and the same audit has to serve both, so
the block's own contents decide it - which is what the last check here pins.

Driven through the CLI, like the other suites: l2_stig_audit.py parses argv at
import, so a report is the only way to read its verdicts from outside.
"""

import os
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


# One user port, hardened everywhere except 802.1x - so the report has exactly
# one legitimate per-port finding to name, and any other interface appearing
# beside it is the bug this suite is about.
HARDENED_PORT = """interface GigabitEthernet1/0/1
 description user port
 switchport mode access
 switchport access vlan 10
 spanning-tree bpduguard enable
 spanning-tree portfast
 switchport block unicast
 ip verify source
 storm-control broadcast level bps 20000000
!
"""

ROUTED_UPLINK = """interface TenGigabitEthernet1/0/24
 description routed uplink to the core
 no switchport
 ip address 198.51.100.9 255.255.255.252
!
"""

OOB_MANAGEMENT = """interface GigabitEthernet0/0
 description out-of-band management
 vrf forwarding Mgmt-vrf
 ip address 198.51.100.5 255.255.255.0
 negotiation auto
!
"""

# The same interface name on the lab image, where it is a genuine switchport -
# unhardened, so every per-access-port rule should name it.
VIOS_SWITCHPORT = """interface GigabitEthernet0/0
 switchport mode access
 switchport access vlan 10
!
"""


def report_for(tmpdir, name, interfaces):
    """Audit a running-config made of `interfaces`, returning the report text."""
    cfg = 'hostname TESTSW01\n!\n' + interfaces + 'end'
    path = capture.write(os.path.join(tmpdir, name + '.capture'),
                         {**fixtures.OUTPUTS, 'show running-config': cfg})
    result = subprocess.run(
        [sys.executable, os.path.join(PROJECT, 'scripts', 'l2_stig_audit.py'), 'TESTSW01',
         '--from-capture', path, '--non-user-vlans', '999,1000'],
        capture_output=True, text=True, cwd=PROJECT, timeout=120)
    if result.returncode != 0:
        check(f'{name} audit ran', False, (result.stdout + result.stderr)[-500:])
    return result.stdout


def test_layer3_never_named(tmpdir):
    print('\nLayer 3 interfaces draw no per-access-port findings')
    report = report_for(tmpdir, 'catalyst', HARDENED_PORT + ROUTED_UPLINK + OOB_MANAGEMENT)
    check('the routed uplink is never named', 'TenGigabitEthernet1/0/24' not in report,
          _findings_naming(report, 'TenGigabitEthernet1/0/24'))
    check('the OOB management port is never named', 'GigabitEthernet0/0' not in report,
          _findings_naming(report, 'GigabitEthernet0/0'))
    # Guards against passing by auditing nothing at all: the one real switchport
    # is missing 802.1x, and the report has to say so.
    check('the real switchport is still audited',
          'GigabitEthernet1/0/1' in report and '802.1x' in report)


def test_name_is_not_the_signal(tmpdir):
    print('\nthe same name, as a real switchport, is still audited')
    report = report_for(tmpdir, 'vios', VIOS_SWITCHPORT)
    check('vios_l2 GigabitEthernet0/0 is audited as a switchport',
          'GigabitEthernet0/0' in report,
          'excluded by name - the lab switches would stop being audited')
    check('and its missing hardening is reported',
          any(term in report for term in ('BPDU', 'UUFB', 'Source Guard')))


def test_user_facing_trunk_rule(tmpdir):
    """V-220645/671 scans interfaces itself rather than reusing
    parse_switchports' buckets, so it needs the Layer 3 exclusion
    independently - otherwise it reports a routed port as one whose far end it
    cannot see, when a routed port has no switchport mode to have."""
    print('\nthe user-facing-trunk rule excludes them too, and still catches a real one')
    bare = 'interface GigabitEthernet1/0/2\n description no mode set\n!\n'
    report = report_for(tmpdir, 'mode', HARDENED_PORT + ROUTED_UPLINK + OOB_MANAGEMENT + bare)
    line = _findings_naming(report, 'cannot tell from configuration')
    # A port with no explicit mode will trunk the moment something asks, which
    # on a user-facing port is the DTP problem this rule is about - so it goes
    # to a human with the trunks rather than passing quietly.
    check('the port with no switchport mode goes to a human',
          'GigabitEthernet1/0/2' in line, line)
    check('neither Layer 3 interface is', 'TenGigabitEthernet1/0/24' not in line
          and 'GigabitEthernet0/0' not in line, line)


def _findings_naming(report, needle):
    return ' | '.join(line.strip() for line in report.splitlines() if needle in line)


if __name__ == '__main__':
    with tempfile.TemporaryDirectory() as tmpdir:
        test_layer3_never_named(tmpdir)
        test_name_is_not_the_signal(tmpdir)
        test_user_facing_trunk_rule(tmpdir)
    print('\n' + ('ALL CHECKS PASSED' if not failures
                  else f'{len(failures)} FAILED: {", ".join(failures)}'))
    sys.exit(1 if failures else 0)
