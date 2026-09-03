#!/usr/bin/env python
"""A VLAN's number is a per-switch fact; its name usually is not.

Run directly: `python3 tests/test_user_vlans.py`. No framework, no device.

discover_user_vlans decides which VLANs the DHCP snooping and DAI coverage
rules must cover (V-220633/635 on IOS and IOS XE, V-220684/686 on NX-OS).
Excluding only by VLAN ID assumes one numbering scheme across the fleet. Where
that does not hold - each site numbering its user and voice VLANs with whatever
was free, while calling them the same thing everywhere - an ID exclusion drops
a genuine user VLAN from those checks and the audit reports PASS for coverage
it never verified.

A false PASS on a compliance tool is the failure this project exists to avoid,
so the classification is pinned here from both directions: a named user VLAN
must survive its ID appearing in the non-user list, and a name must never
capture a VLAN it does not actually name.
"""

import os
import sys

PROJECT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import stig_common
from fixtures import VLAN_BRIEF

failures = []


def check(name, condition, detail=''):
    print(f'  {"ok  " if condition else "FAIL"} {name}')
    if not condition:
        if detail:
            print(f'       {detail}')
        failures.append(name)


class FakeSession:
    """Stands in for a Netmiko session or a loaded capture - discover_user_vlans
    only ever calls send_command."""

    def __init__(self, vlan_brief):
        self.vlan_brief = vlan_brief

    def send_command(self, command):
        assert command == 'show vlan brief', command
        return self.vlan_brief


# The fixture switch: 1 default, 10 MGMT, 20 USERS, 999 NATIVE, 1000 UNUSED,
# plus the reserved 1002-1005 block.
session = FakeSession(VLAN_BRIEF)


def discover(**kwargs):
    return stig_common.discover_user_vlans(session, **kwargs)


print('no classification given')
check('every non-reserved VLAN is a user VLAN',
      discover() == ['1', '10', '20', '999', '1000'], discover())
check('reserved 1002-1005 always excluded',
      not [v for v in discover() if 1002 <= int(v) <= 1005])

print()
print('excluding by ID, as before names existed')
check('IDs still exclude',
      discover(exclude=[1, 10, 999, 1000]) == ['20'], discover(exclude=[1, 10, 999, 1000]))
check('absent names change nothing',
      discover(exclude=[1, 10]) == discover(exclude=[1, 10], exclude_names=[], include_names=[]))

print()
print('naming the user VLANs positively - the fleet case')
# This switch calls VLAN 10 MGMT, but a sister switch numbers its user VLAN 10
# and its management VLAN something else. One inventory serves both.
check('a named user VLAN survives its ID being in the non-user list',
      discover(exclude=[1, 10, 999, 1000], include_names=['MGMT']) == ['10', '20'],
      discover(exclude=[1, 10, 999, 1000], include_names=['MGMT']))
check('an include beats an exclude of the same name',
      discover(exclude_names=['MGMT'], include_names=['MGMT']) == discover())
check('include is exact and case-insensitive',
      discover(exclude=[10], include_names=['mgmt']) == discover(exclude=[10], include_names=['MGMT']))
check('an include naming nothing on this switch changes nothing',
      discover(exclude=[10], include_names=['VOICE']) == discover(exclude=[10]))
check('reserved VLANs stay excluded even when named',
      not [v for v in discover(include_names=['fddi-default']) if 1002 <= int(v) <= 1005],
      discover(include_names=['fddi-default']))

print()
print('excluding by name, for a non-user VLAN whose ID moves instead')
check('name excludes its VLAN whatever its number',
      discover(exclude_names=['MGMT']) == ['1', '20', '999', '1000'],
      discover(exclude_names=['MGMT']))
check('matching is case-insensitive',
      discover(exclude_names=['mgmt']) == discover(exclude_names=['MGMT']))
check('surrounding whitespace is tolerated',
      discover(exclude_names=['  MGMT  ']) == discover(exclude_names=['MGMT']))
check('IDs and names combine, not replace',
      discover(exclude=[1], exclude_names=['MGMT']) == ['20', '999', '1000'],
      discover(exclude=[1], exclude_names=['MGMT']))

print()
print('over-matching is the dangerous direction')
check('a substring does not match - USERS survives an entry for USERS_MGMT',
      '20' in discover(exclude_names=['USERS_MGMT']), discover(exclude_names=['USERS_MGMT']))
check('a prefix does not match either - an exclude spelled MGM excludes nothing',
      discover(exclude_names=['MGM']) == discover(), discover(exclude_names=['MGM']))
check('a misspelled exclude leaves every VLAN in, which is a finding not a pass',
      set(discover(exclude_names=['MGM'])) >= set(discover(exclude_names=['MGMT'])))
check('a misspelled include also only ever adds VLANs to the audited set',
      set(discover(exclude=[10], include_names=['MGM'])) <= set(discover(exclude=[10], include_names=['MGMT'])))

print()
if failures:
    print(f'{len(failures)} FAILED: ' + ', '.join(failures))
    sys.exit(1)
print('all checks passed')
