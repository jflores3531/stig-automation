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

Names alone are not always enough either. A fleet that calls the same role
army-xxx-abc-user1 at one site and army-yyy-def-user15 at the next cannot be
described by a list of exact names without listing every site's spelling of
every user VLAN - and the one eventually missed is the silent PASS again. An
entry carrying a wildcard is matched as a glob for that case, and the last
section here pins how far each pattern reaches, including one written
deliberately too broadly.
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
print('naming a role rather than a VLAN - the wildcard form')
# The fleet the exact-name list cannot describe: the first three parts of the
# name are the site and stay put, the last word is the role and changes, the
# number changes with it, and each carries a different VLAN ID per switch.
# Listing every switch's spelling of every user VLAN is the thing that
# eventually misses one, and a missed user VLAN is a silent PASS on DHCP
# snooping and DAI coverage. 950 is the trap: a name with 'user' inside it
# that is not a user VLAN.
FLEET_BRIEF = """VLAN Name                             Status    Ports
---- -------------------------------- --------- -------------------------------
1    default                          active
600  army-xxx-abc-mgmt                active    Vl600
700  army-xxx-abc-tel                 active    Gi1/0/6
750  army-yyy-def-tel2                active    Gi1/0/7
800  army-xxx-abc-user1               active    Gi1/0/1
850  army-xxx-abc-user15              active    Gi1/0/2
860  army-yyy-def-user                active    Gi1/0/3
950  army-xxx-abc-superuser-admin     active    Gi1/0/5"""

# Every ID on that switch. Excluding all of them means each check below sees
# only what its pattern actually claimed, rather than what the ID list happened
# to leave behind.
FLEET_IDS = [1, 600, 700, 750, 800, 850, 860, 950]

fleet = FakeSession(FLEET_BRIEF)


def fleet_vlans(**kwargs):
    return stig_common.discover_user_vlans(fleet, **kwargs)


def claimed_by(*patterns):
    return fleet_vlans(exclude=FLEET_IDS, include_names=list(patterns))


check("'*user' catches the names that end in it, and only those",
      claimed_by('*user') == ['860'], claimed_by('*user'))
check("'*user[0-9]*' catches the numbered ones whatever the number",
      claimed_by('*user[0-9]*') == ['800', '850'], claimed_by('*user[0-9]*'))
check('the two together cover the role across sites, whatever ID each carries',
      claimed_by('*user', '*user[0-9]*') == ['800', '850', '860'])
# The voice VLAN is a second role under the same site prefix, spelled by its
# own last word - one more pattern, not one more list of names.
check("the voice role is its own pattern - '*tel' and '*tel[0-9]*'",
      claimed_by('*tel', '*tel[0-9]*') == ['700', '750'], claimed_by('*tel', '*tel[0-9]*'))
check('roles combine: every user-carrying VLAN, none of the infrastructure',
      claimed_by('*user', '*user[0-9]*', '*tel', '*tel[0-9]*')
      == ['700', '750', '800', '850', '860'],
      claimed_by('*user', '*user[0-9]*', '*tel', '*tel[0-9]*'))
check('the management VLAN is claimed by none of them',
      '600' not in claimed_by('*user', '*user[0-9]*', '*tel', '*tel[0-9]*'))
check('a pattern beats an ID exclusion, same as an exact name does',
      '800' in fleet_vlans(exclude=[800], include_names=['*user[0-9]*']))
check('patterns are case-insensitive too',
      claimed_by('*USER[0-9]*') == claimed_by('*user[0-9]*'))
check("'*user*' reaches further - superuser-admin comes with it",
      '950' in claimed_by('*user*'),
      'the broad pattern is allowed, but it must be visible in the classification')
check('an entry with no wildcard is still exact, not a substring',
      claimed_by('user') == [], claimed_by('user'))
# The site prefix is matchable too, for a switch where everything under it is
# a user VLAN - but here it would take the management VLAN with it, which is
# why the roles are named by their last word instead.
check("'army-xxx-abc-*' matches by prefix, mgmt VLAN included",
      claimed_by('army-xxx-abc-*') == ['600', '700', '800', '850', '950'],
      claimed_by('army-xxx-abc-*'))
check('excluding by pattern works the same way',
      '600' not in fleet_vlans(exclude_names=['*mgmt']),
      fleet_vlans(exclude_names=['*mgmt']))
check('a pattern matching nothing changes nothing',
      fleet_vlans(include_names=['*printer*']) == fleet_vlans())

# Which pattern claimed a VLAN is printed above every report, because the cost
# of a pattern reaching too far is only visible if it can be read back.
reasons = {vid: why for vid, _, _, why in stig_common.classify_vlans(
    fleet, exclude=[1, 600, 800, 850, 860, 900, 950], include_names=['*user[0-9]*'])}
check('the classification names the pattern that matched',
      '*user[0-9]*' in reasons['800'], reasons['800'])
check('and says so per VLAN, not once for the list',
      'ID listed as non-user' in reasons['950'], reasons['950'])

print()
print('a VLAN ID that is not a number stops the run instead of skewing it')
# Skipping the bad entry would leave the exclusion set wrong and every DHCP
# snooping and DAI verdict downstream reported with full confidence anyway.
try:
    discover(exclude=[1, 'ten'])
    check('unreadable VLAN ID raises', False, 'no exception')
except stig_common.InventoryError as err:
    check('unreadable VLAN ID raises InventoryError', True)
    check('the message names the offending value', "'ten'" in str(err), str(err))
    check('the message names inventory.yaml', 'inventory.yaml' in str(err), str(err))
    check('the message says where to look',
          'non_user_vlans' in str(err) and 'unused_vlan' in str(err), str(err))
check('numeric strings are still fine',
      discover(exclude=['1', '10']) == discover(exclude=[1, 10]))

print()
if failures:
    print(f'{len(failures)} FAILED: ' + ', '.join(failures))
    sys.exit(1)
print('all checks passed')
