#!/usr/bin/env python
"""Verification for scripts/snmp_host_acl.py.

Run directly: `python3 tests/test_snmp_host_acl.py`. No framework, no device.

The script's whole reason to exist is that appending to a standard ACL is
silently wrong: a `permit` added after the list's `deny any` is present in
`show run`, looks done, and matches nothing. Nothing about that failure raises
on the device, so the only place it can be caught is here, against real
`show ip access-lists` output.

So the suite is built around five claims:

  * entries are read back correctly from the way IOS renders them, including
    the wildcard-bits and `(N matches)` forms that make a line read off the
    device look nothing like the line that was pushed;
  * new permits are planned INTO the gap before the first deny, never after it;
  * a PINNED position (`--insert-at 11` for 11, 12, 13) lands exactly there,
    and is refused rather than sent when a target number already holds an
    entry - IOS would replace that entry in place, silently, and nothing in
    the session afterwards would say an ACE had been destroyed;
  * a gap too narrow to hold the entries stops the run rather than appending;
  * an entry already present is skipped rather than duplicated at a new
    sequence number.

The resequence command is one f-string and is checked for exact text, because
`ip access-list resequence` is a global-config command and a typo in it fails
silently in the other direction - Netmiko does not treat a rejected command as
fatal.

The inventory round-trip at the end writes a temporary file and loads it
through netauto.load_snmp(path=...) rather than the repo's own inventory.yaml,
which is gitignored and so absent from a fresh clone. That also proves the
section's shape parses under scripts/yaml.py, which is json.load here.
"""

import json
import os
import sys
import tempfile

PROJECT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(PROJECT, 'scripts'))

import netauto
import snmp_host_acl as snmp

failures = []


def check(name, condition, detail=''):
    print(f'  {"ok  " if condition else "FAIL"} {name}')
    if not condition:
        if detail:
            print(f'       {detail}')
        failures.append(name)


def raises(name, call, *fragments):
    """The AclError messages are the entire user interface when a run stops,
    so each is checked for the words that tell the operator what to do - not
    merely that something was raised."""
    try:
        call()
    except snmp.AclError as err:
        check(name, True)
        for fragment in fragments:
            check(f'{name}: message says "{fragment}"', fragment in str(err), str(err))
    except Exception as err:
        check(name, False, f'raised {type(err).__name__}: {err}')
    else:
        check(name, False, 'nothing was raised')


# How IOS actually renders a managed standard list: a host entry without the
# word `host`, a wildcard entry split across a comma, a hit counter on the line
# that has traffic, and an explicit deny at the end.
ACL_OUTPUT = """Standard IP access list SNMP_ACCESS
    10 permit 192.0.2.10
    20 permit 192.0.2.64, wildcard bits 0.0.0.31 (4 matches)
    30 deny   any log (112 matches)
"""

PERMIT_ONLY_OUTPUT = """Standard IP access list SNMP_ACCESS
    10 permit 192.0.2.10
    20 permit 192.0.2.11
"""

NO_ROOM_OUTPUT = """Standard IP access list SNMP_ACCESS
    10 permit 192.0.2.10
    11 permit 192.0.2.11
    12 deny   any log
"""

EXTENDED_OUTPUT = """Extended IP access list SNMP_ACCESS
    10 permit tcp host 192.0.2.10 any eq 22
    20 deny   ip any any log
"""

UNNUMBERED_OUTPUT = """Standard IP access list SNMP_ACCESS
    permit 192.0.2.10
    deny   any log
"""

WANTED = ['host 192.0.2.20', '192.0.2.21', '192.0.2.64 0.0.0.31']
THREE = ['host 192.0.2.20', '192.0.2.21', '192.0.2.22']


print('reading the ACL back off the device')
entries = snmp.parse_acl(ACL_OUTPUT, 'SNMP_ACCESS')
check('every entry is read', len(entries) == 3, str(entries))
check('sequence numbers are integers, not strings',
      [sequence for sequence, _ in entries] == [10, 20, 30], str(entries))
# Left on the line, the hit counter becomes part of the entry text and every
# comparison against it fails - so an entry with traffic is the one that gets
# wrongly re-inserted.
check('the (N matches) counter is stripped',
      'matches' not in ' '.join(text for _, text in entries), str(entries))
check('the deny keeps its log keyword', entries[2][1] == 'deny any log', str(entries[2]))
check('the header line is not read as an entry',
      all('access list' not in text for _, text in entries), str(entries))

print()
print('one spelling for an entry, whichever end it came from')
# These pairs are the same ACL entry written the two ways it appears: as
# pushed, and as read back. If any pair disagrees, an entry already in the list
# reads as absent and is inserted a second time at a new sequence number.
check('`permit host X` matches the `permit X` it is read back as',
      snmp.normalise_entry('permit host 192.0.2.10') == snmp.normalise_entry('permit 192.0.2.10'))
check('a wildcard pair matches the `, wildcard bits` form',
      snmp.normalise_entry('permit 192.0.2.64 0.0.0.31')
      == snmp.normalise_entry('permit 192.0.2.64, wildcard bits 0.0.0.31'))
check('case and run-together spacing do not matter',
      snmp.normalise_entry('PERMIT   HOST 192.0.2.10')
      == snmp.normalise_entry('permit 192.0.2.10'))
check('a hit counter does not change the entry',
      snmp.normalise_entry('permit 192.0.2.10 (4 matches)')
      == snmp.normalise_entry('permit 192.0.2.10'))
# The normaliser is deliberately loose about `host`; it must not be loose about
# addresses, or two different permits collapse into one and the second is never
# inserted at all.
check('two different hosts stay different',
      snmp.normalise_entry('permit host 192.0.2.10')
      != snmp.normalise_entry('permit host 192.0.2.11'))
check('a host is not the same as its /27',
      snmp.normalise_entry('permit 192.0.2.64')
      != snmp.normalise_entry('permit 192.0.2.64 0.0.0.31'))

print()
print('the deny is the floor, and it is found rather than assumed')
check('the first deny and the entry before it', snmp.first_deny(entries) == (30, 20),
      str(snmp.first_deny(entries)))
check('a permit-only list reports no deny and its last sequence',
      snmp.first_deny(snmp.parse_acl(PERMIT_ONLY_OUTPUT, 'SNMP_ACCESS')) == (None, 20))
check('an empty list reports no deny and nothing before it', snmp.first_deny([]) == (None, 0))
# A list that opens with its deny has no entry above it, so the floor is the
# start of the list rather than the previous entry's number.
check('a deny at the top leaves the start of the list below it',
      snmp.first_deny([(10, 'deny any log')]) == (10, 0))
check('only the FIRST deny counts - entries after it are already dead',
      snmp.first_deny([(10, 'permit 192.0.2.1'), (20, 'deny any'),
                       (30, 'permit 192.0.2.2'), (40, 'deny any')]) == (20, 10))

print()
print('planning the insert, numbers computed from the gap')
planned, already = snmp.plan_insert(entries, WANTED)
check('only the entries not already present are planned', len(planned) == 2, str(planned))
check('the wildcard entry already in the list is skipped',
      already == ['192.0.2.64 0.0.0.31'], str(already))
check('the planned entries get free numbers in the gap above 20',
      [sequence for sequence, _ in planned] == [21, 22], str(planned))
# The claim the whole script rests on.
check('every planned entry sits BEFORE the deny at 30',
      all(sequence < 30 for sequence, _ in planned), str(planned))
check('the planned text is a permit line', [text for _, text in planned]
      == ['permit host 192.0.2.20', 'permit 192.0.2.21'], str(planned))

# The case that makes the computed numbers equal the intended 11, 12, 13: one
# entry at 10, the deny above it.
computed = snmp.plan_insert([(10, 'permit 192.0.2.10'), (20, 'deny any log')], THREE)[0]
check('a list of one entry at 10 with a deny at 20 computes 11, 12, 13',
      [sequence for sequence, _ in computed] == [11, 12, 13], str(computed))
# And the case where they do NOT, which is why the pin exists.
computed2 = snmp.plan_insert([(10, 'permit 192.0.2.10'), (20, 'permit 192.0.2.11'),
                              (30, 'deny any log')], THREE)[0]
check('add a permit at 20 and the computed numbers become 21, 22, 23',
      [sequence for sequence, _ in computed2] == [21, 22, 23], str(computed2))

no_deny = snmp.parse_acl(PERMIT_ONLY_OUTPUT, 'SNMP_ACCESS')
planned_append, _ = snmp.plan_insert(no_deny, WANTED)
# With no explicit deny the implicit one sits past the end of the list, so
# appending is already in front of it and IOS can pick the numbers.
check('a list with no explicit deny appends instead, with no numbers chosen',
      [sequence for sequence, _ in planned_append] == [None, None, None], str(planned_append))
check('all three are still planned there', len(planned_append) == 3, str(planned_append))

check('nothing to do is empty, not an error',
      snmp.plan_insert(entries, ['host 192.0.2.10']) == ([], ['host 192.0.2.10']))

print()
print('planning the insert, position PINNED at 11')
BASE = [(10, 'permit 192.0.2.10'), (20, 'deny any log')]
pinned, _ = snmp.plan_insert(BASE, THREE, insert_at=11)
check('three permits land at exactly 11, 12, 13',
      [sequence for sequence, _ in pinned] == [11, 12, 13], str(pinned))
check('in inventory order', [text for _, text in pinned]
      == ['permit host 192.0.2.20', 'permit 192.0.2.21', 'permit 192.0.2.22'], str(pinned))
check('pinning past the start of the list is honoured, not clamped',
      [s for s, _ in snmp.plan_insert([(10, 'permit 192.0.2.10'), (50, 'deny any log')],
                                      THREE, insert_at=30)[0]] == [30, 31, 32])
# A skipped entry shortens the run, so the remaining ones shift down. Worth
# pinning down: an operator who expects 11, 12, 13 gets 11, 12 when one of the
# three is already there.
shifted, skipped = snmp.plan_insert(
    [(10, 'permit 192.0.2.10'), (15, 'permit 192.0.2.21'), (20, 'deny any log')],
    THREE, insert_at=11)
check('an entry already present is skipped and the rest close up',
      [sequence for sequence, _ in shifted] == [11, 12], str(shifted))
check('and it is reported as already present', skipped == ['192.0.2.21'], str(skipped))

print()
print('a pinned number that would overwrite an entry is refused')
# This is the destructive case. IOS does not error on it: `12 permit X` where
# 12 exists REPLACES it, in place, with no confirmation and nothing afterwards
# to say a rule is gone.
raises('a collision with one existing entry raises',
       lambda: snmp.plan_insert([(10, 'permit 192.0.2.10'), (12, 'permit 192.0.2.99'),
                                 (30, 'deny any log')], THREE, insert_at=11),
       'Refusing to insert', 'REPLACE', '12 permit 192.0.2.99', 'Nothing was pushed')
raises('the collision message lists every number it would have used',
       lambda: snmp.plan_insert([(11, 'permit 192.0.2.98'), (13, 'permit 192.0.2.99'),
                                 (30, 'deny any log')], THREE, insert_at=11),
       '11, 12, 13', '11 permit 192.0.2.98', '13 permit 192.0.2.99')
check('a pin into free numbers beside existing ones is fine',
      [s for s, _ in snmp.plan_insert([(10, 'permit 192.0.2.10'), (14, 'permit 192.0.2.99'),
                                       (30, 'deny any log')], THREE, insert_at=11)[0]]
      == [11, 12, 13])
# The entry being overwritten could be the deny itself, which is worse again -
# it is caught by the collision check before the floor check.
raises('a pin onto the deny itself is refused',
       lambda: snmp.plan_insert([(10, 'permit 192.0.2.10'), (11, 'deny any log')],
                                THREE, insert_at=11),
       'Refusing to insert', 'deny any log')

print()
print('a pinned number at or past the deny is refused')
raises('all three past the deny raises and names the deny',
       lambda: snmp.plan_insert([(10, 'permit 192.0.2.10'), (20, 'deny any log')],
                                THREE, insert_at=21),
       'at or after the deny at sequence 20', 'first-match', 'Nothing was pushed')
raises('the message says how low to start',
       lambda: snmp.plan_insert([(10, 'permit 192.0.2.10'), (20, 'deny any log')],
                                THREE, insert_at=21),
       'Start at 17 or lower')
check('starting exactly that low is accepted',
      [s for s, _ in snmp.plan_insert([(10, 'permit 192.0.2.10'), (20, 'deny any log')],
                                      THREE, insert_at=17)[0]] == [17, 18, 19])
# The partial case - 19, 20, 21 against a deny at 20 - would put one entry in
# front of the deny and two behind it. Because the targets are consecutive,
# straddling the deny always means one of them lands ON it, so this surfaces as
# the collision rather than the floor check. That is the better of the two
# messages here: the hazard is that the DENY would be the entry replaced.
raises('straddling the deny is caught as overwriting the deny itself',
       lambda: snmp.plan_insert([(10, 'permit 192.0.2.10'), (20, 'deny any log')],
                                THREE, insert_at=19),
       'Refusing to insert at 19, 20, 21', 'REPLACE', '20 deny any log')
check('starting exactly low enough is accepted',
      [s for s, _ in snmp.plan_insert([(10, 'permit 192.0.2.10'), (20, 'deny any log')],
                                      THREE, insert_at=17)[0]] == [17, 18, 19])
# No room below the deny for three entries at all - the advice has to change,
# because there is no valid start to suggest.
raises('a deny too low to fit under says to resequence instead',
       lambda: snmp.plan_insert([(2, 'deny any log')], THREE, insert_at=1),
       '--resequence-first')
raises('a pin below 1 is refused',
       lambda: snmp.plan_insert(BASE, THREE, insert_at=0), '1 or more')
# A pin into a list with no explicit deny has no floor to check against.
check('no deny means a pin is only checked for collisions',
      [s for s, _ in snmp.plan_insert([(10, 'permit 192.0.2.10')], THREE, insert_at=11)[0]]
      == [11, 12, 13])

print()
print('a gap too narrow to insert into stops the run')
# The alternative is appending after the deny, which is accepted by the device,
# reported as success, and matches nothing. Refusing is the only safe answer.
raises('no room raises AclError',
       lambda: snmp.plan_insert(snmp.parse_acl(NO_ROOM_OUTPUT, 'SNMP_ACCESS'), WANTED),
       'No room', 'sequence 12', '--resequence-first', 'nothing was pushed')
# The off-by-one here decides whether a run appends past the deny, so it is
# pinned from both sides.
check('room for exactly as many as are wanted is accepted',
      [s for s, _ in snmp.plan_insert([(10, 'permit 192.0.2.1'), (14, 'deny any log')],
                                      WANTED)[0]] == [11, 12, 13])
raises('one short is refused',
       lambda: snmp.plan_insert([(10, 'permit 192.0.2.1'), (13, 'deny any log')], WANTED),
       'No room')
raises('a deny at the very first sequence leaves no room',
       lambda: snmp.plan_insert([(1, 'deny any log')], WANTED), 'No room')

print()
print('ACLs this script must refuse to touch')
raises('an undefined ACL raises rather than being created',
       lambda: snmp.parse_acl('', 'SNMP_ACCESS'), 'is not defined', 'snmp.acl_name')
raises('a different ACL in the output is not mistaken for this one',
       lambda: snmp.parse_acl(ACL_OUTPUT, 'VTY_MGMT'), 'is not defined')
raises('an extended list of the same name raises',
       lambda: snmp.parse_acl(EXTENDED_OUTPUT, 'SNMP_ACCESS'), 'EXTENDED', 'standard')
# The quiet one: no sequence numbers means neither an insert nor a resequence
# is possible, and reading it as an empty list would append past the deny.
raises('an image that renders no sequence numbers raises',
       lambda: snmp.parse_acl(UNNUMBERED_OUTPUT, 'SNMP_ACCESS'),
       'sequence number', 'resequence')
# A defined but empty list is legitimate - it is not the unnumbered case.
check('a defined, empty ACL is read as empty rather than refused',
      snmp.parse_acl('Standard IP access list SNMP_ACCESS\n', 'SNMP_ACCESS') == [])

print()
print('the commands')
check('the resequence line is exact',
      snmp.resequence_command('SNMP_ACCESS', 10, 10)
      == 'ip access-list resequence SNMP_ACCESS 10 10')
check('the resequence defaults to 10/10',
      snmp.resequence_command('SNMP_ACCESS') == 'ip access-list resequence SNMP_ACCESS 10 10')
check('the snmp-server host line is exact',
      snmp.snmp_host_command('192.0.2.20', 'SNMPV3_USER')
      == 'snmp-server host 192.0.2.20 version 3 priv SNMPV3_USER')

commands = snmp.acl_commands('SNMP_ACCESS', pinned)
check('the ACL block opens in standard-list config mode',
      commands[0] == 'ip access-list standard SNMP_ACCESS', str(commands))
check('each entry carries its sequence number first',
      commands[1:4] == ['11 permit host 192.0.2.20 log', '12 permit 192.0.2.21 log',
                        '13 permit 192.0.2.22 log'], str(commands))
# Without this, the resequence line that follows is sent while still in
# config-acl mode, where IOS does not know it.
check('the block exits config-acl mode for the resequence that follows',
      commands[-1] == 'exit', str(commands))
check('an append with no numbers sends the bare permit',
      snmp.acl_commands('SNMP_ACCESS', planned_append)[1] == 'permit host 192.0.2.20 log')
check('a permit already ending in log is not given a second one',
      snmp.acl_commands('SNMP_ACCESS', [(11, 'permit host 192.0.2.20 log')])[1]
      == '11 permit host 192.0.2.20 log')
check('log is ignored when comparing entries',
      snmp.normalise_entry('permit 192.0.2.20 log') == snmp.normalise_entry('permit host 192.0.2.20'))
check('nothing planned means no ACL block at all',
      snmp.acl_commands('SNMP_ACCESS', []) == [])

relog = snmp.relog_plan([(10, 'permit 192.0.2.10'), (20, 'permit 192.0.2.64, wildcard bits 0.0.0.31'),
                         (30, 'permit 192.0.2.30 log'), (40, 'deny any log')])
check('relog_plan picks only the permits without log',
      relog == [(10, 'permit 192.0.2.10 log'), (20, 'permit 192.0.2.64 0.0.0.31 log')], str(relog))
check('a permit with log and a match count is already logged',
      snmp.relog_plan([(10, 'permit 192.0.2.10 log (12 matches)')]) == [])
check('each is replaced in place: no N, then N with log',
      snmp.acl_commands('SNMP_ACCESS', [], relog)[1:5]
      == ['no 10', '10 permit 192.0.2.10 log', 'no 20', '20 permit 192.0.2.64 0.0.0.31 log'],
      str(snmp.acl_commands('SNMP_ACCESS', [], relog)))
check('relogs alone still open and close the ACL block',
      snmp.acl_commands('SNMP_ACCESS', [], relog)[0] == 'ip access-list standard SNMP_ACCESS'
      and snmp.acl_commands('SNMP_ACCESS', [], relog)[-1] == 'exit')
lost, unlogged = snmp.check_relogged([(10, 'permit 192.0.2.10 log'), (30, 'permit 192.0.2.30')],
                                     relog)
check('a replaced permit missing after the push is reported as lost',
      lost == [(20, 'permit 192.0.2.64 0.0.0.31 log')], str(lost))
check('a permit still without log is reported', unlogged == [(30, 'permit 192.0.2.30')],
      str(unlogged))

print()
print('reading the result back off the device, which is the only proof')
after = snmp.parse_acl("""Standard IP access list SNMP_ACCESS
    10 permit 192.0.2.10
    20 permit 192.0.2.20
    30 permit 192.0.2.21
    40 permit 192.0.2.64, wildcard bits 0.0.0.31
    50 deny   any log
""", 'SNMP_ACCESS')
check('a clean result reports nothing missing and nothing stranded',
      snmp.check_applied(after, WANTED) == ([], [], 50), str(snmp.check_applied(after, WANTED)))

# The failure the script exists to catch, confirmed to be caught: both entries
# are present in the config and both are past the deny.
stranded = snmp.parse_acl("""Standard IP access list SNMP_ACCESS
    10 permit 192.0.2.10
    20 permit 192.0.2.64, wildcard bits 0.0.0.31
    30 deny   any log
    40 permit 192.0.2.20
    50 permit 192.0.2.21
""", 'SNMP_ACCESS')
missing, unreachable, deny_sequence = snmp.check_applied(stranded, WANTED)
check('an entry present but past the deny is NOT reported as done', unreachable, str(unreachable))
check('both stranded entries are named with their sequence numbers',
      unreachable == [('host 192.0.2.20', 40), ('192.0.2.21', 50)], str(unreachable))
check('stranded entries are not also counted as missing', missing == [], str(missing))
check('the deny they are stranded behind is reported', deny_sequence == 30)

rejected, _, _ = snmp.check_applied(entries, WANTED)
check('an entry the device rejected is reported missing',
      rejected == ['host 192.0.2.20', '192.0.2.21'], str(rejected))

print()
print('what references the ACL, which decides whether any of this has an effect')
reference_output = """ip access-list standard SNMP_ACCESS
snmp-server group SNMPV3_GROUP v3 priv access SNMP_ACCESS
 access-class SNMP_ACCESS in
"""
found = snmp.references(reference_output, 'SNMP_ACCESS')
check("the ACL's own definition is not counted as a reference to it",
      all('access-list' not in line for line in found), str(found))
check('both real references are found', len(found) == 2, str(found))
check('nothing referencing it is an empty list, not a false positive',
      snmp.references('ip access-list standard SNMP_ACCESS\n', 'SNMP_ACCESS') == [])
# Inserting a permit into a vty access-class grants SSH, not polling. The run
# has to be able to say so before it pushes.
check('a vty access-class is singled out',
      snmp.vty_references(found) == ['access-class SNMP_ACCESS in'], str(found))
check('an snmp-server group reference is not flagged as a vty one',
      snmp.vty_references(['snmp-server group G v3 priv access SNMP_ACCESS']) == [])

print()
print('the SNMPv3 user, read live because classic IOS never writes it to config')
SNMP_USER_OUTPUT = """
User name: SNMPV3_USER
Engine ID: 800000090300525400123456
storage-type: nonvolatile        active
Authentication Protocol: SHA
Privacy Protocol: AES128
Group-name: SNMPV3_GROUP
"""
check('a configured user is found', snmp.snmp_user_present(SNMP_USER_OUTPUT, 'SNMPV3_USER'))
check('a user that is not there is not found',
      not snmp.snmp_user_present(SNMP_USER_OUTPUT, 'OTHER_USER'))
# This is the check that catches an ACL name typed where the username goes -
# the line IOS accepts and then drops every trap for.
check('an ACL name in the username position is reported absent',
      not snmp.snmp_user_present(SNMP_USER_OUTPUT, 'SNMP_ACCESS'))
check('empty output is not a user', not snmp.snmp_user_present('', 'SNMPV3_USER'))
# A name that is a prefix of a configured one must not match it, or a typo'd
# username is reported as present.
check('a prefix of a configured name does not match',
      not snmp.snmp_user_present(SNMP_USER_OUTPUT, 'SNMPV3_USE'))

print()
print('the inventory is the only place the config comes from')
INVENTORY = {
    'devices': {},
    'snmp': {
        'acl_name': 'SNMP_ACCESS',
        'trap_hosts': {'192.0.2.20': 'SNMPV3_USER'},
        'permits': ['host 192.0.2.20', '192.0.2.21', '192.0.2.64 0.0.0.31'],
        'insert_at': 11,
        'resequence': {'start': 10, 'increment': 10},
    },
}
handle, path = tempfile.mkstemp(suffix='.yaml')
with os.fdopen(handle, 'w') as inventory_file:
    json.dump(INVENTORY, inventory_file)
try:
    # Round-tripped through the file rather than asserted on the dict, so the
    # section's shape is proved to parse under scripts/yaml.py too.
    loaded = netauto.load_snmp(path=path)
    acl_name, permits, hosts, (start, increment), insert_at = snmp.load_config(loaded)
finally:
    os.unlink(path)
check('the ACL name is read from the inventory', acl_name == 'SNMP_ACCESS', acl_name)
check('all three permits are read, in order', permits == WANTED, str(permits))
check('the receiver and its v3 user are read',
      hosts == [('192.0.2.20', 'SNMPV3_USER')], str(hosts))
check('the resequence start/increment are read as numbers',
      (start, increment) == (10, 10), f'{start}/{increment}')
check('insert_at is read as a number', insert_at == 11, repr(insert_at))

# Every one of these would otherwise reach the device as a push. A bare string
# for permits is the dangerous one: Python iterates it per character, so the
# device gets `permit h`, `permit o`, `permit s`...
raises('a missing snmp section names the key to add',
       lambda: snmp.load_config({}), 'snmp.acl_name')
raises('a bare string for permits is refused, not iterated per character',
       lambda: snmp.load_config({'acl_name': 'A', 'permits': 'host 192.0.2.20'}),
       'LIST', 'one character at a time')
raises('an empty permits list is refused',
       lambda: snmp.load_config({'acl_name': 'A', 'permits': []}), 'non-empty')
raises('a blank permit entry is refused',
       lambda: snmp.load_config({'acl_name': 'A', 'permits': ['host 192.0.2.20', '  ']}),
       'blank entry')
raises('a receiver with no username is refused, and the message says it is a username',
       lambda: snmp.load_config({'acl_name': 'A', 'permits': ['any'],
                                 'trap_hosts': {'192.0.2.20': None}}),
       'NOT an ACL name')
raises('a list of receivers is refused with the mapping shape to use instead',
       lambda: snmp.load_config({'acl_name': 'A', 'permits': ['any'],
                                 'trap_hosts': ['192.0.2.20']}),
       'MAPPING', '192.0.2.20')
raises('a non-numeric resequence start is refused',
       lambda: snmp.load_config({'acl_name': 'A', 'permits': ['any'],
                                 'resequence': {'start': 'ten'}}),
       'whole numbers')
raises('a zero increment is refused - it would renumber every entry to start',
       lambda: snmp.load_config({'acl_name': 'A', 'permits': ['any'],
                                 'resequence': {'increment': 0}}),
       '1 or more')
raises('a non-numeric insert_at is refused',
       lambda: snmp.load_config({'acl_name': 'A', 'permits': ['any'], 'insert_at': 'eleven'}),
       'whole number', '11, 12, 13')
raises('a zero insert_at is refused',
       lambda: snmp.load_config({'acl_name': 'A', 'permits': ['any'], 'insert_at': 0}),
       '1 or more')
# true is 1 in Python, which would silently pin the insert at sequence 1.
raises('a boolean insert_at is refused rather than treated as 1',
       lambda: snmp.load_config({'acl_name': 'A', 'permits': ['any'], 'insert_at': True}),
       'whole number')
check('insert_at is None when the inventory omits it, meaning compute the numbers',
      snmp.load_config({'acl_name': 'A', 'permits': ['any']})[4] is None)
check('resequence defaults to 10/10 when the inventory omits it',
      snmp.load_config({'acl_name': 'A', 'permits': ['any']})[3] == (10, 10))
check('extra whitespace inside a permit spec is collapsed, not pushed',
      snmp.load_config({'acl_name': 'A',
                        'permits': ['host   192.0.2.20']})[1] == ['host 192.0.2.20'])

print()
print('the shipped inventory template still parses, with the snmp section in it')
with open(os.path.join(PROJECT, 'inventory.yaml.example')) as example_file:
    example = netauto.yaml.safe_load(example_file)
check('inventory.yaml.example has an snmp section', 'snmp' in example, str(list(example)))
check('it is documented in _comments like every other key',
      'snmp' in example.get('_comments', {}))
check('it ships with no permits, so no site addressing is committed',
      example['snmp']['permits'] == [], str(example['snmp']))
check('it ships with insert_at null, meaning compute the numbers',
      example['snmp']['insert_at'] is None, str(example['snmp']))
# The template must be refused rather than pushed as-is: permits is empty.
raises('the template as shipped refuses to run until permits are filled in',
       lambda: snmp.load_config(example['snmp']), 'non-empty')

print()
if failures:
    print(f'{len(failures)} FAILED: ' + ', '.join(failures))
    sys.exit(1)
print('all checks passed')
