#!/usr/bin/env python
"""Point a device's SNMPv3 notifications at a receiver, and insert the matching
permits into an EXISTING named standard ACL - in front of its deny, not after
it - then renumber the list with `ip access-list resequence`.

Two commands, from inventory.yaml's `snmp` section:

    snmp-server host <trap_hosts key> version 3 priv <trap_hosts value>
    ip access-list resequence <acl_name> <start> <increment>

and between them, one `<seq> permit <spec>` per entry in `snmp.permits` - at
11, 12, 13 with `insert_at` set to 11, or at numbers read off the device when
it is not. See WHERE THE ENTRIES LAND below; it is the one decision here worth
making deliberately.

This is not a STIG script. No rule in the four checklists under checklists/
ties SNMP to an ACL - the closest are the OOBM management-traffic rules
(V-216587/216589/216593), which are about a perimeter router's interfaces
rather than about who may poll. The SNMPv3 rules that DO exist
(V-220604/605 on the L2S book, V-215696/697 on the router's) are about the
auth/priv algorithms on the USER, and l2_stig_harden_global.py and
ios_router_stig_harden_global.py already push those from secrets.yaml. So this
sits with backup_config.py and arp_inventory.py as operational tooling, and
nothing in it reports a verdict or writes a checklist.

READ THIS FIRST: THE LAST FIELD IS A USERNAME, NOT AN ACL NAME
`snmp-server host` has no ACL field on IOS or IOS XE. In

    snmp-server host 192.0.2.20 version 3 priv SNMPV3_USER

the trailing token is the SNMPv3 *user* whose auth/priv keys sign and encrypt
the traps sent to that host, and IOS resolves it against the SNMP user table -
not the ACL table. Nothing rejects an ACL name typed there: the line is
accepted, stored, and then every notification to that host is silently dropped
because no such user exists. Which is why this script reads `show snmp user`
and says so, instead of letting a quiet NMS be the thing that tells you.

Where an ACL does attach to SNMPv3 is the group, which this script does NOT
push - where traps go and who may poll are two different decisions:

    snmp-server group <group> v3 priv access <acl_name>

and for v1/v2c it is `snmp-server community <string> RO <acl_name>`. Until one
of those exists, an ACL full of permits restricts nothing. The run reports what
actually references the list, and says plainly when the answer is nothing.

WHY INSERT RATHER THAN APPEND
A standard ACL is first-match, and a managed list ends in an explicit
`deny any log`. Type `permit host 192.0.2.20` inside `ip access-list standard
SNMP_ACCESS` and IOS appends it at last + 10 - after the deny, where no packet
will ever reach it. The list looks right in `show run` and denies the host. So
the permits go in front of the first deny, and that deny is found by reading the
device rather than assumed.

WHERE THE ENTRIES LAND
Two ways, and they are not the same position:

  `insert_at` / `--insert-at 11` pins the numbers: the entries take 11, 12, 13
  exactly. Use this when the order matters - when the new permits must sit
  immediately after sequence 10 rather than wherever there happens to be room.

  Left unset, the numbers are computed: the entries are packed into the gap
  immediately BELOW the first deny. On a list whose only entry above the deny
  is at 10 that is also 11, 12, 13. On one that also has a permit at 20 it is
  21, 22, 23 - still correct, still in front of the deny, but last among the
  permits rather than second.

For plain host permits that do not overlap each other the distinction is
cosmetic: a standard ACL only cares that a permit precedes the deny. It stops
being cosmetic the moment two entries overlap - a `permit host` that has to be
reached before a wider `permit <subnet>`, or a deny sitting mid-list - because
then first-match makes the order the behaviour. And after the resequence the
numbers are gone and that order is the only thing left. So where it matters,
pin it.

A pinned number that is already in use is NOT an error on IOS: entering
`12 permit ...` when 12 already holds an entry REPLACES it, in place, silently.
That is checked before anything is sent - see pinned_sequences.

WHY RESEQUENCE COMES AFTER, NOT BEFORE
The inserted numbers are whatever was free - 11, 12, 13 wedged above a 10 -
which leaves a correct list with almost no room left in it for the next insert.
`ip access-list resequence SNMP_ACCESS 10 10` renumbers the entries in place,
order unchanged, and hands back a 10-wide gap between each. Running it first
would also make room, but then you insert into that room and end up with the
wedged numbers anyway; running it last is the pass that leaves the list ready
for the next one. It changes no access decision - only the numbers - and it is
the one command here that is pure housekeeping.

If the gap is too narrow to hold the entries (an existing 10 and a deny at 12)
there is nothing to insert into, and the run stops naming --resequence-first,
which renumbers before inserting as well as after.

WHAT THIS CANNOT DO TO YOU
Every change here is additive: new permits in front of a deny, and a renumber.
No entry is removed and no deny is added, so nothing that reaches the device
today stops reaching it. That is why there is no second-session verification
dance like the one in l2_stig_harden_acl.py - there is no lockout to catch.

The additive direction has its own trap, and it is why the run prints what
references the ACL before pushing: a list under `line vty 0 4 / access-class
... in` is an SSH filter, and inserting a permit there grants the NMS
interactive access to the device rather than the right to poll it. Point
snmp.acl_name at a list that exists for SNMP.

Nothing is written to startup-config. Confirm the result, then save_config.py.
"""

import argparse
import re
import sys

import netauto

# `show ip access-lists <name>` renders a standard list like this:
#
#   Standard IP access list SNMP_ACCESS
#       10 permit 192.0.2.10
#       20 permit 192.0.2.0, wildcard bits 0.0.0.255 (4 matches)
#       30 deny   any log
#
# The leading integer is what this script inserts between; the rest is the
# entry, normalised before any comparison - see normalise_entry.
ENTRY_RE = re.compile(r'^\s*(\d+)\s+(permit|deny)\b(.*)$', re.IGNORECASE)
UNNUMBERED_ENTRY_RE = re.compile(r'^\s*(permit|deny)\b', re.IGNORECASE)
HEADER_RE = re.compile(r'^\s*(Standard|Extended)\s+IP\s+access\s+list\s+(\S+)',
                       re.IGNORECASE | re.MULTILINE)
MATCH_COUNT_RE = re.compile(r'\(\d+\s+matches?\)\s*$')

# The resequence defaults. 10/10 is IOS's own numbering for a list built
# without explicit sequence numbers, so a resequenced list looks like one
# nobody had to repair.
DEFAULT_START = 10
DEFAULT_INCREMENT = 10


class AclError(Exception):
    """The ACL on the device makes the asked-for insert wrong, rather than
    merely unnecessary. Always carries what was read and what to do about it -
    these messages are the whole user interface when a run stops."""


def normalise_entry(text):
    """One spelling for an ACL entry, so a line read off the device can be
    compared with a line about to be pushed.

    The two are never written the same way. `permit host 192.0.2.10` is pushed
    and read back as `permit 192.0.2.10`; `permit 192.0.2.0 0.0.0.255` is read
    back as `permit 192.0.2.0, wildcard bits 0.0.0.255`. Without this, an entry
    already in the list looks absent and is inserted again - which IOS accepts,
    leaving the same permit twice at two sequence numbers."""
    text = MATCH_COUNT_RE.sub('', str(text)).strip().lower()
    text = text.replace(', wildcard bits ', ' ')
    text = re.sub(r'\bhost\s+', '', text)
    return re.sub(r'\s+', ' ', text).strip()


def parse_acl(output, name):
    """The ACL's entries as [(sequence, 'permit|deny <body>')], in list order.

    Raises AclError rather than returning [] for the three cases where an empty
    list would be a lie: the ACL is not defined (IOS answers a `show` for a
    list it does not have with nothing at all), it is defined as an extended
    list under the same name, or the image renders entries without sequence
    numbers. The last one is the quiet one - a list with no numbers can be
    neither inserted into nor resequenced, and treating it as empty would
    append every permit after the deny, which is the exact failure this script
    exists to avoid."""
    text = str(output or '')
    header = None
    for kind, listed_name in HEADER_RE.findall(text):
        if listed_name.lower() == str(name).lower():
            header = kind.lower()
            break
    if header is None:
        raise AclError(
            f'{name} is not defined on this device - `show ip access-lists {name}` returned no '
            f'list by that name.\nThis script inserts into an ACL that already exists, because '
            f'creating a standard list named in inventory.yaml and silently filling it with '
            f'permits is not what "insert into the existing ACL" asked for. Create it first, or '
            f'fix snmp.acl_name.')
    if header != 'standard':
        raise AclError(
            f'{name} exists on this device as an EXTENDED IP access list, and snmp.permits are '
            f'standard-list entries (source only).\n`ip access-list standard {name}` against an '
            f'extended list of the same name is rejected by IOS, so nothing here would land. '
            f'Point snmp.acl_name at the standard list, or write the entries as extended ones in '
            f'a script that pushes those.')

    entries = []
    unnumbered = 0
    for line in text.splitlines():
        if HEADER_RE.match(line):
            continue
        match = ENTRY_RE.match(line)
        if match:
            body = MATCH_COUNT_RE.sub('', match.group(3)).strip()
            entries.append((int(match.group(1)), f'{match.group(2).lower()} {body}'.strip()))
        elif UNNUMBERED_ENTRY_RE.match(line):
            unnumbered += 1

    if unnumbered and not entries:
        raise AclError(
            f'{name} has {unnumbered} entr(ies) and this image renders none of them with a '
            f'sequence number.\nWithout numbers there is nothing to insert between and nothing '
            f'for `ip access-list resequence` to renumber - both need the ACL sequence number '
            f'feature. Rewrite the list by hand on this device, or run against an image that '
            f'supports it.')
    return entries


def first_deny(entries):
    """(sequence of the first deny, sequence of the entry before it), or
    (None, last sequence) for a list with no explicit deny.

    The first deny is the floor for an insert. Everything below it is reachable
    and everything at or after it is not, for whatever sources it covers - and
    for the `deny any` that ends a managed list, that is every source there
    is."""
    previous = 0
    for sequence, text in entries:
        if text.startswith('deny'):
            return sequence, previous
        previous = sequence
    return None, previous


def pinned_sequences(entries, wanted, insert_at, deny_sequence):
    """Consecutive sequence numbers from insert_at, checked against the list
    that is actually on the device.

    Used when the position is stated rather than computed - `--insert-at 11`
    for the 11, 12, 13 an operator intends. Two things have to be true for
    those numbers to mean what they look like, and neither holds by assumption.

    A pinned number that is already in use is NOT an error on IOS. Entering
    `12 permit 192.0.2.21` inside `ip access-list standard X` when 12 already
    holds an entry REPLACES that entry, in place, with no warning and no
    confirmation. There is nothing in the session afterwards to say an ACE was
    destroyed, and `show ip access-lists` looks healthy because it is - it is
    just missing a rule that used to be there. So every target number is
    checked against the list first, and a collision stops the run.

    And a pinned number can land past the deny just as easily as an append can:
    11, 12, 13 is right against a list whose deny is at 20 and wrong against
    one whose deny is at 12. The deny is the floor either way."""
    if insert_at < 1:
        raise AclError(f'The first sequence number must be 1 or more; got {insert_at}. '
                       f'IOS numbers ACL entries from 1.')

    targets = [insert_at + offset for offset in range(len(wanted))]
    taken = dict(entries)

    collisions = [(target, taken[target]) for target in targets if target in taken]
    if collisions:
        raise AclError(
            'Refusing to insert at ' + ', '.join(str(t) for t in targets)
            + f' - {len(collisions)} of those sequence number(s) already hold an entry:\n'
            + '\n'.join(f'  {sequence} {text}' for sequence, text in collisions)
            + '\nIOS would REPLACE each of those in place, silently and with no confirmation, and '
              'the rule that was\nthere would be gone with nothing in the session to say so. '
              'Nothing was pushed.\nPick a free start, or drop the pin and let the run put them in '
              'the gap just below the deny,\nor use --resequence-first to spread the list out '
              'before inserting.')

    if deny_sequence is not None and any(target >= deny_sequence for target in targets):
        past = [target for target in targets if target >= deny_sequence]
        highest_usable = deny_sequence - len(wanted)
        raise AclError(
            'Refusing to insert at ' + ', '.join(str(t) for t in targets)
            + f' - {len(past)} of those sit at or after the deny at sequence {deny_sequence} '
              f'({", ".join(str(t) for t in past)}).\nA standard ACL is first-match, so an entry '
              f'there matches nothing however correct it looks in `show run`. Nothing was '
              f'pushed.\n'
            + (f'Start at {highest_usable} or lower' if highest_usable >= 1
               else f'There is no room below sequence {deny_sequence} for {len(wanted)} entries, '
                    f'so use --resequence-first')
            + ', or drop the pin and let the run pick the numbers\nfrom the gap it reads off the '
              'device.')
    return targets


def plan_insert(entries, permits, insert_at=None):
    """Where each permit goes and at what sequence number.

    Returns (planned, already_present), where planned is
    [(sequence_or_None, 'permit <spec>')] in send order. A None sequence means
    append and let IOS pick last + 10, used only for a list with no explicit
    deny to get in front of; the resequence afterwards tidies whatever it chose
    either way.

    `insert_at` pins the first sequence number, so the entries land at exactly
    insert_at, insert_at + 1, ... Left None they are packed into the gap
    immediately below the first deny instead. See WHERE THE ENTRIES LAND at the
    top of this file for which to use.

    Raises AclError when the gap before the first deny cannot hold the entries,
    or when a pinned number would overwrite one - see pinned_sequences."""
    existing = {normalise_entry(text) for _, text in entries}
    wanted, already = [], []
    for spec in permits:
        (already if normalise_entry(f'permit {spec}') in existing else wanted).append(spec)
    if not wanted:
        return [], already

    deny_sequence, previous = first_deny(entries)

    if insert_at is not None:
        sequences = pinned_sequences(entries, wanted, insert_at, deny_sequence)
        return ([(sequence, f'permit {spec}')
                 for sequence, spec in zip(sequences, wanted)], already)

    if deny_sequence is None:
        # The implicit deny sits past the end of the list, so appending is
        # already in front of it. No room to count.
        return [(None, f'permit {spec}') for spec in wanted], already

    room = deny_sequence - previous - 1
    if room < len(wanted):
        raise AclError(
            f'No room to insert {len(wanted)} entr(ies) before the deny at sequence '
            f'{deny_sequence}: the gap above {previous or "the start of the list"} holds {room}.\n'
            f'Appending them instead would put them after the deny, where they match nothing - '
            f'so nothing was pushed.\nRe-run with --resequence-first to renumber the list before '
            f'inserting, which opens the gap up; the resequence afterwards still runs, so the '
            f'list ends up numbered the same either way.')
    return ([(previous + 1 + offset, f'permit {spec}') for offset, spec in enumerate(wanted)],
            already)


def resequence_command(name, start=DEFAULT_START, increment=DEFAULT_INCREMENT):
    """Global-config, not an EXEC command - it goes in the same send_config_set
    as the ACL block, after the `exit` out of it."""
    return f'ip access-list resequence {name} {start} {increment}'


def snmp_host_command(ip, v3_user):
    """The line this script was written for. `v3_user` is the SNMPv3 username
    IOS resolves to auth/priv keys - see the warning at the top of this file
    about what happens when an ACL name is put there instead."""
    return f'snmp-server host {ip} version 3 priv {v3_user}'


def acl_commands(name, planned):
    """The ACL block. The explicit `exit` closes config-acl mode, because the
    resequence line that follows is a global-config command and Netmiko sends
    this list flat without navigating modes on its own."""
    if not planned:
        return []
    body = [f'{sequence} {text}' if sequence is not None else text
            for sequence, text in planned]
    return [f'ip access-list standard {name}'] + body + ['exit']


def references(output, name):
    """Lines in the running-config that point at the ACL, minus its own
    definition.

    An ACL nothing references filters nothing, which is the difference between
    this run having had an effect and having only looked like one. A `show run
    | include <name>` also returns the `ip access-list standard <name>` header,
    which is the definition rather than a reference, so it is dropped here."""
    found = []
    for line in str(output or '').splitlines():
        line = line.strip()
        if not line or name.lower() not in line.lower():
            continue
        if re.match(rf'(?i)^(ip )?access-list\s+(standard|extended)\s+{re.escape(name)}$', line):
            continue
        found.append(line)
    return found


def vty_references(reference_lines):
    """The subset of references that make this ACL an SSH filter rather than an
    SNMP one. Inserting a permit into one of those grants the NMS a login."""
    return [line for line in reference_lines if re.search(r'(?i)\baccess-class\b', line)]


def snmp_user_present(output, v3_user):
    """Whether `show snmp user` lists the user named on the snmp-server host
    line.

    Read live and not from the running-config on purpose: classic IOS never
    writes `snmp-server user` back into the running-config at all, so a config
    read reports the user missing on every device whether it is or not. NX-OS
    does render it, but `snmp-server host` is IOS syntax and this is a
    cisco_ios script."""
    return bool(re.search(rf'(?mi)^\s*User name:\s*{re.escape(str(v3_user))}\s*$',
                          str(output or '')))


def load_config(snmp):
    """Validate inventory.yaml's `snmp` section into
    (acl_name, permits, hosts, (start, increment), insert_at).

    Every value this script sends comes from here - an address or an ACL name
    written into the script body is one more place a site fact has to be
    corrected. Bad shapes stop the run: an inventory that reads
    `"permits": "192.0.2.10"` instead of a list would otherwise push one permit
    per character."""
    snmp = snmp or {}
    acl_name = str(snmp.get('acl_name') or '').strip()
    if not acl_name:
        raise AclError('inventory.yaml has no snmp.acl_name - the existing named standard ACL to '
                       'insert the permits into. See inventory.yaml.example.')

    raw_permits = snmp.get('permits')
    if not isinstance(raw_permits, list) or not raw_permits:
        raise AclError('inventory.yaml needs snmp.permits as a non-empty LIST of standard-ACL '
                       'source specs, e.g.\n  "permits": ["host 192.0.2.20", '
                       '"192.0.2.0 0.0.0.255"]\nA bare string is pushed one character at a time, '
                       'so it is refused rather than guessed at.')
    permits = [re.sub(r'\s+', ' ', str(spec).strip()) for spec in raw_permits]
    if any(not spec for spec in permits):
        raise AclError('inventory.yaml has a blank entry in snmp.permits.')

    # A mapping of receiver -> username rather than a list of {ip, v3_user}
    # mappings: one receiver cannot be given two users, which is true of
    # `snmp-server host` as well, and the mapping says so in the shape.
    raw_hosts = snmp.get('trap_hosts')
    if raw_hosts is not None and not isinstance(raw_hosts, dict):
        raise AclError('inventory.yaml snmp.trap_hosts must be a MAPPING of receiver address to '
                       'SNMPv3 username, e.g.\n  "trap_hosts": {"192.0.2.20": "SNMPV3_USER"}\n'
                       f'got {type(raw_hosts).__name__}.')
    hosts = []
    for ip, v3_user in (raw_hosts or {}).items():
        ip = str(ip).strip()
        v3_user = str(v3_user or '').strip()
        if not v3_user:
            raise AclError(f'inventory.yaml snmp.trap_hosts["{ip}"] has no SNMPv3 username. That '
                           f'is the trailing field of `snmp-server host {ip} version 3 priv '
                           f'<user>` - the user whose auth/priv keys protect the traps, NOT an '
                           f'ACL name; see the top of snmp_host_acl.py.')
        hosts.append((ip, v3_user))

    resequence = snmp.get('resequence') or {}
    if not isinstance(resequence, dict):
        raise AclError('inventory.yaml snmp.resequence must be a mapping with `start` and '
                       '`increment` keys.')
    try:
        start = int(resequence.get('start', DEFAULT_START))
        increment = int(resequence.get('increment', DEFAULT_INCREMENT))
    except (TypeError, ValueError) as err:
        raise AclError(f'inventory.yaml snmp.resequence takes whole numbers for `start` and '
                       f'`increment`: {err}')
    if start < 1 or increment < 1:
        raise AclError(f'inventory.yaml snmp.resequence needs start and increment of 1 or more; '
                       f'got start {start}, increment {increment}.')

    # Optional. Null means compute the numbers from the gap below the deny
    # instead of pinning them - see WHERE THE ENTRIES LAND.
    insert_at = snmp.get('insert_at')
    if insert_at is not None:
        if isinstance(insert_at, bool) or not isinstance(insert_at, (int, str)):
            raise AclError(f'inventory.yaml snmp.insert_at must be a whole number - the first '
                           f'sequence number the inserted entries take, e.g. 11 for 11, 12, 13 - '
                           f'or null to have it read off the device; got {insert_at!r}.')
        try:
            insert_at = int(insert_at)
        except ValueError:
            raise AclError(f'inventory.yaml snmp.insert_at must be a whole number - the first '
                           f'sequence number the inserted entries take, e.g. 11 for 11, 12, 13 - '
                           f'or null to have it read off the device; got {insert_at!r}.')
        if insert_at < 1:
            raise AclError(f'inventory.yaml snmp.insert_at must be 1 or more; got {insert_at}. '
                           f'IOS numbers ACL entries from 1.')
    return acl_name, permits, hosts, (start, increment), insert_at


def check_applied(entries, permits):
    """Read the ACL back and answer the only two questions that matter: is
    every permit there, and is it in front of the deny.

    The second is not pedantry. An entry that landed after the deny is present
    in `show run`, reported by a naive check as done, and matches nothing - the
    failure this whole script is shaped around, so it is confirmed against the
    device rather than inferred from the commands having been accepted."""
    deny_sequence, _ = first_deny(entries)
    present = {normalise_entry(text): sequence for sequence, text in entries}
    missing, unreachable = [], []
    for spec in permits:
        sequence = present.get(normalise_entry(f'permit {spec}'))
        if sequence is None:
            missing.append(spec)
        elif deny_sequence is not None and sequence > deny_sequence:
            unreachable.append((spec, sequence))
    return missing, unreachable, deny_sequence


def main(argv=None):
    parser = argparse.ArgumentParser(
        description='Push `snmp-server host <ip> version 3 priv <user>` and insert the matching '
                    'permits into an existing named standard ACL, in front of its deny, then '
                    "resequence the list. Reads inventory.yaml's snmp section.")
    parser.add_argument('device', help='Device name as it appears in inventory.yaml (e.g. SWITCH01)')
    parser.add_argument('--insert-at', type=int, metavar='N', dest='insert_at',
                        help='First sequence number for the inserted entries, so three permits '
                             'land at exactly N, N+1, N+2 (--insert-at 11 gives 11, 12, 13). '
                             'Overrides snmp.insert_at. Omit both to have the run pack them into '
                             'the gap just below the first deny instead, which is the same 11, '
                             '12, 13 on a list whose last entry above the deny is 10. A number '
                             'already in use is refused: IOS would silently REPLACE that entry.')
    parser.add_argument('--dry-run', action='store_true',
                        help='Print what would be sent and exit without connecting. With a pinned '
                             'start the exact ACL block is shown; without one the sequence '
                             'numbers depend on the list that is on the device, so only the two '
                             'fixed commands are.')
    parser.add_argument('--resequence-first', action='store_true', dest='resequence_first',
                        help='Renumber the ACL before inserting as well as after. Needed when the '
                             'gap before the deny is too narrow to hold the new entries, which '
                             'the run tells you. Note it moves every existing entry, so a pinned '
                             '--insert-at is applied to the renumbered list.')
    args = parser.parse_args(argv)

    try:
        acl_name, permits, hosts, (start, increment), insert_at = load_config(netauto.load_snmp())
    except AclError as err:
        print(err, file=sys.stderr)
        return 2
    # The flag wins over the inventory, same as --management-subnet does for
    # the audits: a one-off run should not need the file edited.
    if args.insert_at is not None:
        insert_at = args.insert_at
    if insert_at is not None and insert_at < 1:
        print(f'--insert-at must be 1 or more; got {insert_at}. IOS numbers ACL entries from 1.',
              file=sys.stderr)
        return 2

    host_commands = [snmp_host_command(ip, v3_user) for ip, v3_user in hosts]
    resequence = resequence_command(acl_name, start, increment)

    if args.dry_run:
        print('Dry run - nothing was connected to and nothing was pushed.\n')
        print('Notification receivers:')
        for command in host_commands:
            print('  ' + command)
        if not host_commands:
            print('  (none - inventory.yaml snmp.trap_hosts is empty)')
        if insert_at is None:
            print(f'\nInto the existing standard ACL {acl_name}, at free sequence numbers in the '
                  f'gap before its first deny:')
            for spec in permits:
                print(f'  permit {spec}')
            print('\nThe numbers themselves are read off the device - the gap above the deny is a '
                  'fact about that\nswitch, not about the inventory - and entries already present '
                  'are skipped. Pass --insert-at N\nto pin them instead.')
        else:
            print(f'\nInto the existing standard ACL {acl_name}, pinned from sequence {insert_at}:')
            print(f'  ip access-list standard {acl_name}')
            for offset, spec in enumerate(permits):
                print(f'  {insert_at + offset} permit {spec}')
            print('  exit')
            print(f'\nEntries already in the list are skipped, so a run that finds one of these '
                  f'present sends\nfewer lines and the rest shift down. The numbers are refused '
                  f'outright if any is already in use\nor lands at or after the deny - both read '
                  f'off the device.')
        print(f'\nThen, renumbering the list in place without changing its order:\n  {resequence}')
        if args.resequence_first:
            print(f'\n--resequence-first also runs it before the insert:\n  {resequence}')
            if insert_at is not None:
                print(f'Which moves every existing entry first, so sequence {insert_at} means a '
                      f'position in the\nRENUMBERED list - likely not the one it means today.')
        return 0

    all_devices = netauto.load_inventory()
    device_name = args.device
    device_info = netauto.require_devices(all_devices, [device_name])[device_name]
    username, password = netauto.get_credentials()

    connection = netauto.connect(device_name, device_info, username, password)
    if connection is None:
        return 1

    try:
        acl_output = connection.send_command(f'show ip access-lists {acl_name}')
        reference_output = connection.send_command(f'show running-config | include {acl_name}')
        snmp_user_output = connection.send_command('show snmp user')

        try:
            entries = parse_acl(acl_output, acl_name)
        except AclError as err:
            print(f'\n{err}', file=sys.stderr)
            return 2

        print(f'\n{acl_name} on {device_name}, before any change:')
        for sequence, text in entries:
            print(f'  {sequence:>5} {text}')
        if not entries:
            print('  (defined but empty - the implicit deny is all it does today)')

        # What references the ACL, printed before the push rather than after:
        # whether this run has any effect at all, and whether it is an SNMP
        # filter or an SSH one, are both answered here.
        reference_lines = references(reference_output, acl_name)
        if reference_lines:
            print('\nReferenced by:')
            for line in reference_lines:
                print('  ' + netauto.redact_secrets(line))
        else:
            print(f'\nNOTHING references {acl_name} on {device_name}. The permits below will be '
                  f'inserted and will filter nothing:\nan SNMPv3 ACL takes effect through '
                  f'`snmp-server group <group> v3 priv access {acl_name}`, which this script does '
                  f'not push.\nThe insert is still correct; it is just not yet doing anything.')

        on_vty = vty_references(reference_lines)
        if on_vty:
            print(f'\nWARNING: {acl_name} is a vty access-class, so it filters SSH logins to '
                  f'{device_name}, not SNMP polling:')
            for line in on_vty:
                print('  ' + line)
            print('Inserting a permit here grants those sources interactive access to the device. '
                  'If that was not\nthe intent, stop now and point snmp.acl_name at the ACL that '
                  'SNMP actually uses.')

        try:
            if args.resequence_first:
                connection.send_config_set([resequence])
                netauto.log_push('snmp_host_acl.py', device_name, username, [resequence])
                print(f'\nRenumbered {acl_name} to {start}/{increment} before inserting '
                      f'(--resequence-first).')
                entries = parse_acl(
                    connection.send_command(f'show ip access-lists {acl_name}'), acl_name)
                print(f'{acl_name} is now:')
                for sequence, text in entries:
                    print(f'  {sequence:>5} {text}')
            planned, already = plan_insert(entries, permits, insert_at)
        except AclError as err:
            print(f'\n{err}', file=sys.stderr)
            return 2

        if already:
            print(f'\nAlready in {acl_name}, left alone:')
            for spec in already:
                print(f'  permit {spec}')

        commands = host_commands + acl_commands(acl_name, planned)
        # The resequence runs even when nothing was inserted: the list still
        # carries whatever numbering it had, and tidying it changes no access
        # decision, so a re-run that only renumbers is harmless.
        commands.append(resequence)

        connection.send_config_set(commands)
        netauto.log_push('snmp_host_acl.py', device_name, username, commands)

        print(f'\nPushed to {device_name}:')
        for command in commands:
            print('  ' + netauto.redact_secrets(command))

        # Read back, because "the commands were accepted" and "the permits are
        # reachable" are different claims and only the second one is the job.
        final = parse_acl(connection.send_command(f'show ip access-lists {acl_name}'), acl_name)
        print(f'\n{acl_name} on {device_name}, after:')
        for sequence, text in final:
            print(f'  {sequence:>5} {text}')

        missing, unreachable, deny_sequence = check_applied(final, permits)
        failed = False
        if missing:
            failed = True
            print(f'\nFAILED: {len(missing)} permit(s) are not in {acl_name} after the push - the '
                  f'device rejected them:', file=sys.stderr)
            for spec in missing:
                print(f'  permit {spec}', file=sys.stderr)
        if unreachable:
            failed = True
            print(f'\nFAILED: {len(unreachable)} permit(s) landed AFTER the deny at sequence '
                  f'{deny_sequence} and match nothing:', file=sys.stderr)
            for spec, sequence in unreachable:
                print(f'  {sequence} permit {spec}', file=sys.stderr)
            print(f'Remove them with `no <sequence>` under `ip access-list standard {acl_name}` '
                  f'and re-run.', file=sys.stderr)
        if failed:
            return 1

        if deny_sequence is not None:
            print(f'\nAll {len(permits)} permit(s) are present and sit before the deny at '
                  f'sequence {deny_sequence}, so they are reachable.')
        else:
            print(f'\nAll {len(permits)} permit(s) are present. {acl_name} has no explicit deny, '
                  f'so only the implicit one follows them.')

        # The one check the running-config cannot answer, and the reason it is
        # read live: classic IOS never writes `snmp-server user` back out, so
        # `show snmp user` is the only place the user's existence shows.
        for ip, v3_user in hosts:
            if snmp_user_present(snmp_user_output, v3_user):
                print(f'  SNMPv3 user {v3_user} exists - traps to {ip} will be signed and '
                      f'encrypted with its keys.')
            else:
                print(f'\nWARNING: `show snmp user` does not list {v3_user}, named on '
                      f'`snmp-server host {ip} version 3 priv {v3_user}`.\nIOS accepted that line '
                      f'and will silently drop every notification to {ip} until the user '
                      f'exists.\nIf {v3_user} was meant to be an ACL name, it is in the wrong '
                      f'place - `snmp-server host` has no ACL field; see the top of this '
                      f'script.\nCreate the user with `snmp-server user {v3_user} <group> v3 '
                      f'auth sha <key> priv aes 128 <key>`, or run l2_stig_harden_global.py / '
                      f'ios_router_stig_harden_global.py, which push it from secrets.yaml.')

        print('\nNothing here was written to startup-config. Confirm the ACL above is what you '
              'wanted, then run save_config.py.')
        return 0
    finally:
        connection.disconnect()


if __name__ == '__main__':
    sys.exit(main())
