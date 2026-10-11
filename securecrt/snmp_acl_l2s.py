# $language = "Python3"
# $interface = "1.0"

"""Point one switch's SNMPv3 notifications at a receiver and insert the
matching permits into its EXISTING named standard ACL - in front of the deny,
not after it - then resequence the list. Run from the one session that is
already open (Script > Run...). This is the production first step:
snmp_acl_l2s_bulk.py does the same thing across every saved session once this
has been seen to work on one switch.

READ THIS FIRST - THIS SCRIPT CONFIGURES THE SWITCH
It writes to running-config. It shows the ACL as it is now and the exact
commands it will send, sequence numbers included, and sends nothing until you
say Yes. It never writes startup-config: until someone saves, a reload puts
the switch back as it was.

WHY IT EXISTS ALONGSIDE scripts/snmp_host_acl.py
That script does the same job over netmiko, and netmiko cannot be installed on
the machine the switches are reachable from. Same commands, same refusals, same
read-back. Its docstring has the full reasoning - why the permits go in front
of the deny, why a pinned sequence number in use is refused, why the
resequence comes last, and why the trailing field of `snmp-server host` is a
USERNAME and not an ACL name. The ACL logic is duplicated below rather than
imported because nothing in securecrt/ may import from the wider repository,
and tests/test_securecrt_snmp_acl.py runs both copies over the same lists and
fails if they ever answer differently.

WHERE THE SETTINGS COME FROM
inventory.yaml's `snmp` section - acl_name, permits, trap_hosts, insert_at,
resequence - the same file and keys the netmiko script reads. It is JSON, so
the standard library reads it. If it is not beside this folder the run asks
for its path; nothing is typed in per switch, because a permit typed by hand
on switch four hundred is how a digit ends up wrong.

THE VERDICT
The run ends with one verdict for the switch, from the ACL read back after the
push rather than from the commands having been accepted:

  completed   every permit is in the list and in front of the deny, and no
              command was rejected. Warnings (nothing references the ACL; the
              SNMPv3 user does not exist) ride along without changing that.
  failed      something was pushed and the read-back disagrees - a permit
              missing, a permit past the deny, or a rejected line.
  skipped     nothing was pushed: the ACL is not there, is extended, has no
              room before its deny, or a pinned number is already in use.

The same row is written to a CSV in OUTPUT_DIR, so the production switch has a
record alongside the bulk run's.
"""

import os
import os.path
import re
import time

# `crt` is injected by SecureCRT into this script's globals, not into the
# modules it imports - so those get it handed over at the bottom of this file.
crt = globals().get('crt')

import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import capture_l2s
import capture_l2s_bulk as bulk
import harden_l2s_bulk as harden


# Where the run log is written. Created if missing.
OUTPUT_DIR = r'C:\Documents\netauto_snmp'

LOG_COLUMNS = ('hostname', 'ip_address', 'outcome', 'reason', 'inserted', 'warnings',
               'acl_after', 'session', 'timestamp')

COMPLETED = 'completed'
FAILED = 'failed'
SKIPPED = 'skipped'

# The one AclError a renumber fixes without changing what the list means: an
# unpinned insert with no room under the deny. Renumbering keeps the order and
# changes no access decision, and the resequence at the end runs regardless.
NO_ROOM = 'no room before the deny'


# ---------------------------------------------------------------------------
# The ACL logic. Kept equal to scripts/snmp_host_acl.py - see the docstring and
# the parity test. The reasoning lives there; only what differs is noted here.
# ---------------------------------------------------------------------------

ENTRY_RE = re.compile(r'^\s*(\d+)\s+(permit|deny)\b(.*)$', re.IGNORECASE)
UNNUMBERED_ENTRY_RE = re.compile(r'^\s*(permit|deny)\b', re.IGNORECASE)
HEADER_RE = re.compile(r'^\s*(Standard|Extended)\s+IP\s+access\s+list\s+(\S+)',
                       re.IGNORECASE | re.MULTILINE)
MATCH_COUNT_RE = re.compile(r'\(\d+\s+matches?\)\s*$')

DEFAULT_START = 10
DEFAULT_INCREMENT = 10


class AclError(Exception):
    """The ACL makes the insert wrong. Unlike the netmiko script's, this one
    carries a short `.reason` as well as the full message - the same split as
    capture_l2s.CollectionError - because a bulk run writes one line per switch
    and the full explanation belongs in a dialog."""

    def __init__(self, reason, message):
        Exception.__init__(self, message)
        self.reason = reason


def normalise_entry(text):
    text = MATCH_COUNT_RE.sub('', str(text)).strip().lower()
    text = text.replace(', wildcard bits ', ' ')
    text = re.sub(r'\bhost\s+', '', text)
    return re.sub(r'\s+', ' ', text).strip()


def parse_acl(output, name):
    """[(sequence, 'permit|deny <body>')] in list order. Raises rather than
    returning [] for an ACL that is missing, extended, or unnumbered - an empty
    list there would append every permit after the deny."""
    text = str(output or '')
    header = None
    for kind, listed_name in HEADER_RE.findall(text):
        if listed_name.lower() == str(name).lower():
            header = kind.lower()
            break
    if header is None:
        raise AclError(
            'ACL not defined',
            '{0} is not defined on this switch - `show ip access-lists {0}` returned no list '
            'by that name.\n\nThis inserts into an ACL that already exists; it does not create '
            'one. Create it first, or fix snmp.acl_name in inventory.yaml.'.format(name))
    if header != 'standard':
        raise AclError(
            'ACL is extended',
            '{0} exists on this switch as an EXTENDED list, and snmp.permits are standard-list '
            'entries.\n\nIOS rejects `ip access-list standard {0}` against an extended list of '
            'the same name, so nothing would land. Point snmp.acl_name at the standard list.'
            .format(name))

    entries = []
    unnumbered = 0
    for line in text.splitlines():
        if HEADER_RE.match(line):
            continue
        match = ENTRY_RE.match(line)
        if match:
            body = MATCH_COUNT_RE.sub('', match.group(3)).strip()
            entries.append((int(match.group(1)), '{0} {1}'.format(match.group(2).lower(),
                                                                  body).strip()))
        elif UNNUMBERED_ENTRY_RE.match(line):
            unnumbered += 1

    if unnumbered and not entries:
        raise AclError(
            'ACL has no sequence numbers',
            '{0} has {1} entr(ies) and this image shows none of them with a sequence number.\n\n'
            'Without numbers there is nothing to insert between and nothing to resequence. '
            'Fix the list by hand on this switch.'.format(name, unnumbered))
    return entries


def first_deny(entries):
    previous = 0
    for sequence, text in entries:
        if text.startswith('deny'):
            return sequence, previous
        previous = sequence
    return None, previous


def pinned_sequences(entries, wanted, insert_at, deny_sequence):
    """insert_at, insert_at + 1, ... checked against the list on the switch.
    A number already in use is refused: IOS would REPLACE that entry, silently."""
    if insert_at < 1:
        raise AclError('insert_at below 1',
                       'snmp.insert_at must be 1 or more; got {0}.'.format(insert_at))

    targets = [insert_at + offset for offset in range(len(wanted))]
    taken = dict(entries)

    collisions = [(target, taken[target]) for target in targets if target in taken]
    if collisions:
        raise AclError(
            'pinned sequence number already in use',
            'Refusing to insert at ' + ', '.join(str(t) for t in targets)
            + ' - {0} of those already hold an entry:\n'.format(len(collisions))
            + '\n'.join('  {0} {1}'.format(sequence, text) for sequence, text in collisions)
            + '\n\nIOS would REPLACE each of those in place, with no warning. Nothing was '
              'sent.\nChange snmp.insert_at to a free number, or set it to null to have the '
              'run use the gap below the deny.')

    if deny_sequence is not None and any(target >= deny_sequence for target in targets):
        past = [target for target in targets if target >= deny_sequence]
        highest_usable = deny_sequence - len(wanted)
        raise AclError(
            'pinned sequence number at or after the deny',
            'Refusing to insert at ' + ', '.join(str(t) for t in targets)
            + ' - {0} of those sit at or after the deny at {1}.\nAn entry there matches '
              'nothing. Nothing was sent.\n'.format(len(past), deny_sequence)
            + ('Set snmp.insert_at to {0} or lower'.format(highest_usable) if highest_usable >= 1
               else 'There is no room below {0} for {1} entries'.format(deny_sequence,
                                                                         len(wanted)))
            + ', or to null to have the run use the gap below the deny.')
    return targets


def plan_insert(entries, permits, insert_at=None):
    """(planned, already_present). planned is [(sequence or None, 'permit <spec>')]."""
    existing = {normalise_entry(text) for _, text in entries}
    wanted, already = [], []
    for spec in permits:
        (already if normalise_entry('permit ' + spec) in existing else wanted).append(spec)
    if not wanted:
        return [], already

    deny_sequence, previous = first_deny(entries)

    if insert_at is not None:
        sequences = pinned_sequences(entries, wanted, insert_at, deny_sequence)
        return ([(sequence, 'permit ' + spec) for sequence, spec in zip(sequences, wanted)],
                already)

    if deny_sequence is None:
        return [(None, 'permit ' + spec) for spec in wanted], already

    room = deny_sequence - previous - 1
    if room < len(wanted):
        raise AclError(
            NO_ROOM,
            'No room to insert {0} entr(ies) before the deny at {1}: the gap above {2} holds '
            '{3}.\n\nAppending them would put them after the deny, where they match nothing, '
            'so nothing was sent. Renumbering the list first opens the gap without changing '
            'its order.'.format(len(wanted), deny_sequence, previous or 'the start of the list',
                                room))
    return ([(previous + 1 + offset, 'permit ' + spec) for offset, spec in enumerate(wanted)],
            already)


def resequence_command(name, start=DEFAULT_START, increment=DEFAULT_INCREMENT):
    return 'ip access-list resequence {0} {1} {2}'.format(name, start, increment)


def snmp_host_command(ip, v3_user):
    return 'snmp-server host {0} version 3 priv {1}'.format(ip, v3_user)


def acl_commands(name, planned):
    if not planned:
        return []
    body = ['{0} {1}'.format(sequence, text) if sequence is not None else text
            for sequence, text in planned]
    return ['ip access-list standard {0}'.format(name)] + body + ['exit']


def references(output, name):
    found = []
    for line in str(output or '').splitlines():
        line = line.strip()
        if not line or name.lower() not in line.lower():
            continue
        if re.match(r'(?i)^(ip )?access-list\s+(standard|extended)\s+{0}$'.format(re.escape(name)),
                    line):
            continue
        found.append(line)
    return found


def vty_references(reference_lines):
    return [line for line in reference_lines if re.search(r'(?i)\baccess-class\b', line)]


def snmp_user_present(output, v3_user):
    return bool(re.search(r'(?mi)^\s*User name:\s*{0}\s*$'.format(re.escape(str(v3_user))),
                          str(output or '')))


def load_config(snmp):
    """(acl_name, permits, hosts, (start, increment), insert_at) from the
    inventory's snmp section. Bad shapes stop the run before anything is sent."""
    snmp = snmp or {}
    acl_name = str(snmp.get('acl_name') or '').strip()
    if not acl_name:
        raise AclError('no snmp.acl_name',
                       'inventory.yaml has no snmp.acl_name - the existing named standard ACL '
                       'to insert the permits into.')

    raw_permits = snmp.get('permits')
    if not isinstance(raw_permits, list) or not raw_permits:
        raise AclError('snmp.permits not a list',
                       'inventory.yaml needs snmp.permits as a non-empty LIST, e.g.\n'
                       '  "permits": ["host 192.0.2.20", "192.0.2.0 0.0.0.255"]\n'
                       'A bare string would be pushed one character at a time.')
    permits = [re.sub(r'\s+', ' ', str(spec).strip()) for spec in raw_permits]
    if any(not spec for spec in permits):
        raise AclError('blank permit', 'inventory.yaml has a blank entry in snmp.permits.')

    raw_hosts = snmp.get('trap_hosts')
    if raw_hosts is not None and not isinstance(raw_hosts, dict):
        raise AclError('snmp.trap_hosts not a mapping',
                       'inventory.yaml snmp.trap_hosts must be a MAPPING of receiver address '
                       'to SNMPv3 username, e.g.\n  "trap_hosts": {"192.0.2.20": "SNMPV3_USER"}')
    hosts = []
    for ip, v3_user in (raw_hosts or {}).items():
        ip = str(ip).strip()
        v3_user = str(v3_user or '').strip()
        if not v3_user:
            raise AclError('trap host with no username',
                           'inventory.yaml snmp.trap_hosts["{0}"] has no SNMPv3 username. It is '
                           'the user whose keys protect the traps, NOT an ACL name.'.format(ip))
        hosts.append((ip, v3_user))

    resequence = snmp.get('resequence') or {}
    if not isinstance(resequence, dict):
        raise AclError('bad snmp.resequence',
                       'inventory.yaml snmp.resequence must be a mapping with `start` and '
                       '`increment`.')
    try:
        start = int(resequence.get('start', DEFAULT_START))
        increment = int(resequence.get('increment', DEFAULT_INCREMENT))
    except (TypeError, ValueError) as err:
        raise AclError('bad snmp.resequence',
                       'inventory.yaml snmp.resequence takes whole numbers: {0}'.format(err))
    if start < 1 or increment < 1:
        raise AclError('bad snmp.resequence',
                       'inventory.yaml snmp.resequence needs start and increment of 1 or more.')

    insert_at = snmp.get('insert_at')
    if insert_at is not None:
        bad = AclError('bad snmp.insert_at',
                       'inventory.yaml snmp.insert_at must be a whole number of 1 or more - '
                       'e.g. 11 for 11, 12, 13 - or null; got {0!r}.'.format(insert_at))
        if isinstance(insert_at, bool) or not isinstance(insert_at, (int, str)):
            raise bad
        try:
            insert_at = int(insert_at)
        except ValueError:
            raise bad
        if insert_at < 1:
            raise bad
    return acl_name, permits, hosts, (start, increment), insert_at


def check_applied(entries, permits):
    """(missing, unreachable, deny_sequence), from the list read back."""
    deny_sequence, _ = first_deny(entries)
    present = {normalise_entry(text): sequence for sequence, text in entries}
    missing, unreachable = [], []
    for spec in permits:
        sequence = present.get(normalise_entry('permit ' + spec))
        if sequence is None:
            missing.append(spec)
        elif deny_sequence is not None and sequence > deny_sequence:
            unreachable.append((spec, sequence))
    return missing, unreachable, deny_sequence


# ---------------------------------------------------------------------------
# The inventory, read with the standard library.
# ---------------------------------------------------------------------------

def inventory_path():
    """The repository's inventory.yaml, if this folder is still inside it."""
    return os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        'inventory.yaml')


def read_settings(path):
    """load_config() of the file's snmp section. inventory.yaml is JSON, so
    json reads it - see the netmiko side's yaml.py."""
    import json
    try:
        with open(path, encoding='utf-8') as handle:
            inventory = json.load(handle)
    except (OSError, ValueError) as error:
        raise AclError('inventory not readable',
                       'Could not read {0}:\n{1}'.format(path, error))
    return load_config(inventory.get('snmp'))


def settings_from_inventory():
    """The settings, asking for the file's path only when it is not where the
    repository keeps it. Returns None if the person cancelled."""
    path = inventory_path()
    if not os.path.exists(path):
        path = crt.Dialog.Prompt(
            'inventory.yaml was not found beside this folder:\n  {0}\n\n'
            'Path to the inventory.yaml whose `snmp` section to push:'.format(inventory_path()),
            'SNMP ACL - inventory', '', False)
        if not path:
            return None
    return read_settings(path.strip().strip('"'))


# ---------------------------------------------------------------------------
# One switch.
# ---------------------------------------------------------------------------

# A syslog message (`%SYS-5-CONFIG_I: Configured from ...`) also starts with
# '%' and is not a rejection. Left in, `end` on a session with `terminal
# monitor` would fail every switch.
SYSLOG_MESSAGE = re.compile(r'%[A-Z0-9_]+-\d-[A-Z0-9_]+:')


def rejected_lines(transcript):
    return [line for line in harden.rejected_lines(transcript)
            if not SYSLOG_MESSAGE.search(line)]


class Result:
    """What happened to one switch. `reason` is the short form for the log;
    `detail` is the full text for a dialog."""

    def __init__(self, outcome, reason='', detail='', hostname=''):
        self.outcome = outcome
        self.reason = reason
        # Falls back to reason when shown, not here: reason is usually filled
        # in after the Result exists.
        self.detail = detail
        self.hostname = hostname
        self.before = []
        self.after = []
        self.references = []
        self.commands = []
        self.planned = []
        self.already = []
        self.warnings = []
        # Set when the list was renumbered before the insert. That command has
        # already gone by the time anyone is asked about the rest.
        self.renumbered = ''

    def inserted(self):
        return '; '.join('{0} {1}'.format(sequence, text) if sequence is not None else text
                         for sequence, text in self.planned)


def render_acl(entries):
    return '\n'.join('  {0:>5} {1}'.format(sequence, text) for sequence, text in entries) \
        or '  (defined but empty)'


def apply(prompt, settings, renumber_if_no_room=False, confirm=None, refuse_vty=False):
    """Read, plan, push and read back on the switch behind `prompt`.

    `confirm(result)` is shown the plan before anything is sent and returns
    whether to go ahead - the single-switch run's dialog. The bulk run passes
    None, having been confirmed once for the whole list, and refuse_vty=True,
    because the vty warning a person reads here would go unread there.

    Raises capture_l2s.CollectionError for a session that is not a usable
    switch; every ACL problem comes back as a Result instead."""
    acl_name, permits, hosts, (start, increment), insert_at = settings
    if not prompt.endswith('#'):
        raise capture_l2s.CollectionError(
            'user EXEC mode' if prompt.endswith('>') else 'unexpected prompt',
            'This session is not in privileged EXEC ({0}). Run "enable" first.'.format(prompt),
            'Not in enable mode')
    hostname = prompt.rstrip('#').strip()
    reply = capture_l2s.run_command('terminal length 0', prompt)
    wrong_device = capture_l2s.not_a_switch(reply)
    if wrong_device:
        raise capture_l2s.CollectionError(
            'not a Cisco switch: ' + wrong_device,
            'This session does not look like a Cisco switch:\n  {0}'.format(wrong_device),
            'Not a Cisco switch')

    show_acl = 'show ip access-lists ' + acl_name
    reference_output = capture_l2s.run_command('show running-config | include ' + acl_name,
                                               prompt)
    user_output = capture_l2s.run_command('show snmp user', prompt)
    try:
        entries = parse_acl(capture_l2s.run_command(show_acl, prompt), acl_name)
    except AclError as error:
        return Result(SKIPPED, error.reason, str(error), hostname)

    result = Result(COMPLETED, hostname=hostname)
    result.before = entries
    result.references = references(reference_output, acl_name)
    on_vty = vty_references(result.references)
    if on_vty and refuse_vty:
        result.outcome, result.reason = SKIPPED, 'ACL is a vty access-class'
        result.detail = ('{0} filters SSH logins here ({1}); a permit in it grants a login, not '
                         'polling. Left alone.'.format(acl_name, '; '.join(on_vty)))
        return result

    resequence = resequence_command(acl_name, start, increment)
    try:
        result.planned, result.already = plan_insert(entries, permits, insert_at)
    except AclError as error:
        if not (error.reason == NO_ROOM and renumber_if_no_room):
            result.outcome, result.reason, result.detail = SKIPPED, error.reason, str(error)
            return result
        # Renumbered, then read again rather than predicted: the numbers the
        # insert uses must be the ones on the switch.
        transcript = harden.send_config([resequence], prompt)
        result.renumbered = resequence
        if rejected_lines(transcript):
            result.outcome, result.reason = FAILED, 'resequence rejected'
            result.detail = '; '.join(rejected_lines(transcript))
            return result
        try:
            entries = parse_acl(capture_l2s.run_command(show_acl, prompt), acl_name)
            result.planned, result.already = plan_insert(entries, permits, insert_at)
        except AclError as again:
            result.outcome, result.reason, result.detail = FAILED, again.reason, str(again)
            return result

    if not result.references:
        result.warnings.append('nothing references {0}, so it filters nothing yet'
                               .format(acl_name))
    if on_vty:
        result.warnings.append('{0} is a vty access-class - these permits grant SSH'
                               .format(acl_name))
    for ip, v3_user in hosts:
        if not snmp_user_present(user_output, v3_user):
            result.warnings.append('SNMPv3 user {0} does not exist - traps to {1} are dropped'
                                   .format(v3_user, ip))

    result.commands = [snmp_host_command(ip, user) for ip, user in hosts] \
        + acl_commands(acl_name, result.planned) + [resequence]
    if confirm is not None and not confirm(result):
        result.outcome = SKIPPED
        result.reason = ('cancelled - the list was renumbered, nothing else sent'
                         if result.renumbered else 'cancelled - nothing sent')
        return result

    transcript = harden.send_config(result.commands, prompt)
    rejected = rejected_lines(transcript)

    # Read back: "accepted" and "in front of the deny" are different claims.
    try:
        result.after = parse_acl(capture_l2s.run_command(show_acl, prompt), acl_name)
    except AclError as error:
        result.outcome, result.reason, result.detail = FAILED, 'read-back: ' + error.reason, \
            str(error)
        return result
    missing, unreachable, deny_sequence = check_applied(result.after, permits)

    problems = []
    if rejected:
        problems.append('rejected: ' + '; '.join(rejected))
    if missing:
        problems.append('not in the list after the push: ' + '; '.join(missing))
    if unreachable:
        problems.append('after the deny at {0}: {1}'.format(
            deny_sequence, '; '.join('{0} permit {1}'.format(seq, spec)
                                     for spec, seq in unreachable)))
    if problems:
        result.outcome, result.reason = FAILED, ' | '.join(problems)
    else:
        result.reason = ('all {0} permit(s) in front of the deny at {1}'.format(
            len(permits), deny_sequence) if deny_sequence is not None
            else 'all {0} permit(s) present; no explicit deny'.format(len(permits)))
    return result


# ---------------------------------------------------------------------------
# The record and the verdict.
# ---------------------------------------------------------------------------

class RunLog:
    """One row per switch, the same columns for the single run and the bulk
    one, so a production change and the fleet run read the same way."""

    def __init__(self, directory, stem='snmp_acl_log_'):
        self.path = bulk.unused_path(directory, stem + time.strftime('%Y%m%d_%H%M%S'), '.csv')
        self.counts = {}
        self.warned = 0
        with open(self.path, 'w', encoding='utf-8') as handle:
            handle.write(','.join(LOG_COLUMNS) + '\n')

    def record(self, session_path, host, outcome, reason='', hostname='', result=None):
        self.counts[outcome] = self.counts.get(outcome, 0) + 1
        inserted = warnings = after = ''
        if result is not None:
            inserted = result.inserted()
            warnings = '; '.join(result.warnings)
            after = '; '.join('{0} {1}'.format(seq, text) for seq, text in result.after)
            if outcome == COMPLETED and result.warnings:
                self.warned += 1
        row = (hostname or session_path, host, outcome, reason, inserted, warnings, after,
               session_path, time.strftime('%Y-%m-%d %H:%M:%S'))
        with open(self.path, 'a', encoding='utf-8') as handle:
            handle.write(','.join('"{0}"'.format(str(f).replace('"', "'")) for f in row) + '\n')


def verdict(counts, total, warned=0):
    """The run in one paragraph: how many switches it completed out of how many
    it was pointed at, then what happened to the rest.

    `total` is the number of distinct switches, so a duplicate session is not a
    switch the run failed to finish. `failed` is named apart from the others
    because it is the one where something WAS sent - every other outcome left
    the switch as it was."""
    completed = counts.get(COMPLETED, 0)
    lines = ['Completed on {0} of {1} switch(es).'.format(completed, total)]
    if warned:
        lines.append('  {0} of those completed with a warning - see the warnings column.'
                     .format(warned))
    if counts.get(FAILED):
        lines.append('FAILED on {0}: commands were sent and the read-back disagrees.'
                     .format(counts[FAILED]))
    others = sorted((name, n) for name, n in counts.items()
                    if name not in (COMPLETED, FAILED, 'duplicate'))
    if others:
        lines.append('Not changed: ' + ', '.join('{0} {1}'.format(name, n) for name, n in others)
                     + '.')
    if counts.get('duplicate'):
        lines.append('{0} duplicate session(s) collapsed, not counted.'.format(counts['duplicate']))
    return '\n'.join(lines)


def make_log(directory, stem='snmp_acl_log_'):
    """A RunLog, or None with the reason if the folder cannot be written."""
    try:
        if not os.path.isdir(directory):
            os.makedirs(directory)
        return RunLog(directory, stem), ''
    except OSError as error:
        return None, str(error)


# ---------------------------------------------------------------------------
# The single-switch run.
# ---------------------------------------------------------------------------

MB_YESNO = 4
MB_ICONWARNING = 48
MB_DEFBUTTON2 = 256
IDYES = 6


def confirm_dialog(result, settings):
    acl_name = settings[0]
    lines = ['{0}: {1} as it is now:'.format(result.hostname, acl_name), render_acl(result.before),
             '']
    lines.append('Referenced by:\n' + '\n'.join('  ' + line for line in result.references)
                 if result.references else 'NOTHING references {0} - the permits will filter '
                                           'nothing until `snmp-server group <group> v3 priv '
                                           'access {0}` exists.'.format(acl_name))
    if result.already:
        lines.append('\nAlready in the list, left alone:\n'
                     + '\n'.join('  permit ' + spec for spec in result.already))
    if result.renumbered:
        lines.append('\nAlready sent, as agreed: ' + result.renumbered)
    lines.append('\nCommands to send:\n' + '\n'.join('  ' + c for c in result.commands))
    flags = MB_YESNO | MB_ICONWARNING
    on_vty = vty_references(result.references)
    if on_vty:
        # The one case where Yes is the wrong answer more often than not, so
        # it is not the default button.
        flags |= MB_DEFBUTTON2
        lines.append('\nWARNING: {0} is a vty access-class ({1}). These permits would grant '
                     'SSH logins, not SNMP polling.'.format(acl_name, '; '.join(on_vty)))
    lines.append('\nThis writes to running-config. startup-config is NOT written.\n\nSend?')
    return crt.Dialog.MessageBox('\n'.join(lines), 'SNMP ACL - confirm', flags) == IDYES


def report(result):
    title = {COMPLETED: 'SNMP ACL - COMPLETED', FAILED: 'SNMP ACL - FAILED'}.get(
        result.outcome, 'SNMP ACL - not changed')
    lines = ['Verdict for {0}: {1}'.format(result.hostname or 'this switch',
                                           result.outcome.upper()), '',
             result.detail or result.reason]
    if result.after:
        lines += ['', 'The list now:', render_acl(result.after)]
    if result.warnings:
        lines += ['', 'Warnings:'] + ['  ' + w for w in result.warnings]
    if result.outcome == COMPLETED:
        lines += ['', 'Nothing was written to startup-config. Check the list, then save. '
                      'Once this switch looks right, snmp_acl_l2s_bulk.py does the rest.']
    return title, '\n'.join(lines)


def main():
    if not crt.Session.Connected:
        crt.Dialog.MessageBox('Connect and log in to the switch first, then run this script.',
                              'Not connected')
        return
    try:
        settings = settings_from_inventory()
    except AclError as error:
        crt.Dialog.MessageBox('{0}\n\nNothing was sent.'.format(error), 'SNMP ACL - inventory')
        return
    if settings is None:
        return

    crt.Screen.Synchronous = True
    try:
        try:
            prompt = capture_l2s.read_prompt()
            result = apply(prompt, settings,
                           confirm=lambda planned: confirm_dialog(planned, settings))
            if result.reason == NO_ROOM and crt.Dialog.MessageBox(
                    '{0}\n\nRenumber {1} first and try again? Its order is kept, and it is '
                    'renumbered at the end either way.'.format(result.detail, settings[0]),
                    'SNMP ACL - no room', MB_YESNO) == IDYES:
                result = apply(prompt, settings, renumber_if_no_room=True,
                               confirm=lambda planned: confirm_dialog(planned, settings))
        except capture_l2s.CollectionError as refused:
            crt.Dialog.MessageBox('{0}\n\nNothing was sent.'.format(refused), refused.title)
            return

        log, why = make_log(OUTPUT_DIR)
        session = ''
        try:
            session = crt.Session.Path
        except Exception:
            pass
        if log is not None:
            log.record(session, '', result.outcome, result.reason, result.hostname, result)
        title, text = report(result)
        text += ('\n\nLogged to:\n' + log.path) if log is not None \
            else '\n\nNot logged - could not write {0}: {1}'.format(OUTPUT_DIR, why)
        crt.Dialog.MessageBox(text, title)
    except Exception as error:  # surfaced in a dialog; SecureCRT hides tracebacks
        crt.Dialog.MessageBox(str(error), 'SNMP ACL - error')
    finally:
        crt.Screen.Synchronous = False


# SecureCRT injects `crt` before running, so this is truthy there and None on a
# plain import - which is what lets the bulk walk and the tests import this.
if crt is not None:
    capture_l2s.crt = crt
    bulk.crt = crt
    harden.crt = crt
    main()
