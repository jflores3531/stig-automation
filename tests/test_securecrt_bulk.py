#!/usr/bin/env python
"""Verification for securecrt/capture_l2s_bulk.py - the unattended walker.

Run it directly: `python3 tests/test_securecrt_bulk.py`. No framework, no
SecureCRT, no devices.

What this is guarding. The walker runs for hours with nobody watching, against
production switches, and its output is a compliance result someone signs. The
failure that matters is not a crash - a crash is visible. It is a run that
finishes looking healthy while quietly leaving switches out, or writing captures
that are not what they claim to be. So the checks here are mostly about the
run log being a truthful account of what happened to every session in the list:
offline ones skipped rather than fatal, rejected logins tried twice and no more,
duplicates collapsed on purpose rather than by accident, and a resumed run
picking up exactly what the first one missed.

Since it audits what it collects, two more failures belong here. A switch whose
hostname another switch already used would land on that one's checklist -
silently, one file where there should be two. And a machine that cannot run the
audit at all has to be found out before the walk, not six hundred connections
into it.
"""

import io
import json
import os
import re
import sys
import tempfile

PROJECT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(PROJECT, 'scripts'))
sys.path.insert(0, os.path.join(PROJECT, 'securecrt'))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import capture
import capture_l2s
import capture_l2s_bulk as bulk
from fixtures import OUTPUTS

failures = []


def check(name, condition, detail=''):
    print(f'  {"ok  " if condition else "FAIL"} {name}')
    if not condition:
        if detail:
            print(f'       {detail}')
        failures.append(name)


# A line of the DoD notice and consent banner, ruled off in the '#' a prompt
# also ends with - which is exactly why read_prompt() requires the cursor's own
# line to end in one rather than merely contain one.
BANNER_LINE = '#### You are accessing a U.S. Government (USG) Information System ####'


class FakeScreen:
    """Replays fixture output command by command, echoing like a real device.

    `banner_lines` is how many screen reads land mid-banner before the prompt
    appears - what a switch hardened to this STIG actually does to a session
    that connects and reads straight away."""

    def __init__(self, host_outputs, banner_lines=0):
        self.host_outputs = host_outputs
        self.Synchronous = False
        self.prompt = 'SW#'
        self.banner_lines = banner_lines
        self._pending = ''
        self.CurrentRow = 5
        self.CurrentColumn = len(self.prompt) + 1

    def Get(self, *_args):
        if self.banner_lines > 0:
            self.banner_lines -= 1
            return BANNER_LINE
        return self.prompt

    def Send(self, text):
        command = text.rstrip('\r\n')
        # A bare carriage return is read_prompt() asking for a fresh prompt,
        # not a command - a real switch answers it with one and nothing else.
        if not command:
            return
        body = '' if command == 'terminal length 0' else self.host_outputs.get(command, '')
        self._pending = f'{command}\r\n{body}\r\n'

    def ReadString(self, _terminator, timeout=None):
        pending, self._pending = self._pending, ''
        return pending


class FakeSession:
    def __init__(self, crt_stub):
        self.crt = crt_stub
        self.Connected = False

    def Connect(self, connect_string, _suppress=False):
        session = connect_string.split('"')[1]
        self.crt.attempts.append(session)
        self.crt.connect_strings.append(connect_string)
        if self.crt.reject_host_key_flag and '/ACCEPTHOSTKEYS' in connect_string:
            # A build refusing an option it does not know. Pass a string for
            # reject_host_key_flag to refuse it in that build's own words.
            self.crt.last_error = (
                self.crt.reject_host_key_flag
                if isinstance(self.crt.reject_host_key_flag, str)
                else 'Invalid option: /ACCEPTHOSTKEYS')
            raise Exception(self.crt.last_error)
        outcome = self.crt.behaviour.get(session, 'ok')
        if outcome != 'ok':
            self.crt.last_error = {
                'offline': 'The remote system refused the connection.',
                'timeout': 'The connection attempt timed out. No response from host.',
                'rejected': 'Password authentication failed.',
                # Verbatim from a real run: an error none of the categories
                # recognise, which is the case the connect string rides along
                # with. See test_an_unrecognised_failure_says_what_was_tried.
                'mystery': 'A hostname is required for the specific protocol.',
            }[outcome]
            raise Exception(self.crt.last_error)
        self.Connected = True

    def Disconnect(self):
        self.Connected = False

    def SetStatusText(self, _text):
        pass


class FakeDialog:
    def __init__(self, crt_stub):
        self.crt = crt_stub

    def Prompt(self, _message, title='', default='', _password=False):
        if 'scope' in title.lower():
            return self.crt.folder
        return self.crt.output_dir

    def MessageBox(self, message, title='', flags=0):
        self.crt.messages.append((title, message))
        return 6 if flags & 4 else 1  # always answer Yes to the confirm dialog


class FakeCRT:
    def __init__(self, output_dir, behaviour, host_outputs, folder='',
                 reject_host_key_flag=False, banner_lines=0):
        self.output_dir = output_dir
        self.behaviour = behaviour
        self.folder = folder
        self.reject_host_key_flag = reject_host_key_flag
        self.slept = []
        self.connect_strings = []
        self.attempts = []
        self.messages = []
        self.last_error = ''
        self.Screen = FakeScreen(host_outputs, banner_lines)
        self.Session = FakeSession(self)
        self.Dialog = FakeDialog(self)

    def GetLastErrorMessage(self):
        return self.last_error

    def Sleep(self, milliseconds):
        # Recorded rather than actually waited out: the point is that the
        # script gives the banner time, not that a test suite spends it.
        self.slept.append(milliseconds)


def run_walker(tmpdir, sessions, behaviour, host_outputs=None, folder='',
               reject_host_key_flag=False, banner_lines=0):
    """Drive bulk.main() with a stubbed SecureCRT and a stubbed session list."""
    fake = FakeCRT(tmpdir, behaviour, host_outputs or OUTPUTS, folder,
                   reject_host_key_flag, banner_lines)
    bulk.crt = fake
    capture_l2s.crt = fake
    original_find = bulk.find_sessions
    bulk.find_sessions = lambda _filter='': list(sessions)
    try:
        bulk.main()
    finally:
        bulk.find_sessions = original_find
        bulk.crt = None
        capture_l2s.crt = None
    return fake


def log_files(tmpdir):
    """Every run log in the folder, oldest first. One per run."""
    return sorted(os.path.join(tmpdir, name) for name in os.listdir(tmpdir)
                  if name.startswith('run_log_') and name.endswith('.csv'))


def log_rows(tmpdir, which=-1):
    """Rows of one run's log as dicts keyed by column name; the newest run by
    default. Keyed rather than indexed so a column added to the log does not
    silently shift what every assertion here is reading."""
    paths = log_files(tmpdir)
    if not paths:
        return []
    with io.open(paths[which], encoding='utf-8') as handle:
        lines = handle.read().splitlines()
    if not lines:
        return []
    columns = [name.strip().strip('"') for name in lines[0].split(',')]
    rows = []
    for line in lines[1:]:
        values = [field.strip().strip('"') for field in line.split(',')]
        rows.append(dict(zip(columns, values)))
    return rows


def outcomes(tmpdir):
    return {row['session']: row['outcome'] for row in log_rows(tmpdir)}


def checklists(tmpdir):
    """Every checklist in the output folder, sorted."""
    return sorted(name for name in os.listdir(tmpdir) if name.endswith('.cklb'))


def captures(tmpdir):
    """Every capture left in the output folder. Should be empty except where an
    audit failed on one."""
    return sorted(name for name in os.listdir(tmpdir) if name.endswith('.capture'))


def test_offline_switches_do_not_stop_the_run(tmpdir):
    """The reason there is no abort. On any given night a good fraction of six
    hundred switches will be unreachable, and a collector that stops at the
    first one never finishes."""
    print('\noffline switches are skipped, not fatal')
    sessions = [('sw-a', '10.0.0.1'), ('sw-b', '10.0.0.2'), ('sw-c', '10.0.0.3')]
    fake = run_walker(tmpdir, sessions, {'sw-b': 'offline'})
    result = outcomes(tmpdir)
    check('the offline switch is logged unreachable',
          result.get('sw-b') == 'unreachable', result)
    check('the run continues past it', result.get('sw-c') == 'checklisted', result)
    check('reachable switches produce checklists', len(checklists(tmpdir)) == 2,
          checklists(tmpdir))
    check('and no captures are left behind', not captures(tmpdir), captures(tmpdir))
    check('offline is not retried', fake.attempts.count('sw-b') == 1, fake.attempts)


def test_rejected_login_is_tried_twice(tmpdir):
    """Two attempts, then move on - deliberately under V-220524's threshold of
    three within 120 seconds, so a wrong credential does not trip the
    15-minute quiet period."""
    print('\na rejected login is retried once, then skipped')
    sessions = [('sw-a', '10.0.1.1'), ('sw-b', '10.0.1.2')]
    fake = run_walker(tmpdir, sessions, {'sw-a': 'rejected'})
    check('exactly two attempts', fake.attempts.count('sw-a') == 2, fake.attempts)
    check('two is below the STIG lockout threshold of three',
          bulk.LOGIN_ATTEMPTS < 3, bulk.LOGIN_ATTEMPTS)
    check('logged as a rejected login',
          outcomes(tmpdir).get('sw-a') == 'login rejected', outcomes(tmpdir))
    check('the run continues', outcomes(tmpdir).get('sw-b') == 'checklisted')


def test_duplicates_collapsed_and_recorded(tmpdir):
    """Merging a colleague's exported sessions is how the list reaches six
    hundred, so duplicate sessions for one switch are expected. One device
    needs one capture - but the log still has to explain the missing rows."""
    print('\nduplicate sessions for one switch are collapsed, and logged')
    sessions = [('site-a\\sw-1', '10.0.2.1'), ('site-b\\sw-1-copy', '10.0.2.1'),
                ('site-a\\sw-2', '10.0.2.2')]
    fake = run_walker(tmpdir, sessions, {})
    check('the duplicate is never connected to',
          'site-b\\sw-1-copy' not in fake.attempts, fake.attempts)
    check('but it is recorded, not silently dropped',
          outcomes(tmpdir).get('site-b\\sw-1-copy') == 'duplicate', outcomes(tmpdir))
    check('the log accounts for every session in the list',
          len(log_rows(tmpdir)) == len(sessions), log_rows(tmpdir))


def test_not_a_switch_is_refused(tmpdir):
    """A session list will eventually contain a jump host. bash answers every
    command with an error, so nothing is empty and nothing is truncated."""
    print('\na session that is not a Cisco switch writes nothing')
    bash = {command: f'bash: {command.split()[0]}: command not found'
            for command in capture_l2s.COMMANDS}
    run_walker(tmpdir, [('jumphost', '10.0.3.1')], {}, host_outputs=bash)
    check('logged as refused', outcomes(tmpdir).get('jumphost') == 'refused', outcomes(tmpdir))
    check('no checklist and no capture written',
          not checklists(tmpdir) and not captures(tmpdir),
          checklists(tmpdir) + captures(tmpdir))


def test_resume_skips_what_is_done(tmpdir):
    """What makes a five-hour run survivable: a second pass visits only the
    switches not done yet.

    A checklist is named for the switch's own hostname, which is not knowable
    before connecting - so unlike a capture named for the session's address,
    its existence cannot be tested in advance. bulk.INDEX_FILE is what makes
    that testable, and this is what asserts it works."""
    print('\na re-run picks up only what is missing')
    sessions = [('sw-a', '10.0.4.1'), ('sw-b', '10.0.4.2')]
    run_walker(tmpdir, sessions, {'sw-b': 'offline'})
    check('first pass finished one, missed one', len(checklists(tmpdir)) == 1,
          checklists(tmpdir))
    check('and recorded the finished one in the index',
          os.path.exists(os.path.join(tmpdir, bulk.INDEX_FILE)))

    second = run_walker(tmpdir, sessions, {})  # sw-b now reachable
    check('the completed switch is not revisited', 'sw-a' not in second.attempts, second.attempts)
    check('the missed switch is', 'sw-b' in second.attempts, second.attempts)
    check('and is finished on the second pass', len(checklists(tmpdir)) == 2,
          checklists(tmpdir))

    # Per-run files, so a log can be counted in a spreadsheet as it stands
    # rather than by picking the newest row per switch out of a history.
    check('each run wrote its own log', len(log_files(tmpdir)) == 2, log_files(tmpdir))
    # ...which only works if a run also accounts for what it skipped. Without
    # those rows the second pass logs one device and loses the other.
    second_run = outcomes(tmpdir)
    check("the second run's log still accounts for both switches",
          len(second_run) == 2, second_run)
    check('the one it skipped is logged as already done',
          second_run.get('sw-a') == 'already done', second_run)
    check('the one it collected is logged as checklisted',
          second_run.get('sw-b') == 'checklisted', second_run)

    # Deleting a checklist is how a switch is asked for again - the same
    # gesture that used to mean deleting its capture. An index that outvoted
    # the folder would make it do nothing.
    os.remove(os.path.join(tmpdir, checklists(tmpdir)[0]))
    third = run_walker(tmpdir, sessions, {})
    check('deleting a checklist puts its switch back in the queue',
          len(third.attempts) == 1, third.attempts)


def test_checklist_is_what_it_should_be(tmpdir):
    """The whole point. The walker runs the real audit, so what lands in the
    folder is a checklist STIG Viewer opens, named for the switch that produced
    it - not for the session or the address the walker knew it by."""
    print('\nwhat the walker leaves behind is a finished checklist')
    run_walker(tmpdir, [('site-a\\sw-1', '10.0.5.1')], {})
    written = checklists(tmpdir)
    check('one checklist written', len(written) == 1, os.listdir(tmpdir))
    if not written:
        return
    check("named for the switch's own hostname, the date, and the STIG revisions",
          re.match(r'^TESTSW01_\d{2}[A-Z]{3}\d{4}_L2S_V\d+R\d+_NDM_V\d+R\d+\.cklb$',
                   written[0]), written[0])
    check('no capture kept', not captures(tmpdir), captures(tmpdir))

    with io.open(os.path.join(tmpdir, written[0]), encoding='utf-8') as handle:
        checklist = json.load(handle)
    rules = [rule for stig in checklist['stigs'] for rule in stig['rules']]
    check('every rule carries a verdict',
          all(rule['status'] != 'not_reviewed' for rule in rules)
          or any(rule['status'] == 'not_a_finding' for rule in rules), len(rules))
    check("the asset block names the switch, not the session's address",
          checklist['target_data']['host_name'] == 'TESTSW01'
          and checklist['target_data']['fqdn'] == 'TESTSW01.example.test',
          checklist['target_data'])

    # The index is keyed by what the walker knew before connecting, and points
    # at what the audit produced after. That mapping is the only thing that can
    # answer "has this session been done" on a later run.
    with io.open(os.path.join(tmpdir, bulk.INDEX_FILE), encoding='utf-8') as handle:
        rows = [line.split(',') for line in handle.read().splitlines()[1:]]
    check('the index maps the session key to the checklist it produced',
          len(rows) == 1 and rows[0][0].strip('"') == '10.0.5.1.capture'
          and rows[0][1].strip('"') == written[0], rows)


def test_same_hostname_does_not_overwrite(tmpdir):
    """A fleet named per site rather than per device has two switches called
    the same thing, and the checklist is named for the hostname. Landing the
    second on the first would be silent: one file, one switch's verdicts, under
    a name that says nothing is wrong. The session's address is unique and is
    what keeps them apart."""
    print('\ntwo switches with one hostname keep two checklists')
    sessions = [('sw-a', '10.0.8.1'), ('sw-b', '10.0.8.2'), ('sw-c', '10.0.8.3')]
    run_walker(tmpdir, sessions, {})  # the stub gives all three the same config
    written = checklists(tmpdir)
    check('one checklist per switch, not one between them',
          len(written) == 3, written)
    check('the addresses are what tells them apart',
          any('10.0.8.2' in name for name in written)
          and any('10.0.8.3' in name for name in written), written)
    check('the first keeps the plain name', any(
        re.match(r'^TESTSW01_\d{2}[A-Z]{3}\d{4}_L2S[^/]*\.cklb$', name)
        and '10.0.8.' not in name for name in written), written)
    check('and the collision is said out loud in the log',
          sum('another switch' in row['comment'] for row in log_rows(tmpdir)) == 2,
          [row['comment'] for row in log_rows(tmpdir)])

    # Each one is a real checklist, not a truncated or shared file.
    for name in written:
        with io.open(os.path.join(tmpdir, name), encoding='utf-8') as handle:
            rules = [rule for stig in json.load(handle)['stigs'] for rule in stig['rules']]
        check('{0} carries a full checklist'.format(name), len(rules) == 64, len(rules))

    check('nothing is left in the work folder',
          not os.path.isdir(os.path.join(tmpdir, bulk.WORK_DIR)),
          os.listdir(tmpdir))


def test_audit_failure_keeps_its_capture(tmpdir):
    """The switch has been visited by the time the audit runs, and the
    connection is the expensive half. An audit that fails therefore keeps the
    capture rather than throwing away the trip - and says so under its own
    outcome, so it is never mistaken for a switch that was never reached."""
    print('\na failed audit keeps its capture and says so')
    original = capture_l2s.run_audit
    capture_l2s.run_audit = lambda *_args, **_kwargs: (None, 'the audit itself failed:\nboom')
    try:
        run_walker(tmpdir, [('sw-a', '10.0.7.1')], {})
    finally:
        capture_l2s.run_audit = original
    check('logged under its own outcome, not as a capture failure',
          outcomes(tmpdir).get('sw-a') == 'audit failed', outcomes(tmpdir))
    check('the capture is kept, so the trip is not wasted',
          captures(tmpdir) == ['10.0.7.1.capture'], captures(tmpdir))
    check('and it is not recorded as done, so a re-run retries it',
          not os.path.exists(os.path.join(tmpdir, bulk.INDEX_FILE)))


def test_an_unhandled_error_does_not_end_the_walk(tmpdir):
    """The named failures - offline, rejected, refused, write failed, audit
    failed - are each handled where they happen. This is the one that is not:
    something inside a single switch's turn raising what nobody planned for.
    On six hundred devices that is a certainty rather than a worry, and it used
    to cost every switch after it."""
    print('\nan unexpected error costs one switch, not the rest of the list')
    original = bulk.append_index
    hit = []

    def explode(output_dir, key, checklist, host):
        # Stands in for the writes that are not individually guarded: the index
        # and the run log, both of which touch a network share that can drop.
        if key == '10.0.10.2.capture':
            hit.append(key)
            raise OSError('the network share went away')
        return original(output_dir, key, checklist, host)

    bulk.append_index = explode
    try:
        sessions = [('sw-a', '10.0.10.1'), ('sw-b', '10.0.10.2'), ('sw-c', '10.0.10.3')]
        run_walker(tmpdir, sessions, {})
    finally:
        bulk.append_index = original

    check('the failing switch really did fail', hit == ['10.0.10.2.capture'], hit)
    result = outcomes(tmpdir)
    check('it is logged as an error rather than lost', result.get('sw-b') == 'error', result)
    check('and the walk carried on to the switch after it',
          result.get('sw-c') == 'checklisted', result)
    check('every session in the list is still accounted for', len(result) == 3, result)


def test_log_columns(tmpdir):
    """The run log is the fleet's account of itself, so it has to carry what
    the fleet is: what each switch is called, where it is, what hardware and
    software are on it, and one sentence about what happened. A switch nobody
    could reach is exactly the row that needs the sentence, and the two ways it
    fails - nothing answering, or the host answering and saying no - are
    different problems with different fixes, so they are not both "unreachable".
    """
    print('\nthe log says what each switch is, and what happened to it')
    sessions = [('site-a\\sw-1', '10.0.11.1'), ('site-a\\sw-2', '10.0.11.2'),
                ('site-b\\sw-3', '10.0.11.3')]
    run_walker(tmpdir, sessions,
               {'site-a\\sw-2': 'timeout', 'site-b\\sw-3': 'offline'})
    rows = {row['session']: row for row in log_rows(tmpdir)}
    check('every session in the list has a row', len(rows) == 3, sorted(rows))

    check('the columns are the ones a person reads, in order',
          bulk.LOG_COLUMNS[:4] == ('hostname', 'ip_address', 'model', 'comment'),
          bulk.LOG_COLUMNS)
    # Serial and release belong to inventory_l2s.py, which answers that
    # question in minutes. Two files carrying them would disagree the day one
    # of them is a week old.
    check('and it does not duplicate the inventory script\'s columns',
          not any(name in bulk.LOG_COLUMNS for name in ('serial_number', 'ios_version')),
          bulk.LOG_COLUMNS)

    reached = rows.get('site-a\\sw-1', {})
    check('a switch that answered is named by its own hostname',
          reached.get('hostname') == 'TESTSW01', reached)
    check('with its address and the model it was audited on',
          (reached.get('ip_address') == '10.0.11.1'
           and reached.get('model') == 'C9300-48P'), reached)

    # The rows the morning after works from.
    timed_out = rows.get('site-a\\sw-2', {})
    check('a switch that never answered says so in plain words',
          timed_out.get('comment') == 'Connection timed out', timed_out)
    refused = rows.get('site-b\\sw-3', {})
    check('and a host that answered and said no says that instead',
          refused.get('comment') == 'System refused connection', refused)
    check('the two are not collapsed into one sentence',
          timed_out.get('comment') != refused.get('comment'))

    check('an unreached switch is still identifiable by its session and address',
          (timed_out.get('hostname') == 'site-a\\sw-2'
           and timed_out.get('ip_address') == '10.0.11.2'), timed_out)
    check('and its model is blank rather than guessed',
          not timed_out.get('model'), timed_out)


def test_find_sessions_joins_a_folder_with_a_forward_slash(tmpdir):
    """Every other test here stubs find_sessions() out entirely, which is
    exactly how a real bug shipped unnoticed: SecureCRT's own session database
    joins a folder onto a session with a forward slash, not the backslash a
    Windows path would suggest, and /S never resolves a session filed under a
    folder at all if this is wrong - SecureCRT reports it not found rather
    than connecting to something unexpected. This is the one test that drives
    the real function, against real .ini files, rather than replacing it."""
    print('\nfind_sessions() joins a folder onto its session with a forward slash')
    sessions_root = os.path.join(tmpdir, 'Sessions')
    nested = os.path.join(sessions_root, 'DistNode1')
    os.makedirs(nested)
    with io.open(os.path.join(nested, '10.1.2.3 - b100-52.ini'), 'w', encoding='utf-8') as handle:
        handle.write('S:"Hostname"=10.1.2.3\n')
    with io.open(os.path.join(sessions_root, 'sw-top-level.ini'), 'w', encoding='utf-8') as handle:
        handle.write('S:"Hostname"=10.1.2.4\n')

    original = bulk.config_path
    bulk.config_path = lambda: tmpdir
    try:
        found = dict(bulk.find_sessions())
        scoped = dict(bulk.find_sessions('DistNode1'))
    finally:
        bulk.config_path = original

    check('a session inside a folder is joined to it with a forward slash',
          'DistNode1/10.1.2.3 - b100-52' in found, found)
    check('not the backslash a Windows path would suggest',
          'DistNode1\\10.1.2.3 - b100-52' not in found, found)
    check("a top-level session has no separator to get wrong either way",
          'sw-top-level' in found, found)
    check("each session's own Hostname field is read correctly either way",
          found.get('DistNode1/10.1.2.3 - b100-52') == '10.1.2.3'
          and found.get('sw-top-level') == '10.1.2.4', found)
    check('scoping to a folder still matches on the same separator',
          list(scoped) == ['DistNode1/10.1.2.3 - b100-52'], scoped)


def test_session_name_parts():
    """This fleet names sessions "<ip> - <bldg/trailer>[-<room/dept>]", and an
    unreachable switch has nothing else to say who it is - so the bldg/
    trailer belongs in the log, not the raw session path."""
    print('\nan unreachable switch\'s ip and bldg/trailer come off its own name')
    check('ip before the separator, bldg/trailer-room after it',
          bulk.session_name_parts('10.1.2.3 - 5-200') == ('10.1.2.3', '5-200'))
    check('a bldg/trailer with no room is still a whole label',
          bulk.session_name_parts('10.1.2.3 - 5') == ('10.1.2.3', '5'))
    check('a folder prefix does not confuse the parse',
          bulk.session_name_parts('Site A/10.1.2.3 - 5-200') == ('10.1.2.3', '5-200'))
    check('a session not named this way parses to nothing',
          bulk.session_name_parts('sw-b') == ('', ''))
    check('...even one with a folder and a hyphen in it',
          bulk.session_name_parts('site-a/sw-1') == ('', ''))

    # The fleet's real convention: a building (b) or trailer (t) number, with
    # the room or department folded in by a plain hyphen when there is one.
    check('a building with a numeric room',
          bulk.session_name_parts('10.1.2.3 - b100-52') == ('10.1.2.3', 'b100-52'))
    check('a building with a department name instead of a room',
          bulk.session_name_parts('10.1.2.3 - b500-hr') == ('10.1.2.3', 'b500-hr'))
    check('a trailer with no room at all',
          bulk.session_name_parts('10.1.2.3 - t1500') == ('10.1.2.3', 't1500'))


def test_unreachable_switch_is_named_from_its_session(tmpdir):
    """When a switch cannot be reached, its session's own name - not the
    switch - is the only thing that can identify it. The bldg/trailer label
    is what a person chasing it down actually wants to see; the ip backfills
    the address only when the saved session carried none."""
    print('\nan unreachable switch is named for its bldg/trailer, not its session path')
    sessions = [('10.9.0.1 - 5-200', '10.9.0.1'), ('10.9.0.2 - 6', '')]
    fake = run_walker(tmpdir, sessions, {'10.9.0.1 - 5-200': 'offline',
                                         '10.9.0.2 - 6': 'timeout'})
    rows = {row['session']: row for row in log_rows(tmpdir)}
    with_room = rows.get('10.9.0.1 - 5-200', {})
    check('the bldg/trailer-room label becomes the hostname',
          with_room.get('hostname') == '5-200', with_room)
    check('a Hostname field that was already set is kept as the address',
          with_room.get('ip_address') == '10.9.0.1', with_room)

    no_room = rows.get('10.9.0.2 - 6', {})
    check('a bldg/trailer with no room still becomes the hostname',
          no_room.get('hostname') == '6', no_room)
    check('a blank Hostname field is backfilled from the session name',
          no_room.get('ip_address') == '10.9.0.2', no_room)
    check('nothing here stopped the walk', fake.attempts.count('10.9.0.2 - 6') >= 1)


def test_a_banner_still_arriving_is_waited_out(tmpdir):
    """The failure that made a reachable fleet look refused. Every switch this
    tool audits carries the DoD notice and consent banner - V-220521 requires
    it - and that banner is still coming down the wire when Connect() returns.
    Reading the screen straight away reads a line of it, which is not a prompt,
    and the collection is refused on a switch that was answering perfectly
    well.

    Invisible by hand, which is what made it expensive: run capture_l2s.py
    against a session a person logged into and the banner finished scrolling
    long before the script started."""
    print('\na banner still arriving is waited out, not mistaken for no prompt')
    # 40 reads at the poll interval is the 20 seconds a real switch was
    # measured taking to finish its banner - the wait has to outlast that with
    # room to spare, not merely outlast a tidy fixture.
    fake = run_walker(tmpdir, [('node-a/sw-1', '10.0.13.1')], {}, banner_lines=40)
    result = outcomes(tmpdir)
    check('the switch is collected rather than refused',
          result.get('node-a/sw-1') == 'checklisted', result)
    check('nothing is logged as having no prompt',
          not any('prompt' in row['comment'].lower() for row in log_rows(tmpdir)),
          [row['comment'] for row in log_rows(tmpdir)])
    check('and it waited, rather than spinning', fake.slept, fake.slept)
    check('for longer than the 20 seconds a real banner took',
          sum(fake.slept) >= 20000, sum(fake.slept))

    # A banner ruled off in '#' is the trap, and this fixture line is ruled off
    # that way on purpose: it ENDS in one, so "wait until a line ends in #"
    # reads the banner and calls it a prompt. A space is what a banner line has
    # and a prompt never does.
    check('the fixture really is the trap - a banner line ending in #',
          BANNER_LINE.endswith('#'), BANNER_LINE)
    check('and it is not accepted as a prompt',
          not capture_l2s._looks_like_a_prompt(BANNER_LINE), BANNER_LINE)
    check('while a real prompt still is',
          capture_l2s._looks_like_a_prompt('TESTSW01#')
          and capture_l2s._looks_like_a_prompt('TESTSW01(config-if)#'))
    checklist = checklists(tmpdir)
    check('the checklist is named for the switch, not for a line of banner',
          len(checklist) == 1 and checklist[0].startswith('TESTSW01_'), checklist)

    # The other half of the bargain: waiting must not change what a session
    # already at its prompt does. capture_l2s.py attaches to one a person
    # logged into, and it should still be read on sight, with nothing sent to
    # it and nothing waited out.
    settled = run_walker(tmpdir, [('node-b/sw-2', '10.0.13.2')], {})
    check('a session already at its prompt is read immediately',
          not settled.slept, settled.slept)


def test_an_unrecognised_failure_says_what_was_tried(tmpdir):
    """A connect error the categories do not recognise leaves the log saying
    only what SecureCRT said, and SecureCRT's own wording does not distinguish
    "this switch is off" from "I could not resolve that session name at all" -
    the second reads, unhelpfully, as an unreachable device. The request is
    what tells them apart, so an unrecognised failure carries the connect
    string that produced it. The recognised ones do not: they already say what
    went wrong, and repeating the request under every timed-out switch would
    be noise."""
    print('\nan unrecognised connect failure says what was actually tried')
    sessions = [('node-a/10.9.9.1 - b100-52', '10.9.9.1'), ('node-a/sw-2', '10.9.9.2')]
    run_walker(tmpdir, sessions, {'node-a/10.9.9.1 - b100-52': 'mystery',
                                  'node-a/sw-2': 'timeout'})
    rows = {row['session']: row for row in log_rows(tmpdir)}

    mystery = rows.get('node-a/10.9.9.1 - b100-52', {})
    comment = mystery.get('comment', '')
    check("SecureCRT's own wording is still the first thing said",
          comment.startswith('A hostname is required for the specific protocol.'), mystery)
    check('and the connect string that produced it rides along',
          '/S ' in comment and 'node-a/10.9.9.1 - b100-52' in comment, mystery)

    # A recognised failure is already self-explanatory; the request under it
    # would be noise on what is normally the bulk of an overnight run's rows.
    timed_out = rows.get('node-a/sw-2', {})
    check('a recognised failure stays the plain sentence it was',
          timed_out.get('comment') == 'Connection timed out', timed_out)


def test_host_keys_are_accepted_without_a_dialog(tmpdir):
    """The first SSH connection to a switch SecureCRT has not seen raises a New
    Host Key dialog. With a person in the chair that is one press of Enter;
    in an unattended walk it is a modal box no script can dismiss, and the run
    stops on switch 1 of six hundred until somebody comes back to the machine.
    `/ACCEPTHOSTKEYS` makes the same trust decision that button does, without
    drawing it."""
    print('\nan unknown host key does not stop the walk')
    fake = run_walker(tmpdir, [('sw-a', '10.0.12.1')], {})
    check('the connect string carries /ACCEPTHOSTKEYS',
          all('/ACCEPTHOSTKEYS' in text for text in fake.connect_strings),
          fake.connect_strings)
    check('and the session is still named the way SecureCRT expects',
          all(text.startswith('/S "') for text in fake.connect_strings),
          fake.connect_strings)

    # A build old enough not to know the option rejects it rather than ignoring
    # it. That is one retry, not a lost night - and it is discovered once.
    older = run_walker(tmpdir, [('sw-b', '10.0.12.2'), ('sw-c', '10.0.12.3')], {},
                       reject_host_key_flag=True)
    check('an older build still gets its switches',
          outcomes(tmpdir).get('sw-b') == 'checklisted'
          and outcomes(tmpdir).get('sw-c') == 'checklisted', outcomes(tmpdir))
    without = [text for text in older.connect_strings if '/ACCEPTHOSTKEYS' not in text]
    check('by dropping the flag rather than failing',
          len(without) >= 2, older.connect_strings)
    check('and only the first switch pays for finding that out',
          sum('/ACCEPTHOSTKEYS' in text for text in older.connect_strings) == 1,
          older.connect_strings)

    # The wording that cost an afternoon on a real build. It complains about
    # the session rather than about the option, so it read as a fleet that had
    # gone unreachable overnight - every switch, on a network that answered by
    # hand. The recovery is the same one; only the recognising was missing.
    quirky = run_walker(tmpdir, [('sw-d', '10.0.12.4'), ('sw-e', '10.0.12.5')], {},
                        reject_host_key_flag='A hostname is required for the '
                                             'specific protocol.')
    check('a build that refuses the flag in its own words still gets its switches',
          outcomes(tmpdir).get('sw-d') == 'checklisted'
          and outcomes(tmpdir).get('sw-e') == 'checklisted', outcomes(tmpdir))
    check('nothing is left logged as unreachable on a reachable fleet',
          'unreachable' not in set(outcomes(tmpdir).values()), outcomes(tmpdir))
    check('and that build, too, pays for it exactly once',
          sum('/ACCEPTHOSTKEYS' in text for text in quirky.connect_strings) == 1,
          quirky.connect_strings)


def test_no_audit_here_falls_back_to_captures(tmpdir):
    """Only these two files copied to a locked-down machine: nothing there can
    audit anything. Settled once, before the walk, and answered by collecting
    captures - which is what this script did before it audited at all. A run
    that discovered this per switch would visit six hundred devices and produce
    nothing."""
    print('\nwithout an audit here, the walk still collects')
    original = capture_l2s.find_audit
    capture_l2s.find_audit = lambda: (None, None, 'l2_stig_audit.py not found')
    try:
        fake = run_walker(tmpdir, [('sw-a', '10.0.9.1'), ('sw-b', '10.0.9.2')], {})
    finally:
        capture_l2s.find_audit = original

    check('it says so before connecting to anything',
          any('audit' in title.lower() for title, _ in fake.messages), fake.messages)
    check('and collects captures instead of nothing at all',
          captures(tmpdir) == ['10.0.9.1.capture', '10.0.9.2.capture'], captures(tmpdir))
    check('logged as captured, not as checklisted',
          set(outcomes(tmpdir).values()) == {'captured'}, outcomes(tmpdir))

    # Those captures are the input to an audit run elsewhere, so they have to
    # load through exactly the path a hand-collected one does.
    try:
        session = capture.load(os.path.join(tmpdir, '10.0.9.1.capture'))
        ok, detail = True, ''
    except capture.CaptureError as error:
        ok, detail = False, str(error)
    check('and what it wrote is what the audit reads', ok, detail)
    if ok:
        check('serving the running-config back verbatim',
              session.send_command('show running-config')
              == OUTPUTS['show running-config'].strip('\n'))


def test_stop_file_halts_cleanly(tmpdir):
    print('\nthe STOP file ends a run without killing it mid-command')
    open(os.path.join(tmpdir, bulk.STOP_FILE), 'w').close()
    fake = run_walker(tmpdir, [('sw-a', '10.0.6.1'), ('sw-b', '10.0.6.2')], {})
    check('nothing was connected to', not fake.attempts, fake.attempts)
    check('and the run said so',
          any('stopped early' in message.lower() for _title, message in fake.messages),
          fake.messages)


if __name__ == '__main__':
    test_session_name_parts()
    for test in (test_find_sessions_joins_a_folder_with_a_forward_slash,
                 test_offline_switches_do_not_stop_the_run,
                 test_rejected_login_is_tried_twice,
                 test_duplicates_collapsed_and_recorded,
                 test_not_a_switch_is_refused,
                 test_resume_skips_what_is_done,
                 test_checklist_is_what_it_should_be,
                 test_same_hostname_does_not_overwrite,
                 test_audit_failure_keeps_its_capture,
                 test_log_columns,
                 test_unreachable_switch_is_named_from_its_session,
                 test_a_banner_still_arriving_is_waited_out,
                 test_an_unrecognised_failure_says_what_was_tried,
                 test_host_keys_are_accepted_without_a_dialog,
                 test_an_unhandled_error_does_not_end_the_walk,
                 test_no_audit_here_falls_back_to_captures,
                 test_stop_file_halts_cleanly):
        with tempfile.TemporaryDirectory() as tmpdir:
            test(tmpdir)
    print('\n' + ('ALL CHECKS PASSED' if not failures
                  else f'{len(failures)} FAILED: {", ".join(failures)}'))
    sys.exit(1 if failures else 0)
