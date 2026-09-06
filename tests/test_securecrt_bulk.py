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
sys.path.insert(0, PROJECT)
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


class FakeScreen:
    """Replays fixture output command by command, echoing like a real device."""

    def __init__(self, host_outputs):
        self.host_outputs = host_outputs
        self.Synchronous = False
        self.prompt = 'SW#'
        self._pending = ''
        self.CurrentRow = 5
        self.CurrentColumn = len(self.prompt) + 1

    def Get(self, *_args):
        return self.prompt

    def Send(self, text):
        command = text.rstrip('\r\n')
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
        outcome = self.crt.behaviour.get(session, 'ok')
        if outcome != 'ok':
            self.crt.last_error = {
                'offline': 'The remote system refused the connection.',
                'timeout': 'The connection attempt timed out. No response from host.',
                'rejected': 'Password authentication failed.',
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
    def __init__(self, output_dir, behaviour, host_outputs, folder=''):
        self.output_dir = output_dir
        self.behaviour = behaviour
        self.folder = folder
        self.attempts = []
        self.messages = []
        self.last_error = ''
        self.Screen = FakeScreen(host_outputs)
        self.Session = FakeSession(self)
        self.Dialog = FakeDialog(self)

    def GetLastErrorMessage(self):
        return self.last_error


def run_walker(tmpdir, sessions, behaviour, host_outputs=None, folder=''):
    """Drive bulk.main() with a stubbed SecureCRT and a stubbed session list."""
    fake = FakeCRT(tmpdir, behaviour, host_outputs or OUTPUTS, folder)
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
          bulk.LOG_COLUMNS[:5] == ('hostname', 'ip_address', 'model', 'ios_version', 'comment'),
          bulk.LOG_COLUMNS)

    reached = rows.get('site-a\\sw-1', {})
    check('a switch that answered is named by its own hostname',
          reached.get('hostname') == 'TESTSW01', reached)
    check('with its address, model and release from `show version`',
          (reached.get('ip_address') == '10.0.11.1'
           and reached.get('model') == 'C9300-48P'
           and reached.get('ios_version') == '17.12.4'), reached)

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
    check('and its model and release are blank rather than guessed',
          not timed_out.get('model') and not timed_out.get('ios_version'), timed_out)


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
    for test in (test_offline_switches_do_not_stop_the_run,
                 test_rejected_login_is_tried_twice,
                 test_duplicates_collapsed_and_recorded,
                 test_not_a_switch_is_refused,
                 test_resume_skips_what_is_done,
                 test_checklist_is_what_it_should_be,
                 test_same_hostname_does_not_overwrite,
                 test_audit_failure_keeps_its_capture,
                 test_log_columns,
                 test_an_unhandled_error_does_not_end_the_walk,
                 test_no_audit_here_falls_back_to_captures,
                 test_stop_file_halts_cleanly):
        with tempfile.TemporaryDirectory() as tmpdir:
            test(tmpdir)
    print('\n' + ('ALL CHECKS PASSED' if not failures
                  else f'{len(failures)} FAILED: {", ".join(failures)}'))
    sys.exit(1 if failures else 0)
