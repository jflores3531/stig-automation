# $language = "Python3"
# $interface = "1.0"

"""Fill in a STIG Viewer 3 checklist for every saved SecureCRT session, unattended.

For an inventory of the fleet rather than an audit of it - hostname, address,
model, serial and release, in minutes rather than hours - use inventory_l2s.py
beside this file. It asks one command per switch instead of seven.

Run this from SecureCRT (Script > Run...) with no session connected, or with
any session connected - it opens and closes its own. For each saved session it
connects using the credentials SecureCRT already holds, sends the read-only
show commands, audits them, writes

    <hostname>_<DDMMMYYYY>_L2S_V3R2_NDM_V3R6.cklb

and disconnects. Nothing is configured on any device. The only non-show command
sent is `terminal length 0`, which is session-scoped. One output folder holds
the whole fleet: each name carries the switch that produced it, so nothing
writes over anything else.

The capture each audit read is a working file and is deleted once its checklist
exists. It is kept in exactly one case - an audit that failed on that capture -
because the switch has already been visited by then and the collection is the
part that cannot be repeated cheaply. Those show in the log as `audit failed`
with the reason, and can be audited by hand afterwards:

    python l2_stig_audit.py <name> --from-capture <file> --to-cklb <folder>

Whether the audit can run on this machine at all is settled once, before the
walk starts, rather than discovered six hundred connections later. Where it
cannot - only these two files were copied to a locked-down machine, say - the
run offers to collect captures alone, which is what this script did before it
audited anything, and the command above turns them into checklists elsewhere.

WHY THIS IS A SEPARATE SCRIPT FROM capture_l2s.py
capture_l2s.py cannot connect to anything. It attaches to the session in front
of it, which makes it impossible to point at the wrong device and impossible to
run without a human having already logged in. This script gives that property
up: it logs into every switch in the list on its own authority. That is a
materially different thing to put in front of whoever approved the audit
tooling, and it deserves its own approval rather than riding along on
capture_l2s.py's.

Both files must be copied together - this one imports the guards, the command
list and the capture format from capture_l2s.py rather than duplicating them,
so the two cannot drift. Neither imports anything from the wider repository.

WHAT IT DOES NOT DO
It never aborts a run. A switch that is offline, in a login quiet period, or
refusing credentials is logged and skipped. Six hundred switches will not all
be reachable on any given night, and a collector that stops at the first
problem would never finish.
"""

import os
import os.path
import time

# `crt` is injected by SecureCRT into this script's globals, not into the
# modules it imports - so capture_l2s gets it handed over explicitly below.
crt = globals().get('crt')

import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import capture_l2s


# Where the checklists and the run log are written. Deliberately a stable path
# rather than a timestamped one: a re-run skips the sessions already done in
# this folder, which is what makes a five-hour job resumable after it dies at
# switch 400. Point a new round at a new folder.
OUTPUT_DIR = r'C:\Documents\netauto_checklists'

# What "already done" is read from. The checklist is named for the switch's own
# hostname, which is not knowable until it has been connected to and asked - so
# unlike a capture named for the session's address, its existence cannot be
# tested in advance. This file is that test: one row per session that produced
# a checklist, written as each one lands.
#
# It is a plain index of what happened, not a database. A row whose checklist
# has since been deleted from the folder is treated as not done, so removing a
# checklist is still how you ask for that switch again - the same gesture that
# used to mean deleting its capture.
INDEX_FILE = 'collected.csv'

# Drop a file with this name in OUTPUT_DIR to stop a run cleanly at the end of
# the current switch. There is no other way to interrupt a script inside
# SecureCRT without killing it mid-command and losing the log line.
STOP_FILE = 'STOP'

# One retry on a rejected login, then move on. Below the STIG's own threshold:
# V-220524 mandates `login block-for 900 attempts 3 within 120`, so two
# attempts stays under the three that trigger a 15-minute quiet period. That
# quiet period is self-clearing and locks no account - the account-locking form
# (`aaa local authentication attempts max-fail`) is not what the STIG asks for.
LOGIN_ATTEMPTS = 2

# Sessions whose name matches these are SecureCRT's own scaffolding, not devices.
SKIP_SESSIONS = ('Default', 'Default_LocalShell', 'Default_RDP', 'Default_Serial',
                 '__FolderData__')

# Substrings that mark a connect failure as a rejected login rather than an
# unreachable host. Only used to decide whether to spend a second attempt, so
# the run behaves correctly even when the match fails: an unrecognised error is
# treated as unreachable, which skips without retrying. Nothing depends on this
# being exhaustive.
REJECTION_MARKERS = ('authentication', 'password', 'denied', 'credential',
                     'login failed', 'bad passphrase')


def config_path():
    """Where SecureCRT keeps its configuration on this machine.

    Read from the registry rather than assumed, because a work build may put it
    on a network drive or a roaming profile. Falls back to the default only if
    the key is missing."""
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'Software\VanDyke\SecureCRT') as key:
            value = winreg.QueryValueEx(key, 'Config Path')[0]
            if value:
                return value
    except (ImportError, OSError, WindowsError):
        pass
    return os.path.join(os.environ.get('APPDATA', ''), 'VanDyke', 'Config')


def session_hostname(ini_path):
    """The Hostname field of a saved session, or '' if it has none.

    Captures are named by this rather than by session name: the sessions on a
    real network carry long, inconsistent hostnames, while the address is short
    and unique. The device's own hostname still ends up inside the capture,
    where the audit reads it.

    Only Hostname is read. The stored password is never touched - SecureCRT
    supplies it on connect and this script never sees it."""
    try:
        with open(ini_path, 'r', encoding='utf-8', errors='replace') as handle:
            for line in handle:
                if line.startswith('S:"Hostname"='):
                    return line.split('=', 1)[1].strip()
    except OSError:
        pass
    return ''


def find_sessions(folder_filter=''):
    """Every saved session, as (session_path, hostname) pairs.

    session_path is what /S expects: the path as shown in the Connect dialog,
    relative to Sessions\\ and without the .ini extension."""
    root = os.path.join(config_path(), 'Sessions')
    if not os.path.isdir(root):
        return []
    found = []
    for dirpath, _dirnames, filenames in os.walk(root):
        for filename in sorted(filenames):
            if not filename.endswith('.ini'):
                continue
            name = filename[:-len('.ini')]
            if name in SKIP_SESSIONS:
                continue
            full = os.path.join(dirpath, filename)
            relative = os.path.relpath(full, root)[:-len('.ini')].replace('/', '\\')
            if folder_filter and not relative.lower().startswith(folder_filter.lower()):
                continue
            found.append((relative, session_hostname(full)))
    return sorted(found)


def dedupe_by_host(sessions):
    """Collapse sessions that point at the same address, keeping the first.

    Returns (unique, duplicates). Two sessions for one switch need one capture,
    not two - and duplicates are not an edge case here: merging a colleague's
    exported sessions into your own is how the list gets to six hundred in the
    first place. Left implicit, the second session would connect, capture, and
    overwrite the first for no benefit but the connection time.

    Sessions with no Hostname field are never collapsed together, since the
    only thing they would have in common is being unidentifiable."""
    seen = {}
    unique, duplicates = [], []
    for session_path, host in sessions:
        if host and host in seen:
            duplicates.append((session_path, host, seen[host]))
            continue
        if host:
            seen[host] = session_path
        unique.append((session_path, host))
    return unique, duplicates


def capture_name(session_path, hostname):
    """Capture filename for a session. Prefers the address; falls back to the
    session name with path separators flattened when a session has no Hostname
    field (a serial or local-shell session, say).

    Still the switch's identity to this script, even though the capture is now
    a working file: it is the only name available before connecting, and it is
    what the index below is keyed on."""
    stem = hostname or session_path
    for bad in '\\/:*?"<>| ':
        stem = stem.replace(bad, '_')
    return stem + '.capture'


def session_stem(session_path, hostname):
    """The session's address, flattened - unique across the list, and the only
    identity available before connecting."""
    stem = hostname or session_path
    for bad in '\\/:*?"<>| ':
        stem = stem.replace(bad, '_')
    return stem


def index_key(session_path, hostname):
    """How a session is identified in the index, and in the folder if a capture
    ends up kept. One name for both, so the two cannot disagree."""
    return capture_name(session_path, hostname)


# Two switches reporting the same hostname is not a hypothetical on a fleet
# that names them per site rather than per device - and the checklist is named
# for the hostname, so the second one would land on the first one's file. In a
# run nobody is watching, that is silent: one file, one switch's verdicts,
# under a name that says nothing is wrong.
#
# So the audit writes into a work folder and the result is moved into place
# here, where the session's address is known and is unique. A name already
# claimed by a DIFFERENT session gets that address folded in; a name claimed by
# this same session is its own earlier checklist and is replaced, which is what
# re-running one switch should do.
WORK_DIR = '.work'


def place_checklist(output_dir, produced, key, claimed):
    """Move the audit's output into output_dir. Returns (final name, collided).

    `claimed` maps checklist name -> the session key that produced it."""
    name = os.path.basename(produced)
    collided = claimed.get(name, key) != key
    if collided:
        stem, extension = os.path.splitext(name)
        target = unused_path(output_dir, '{0}_{1}'.format(stem, key[:-len('.capture')]),
                             extension)
    else:
        target = os.path.join(output_dir, name)
    if os.path.exists(target):
        os.remove(target)
    os.rename(produced, target)
    return os.path.basename(target), collided


def read_index(output_dir):
    """{session key: checklist filename} for the sessions this folder already
    has a checklist for.

    A row naming a file that is no longer there is dropped rather than trusted:
    deleting a checklist is how a switch is asked for again, and an index that
    outvoted the folder would make that gesture do nothing."""
    done = {}
    path = os.path.join(output_dir, INDEX_FILE)
    if not os.path.exists(path):
        return done
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as handle:
            for line in handle.read().splitlines()[1:]:
                fields = [field.strip().strip('"') for field in line.split(',')]
                if len(fields) < 2 or not fields[0]:
                    continue
                key, checklist = fields[0], fields[1]
                if checklist and os.path.exists(os.path.join(output_dir, checklist)):
                    done[key] = checklist
    except OSError:
        # An unreadable index costs a re-collection, not a failed run. Every
        # command sent is read-only, so the cost is connection time.
        return {}
    return done


def append_index(output_dir, key, checklist, host):
    """Record one finished switch. Appended as it lands rather than written at
    the end, so a run killed at switch 400 leaves 399 rows behind - which is
    the whole point of the file."""
    path = os.path.join(output_dir, INDEX_FILE)
    new = not os.path.exists(path)
    with open(path, 'a', encoding='utf-8') as handle:
        if new:
            handle.write('session_key,checklist,host,written\n')
        handle.write(','.join('"{0}"'.format(str(field).replace('"', "'")) for field in
                              (key, checklist, host, time.strftime('%Y-%m-%d %H:%M:%S'))) + '\n')


def looks_rejected(error_text):
    lowered = (error_text or '').lower()
    return any(marker in lowered for marker in REJECTION_MARKERS)


# What a switch that could not be reached gets written against its name. The
# two that matter are distinct problems with distinct fixes: a refusal is the
# host answering and saying no - SSH disabled, a management ACL, the wrong port
# - while a timeout is nothing answering at all, which is a device that is off,
# moved, or behind something dropping the traffic. Reading "unreachable" for
# both, as the log did, throws that away on exactly the rows somebody has to
# work through the morning after.
#
# Matched on SecureCRT's own error text, and never guessed at: anything these
# do not recognise is written verbatim, which is more useful than a category
# invented for it.
CONNECT_FAILURES = (
    (('timed out', 'timeout', 'no response'), 'Connection timed out'),
    (('refused', 'reset by peer', 'actively refused'), 'System refused connection'),
    (('no route', 'unreachable', 'cannot resolve', 'unknown host', 'name or service'),
     'Host unreachable'),
)


def describe_connect_failure(error_text):
    """A plain sentence for the log's comment column, from SecureCRT's error."""
    lowered = (error_text or '').lower()
    for markers, description in CONNECT_FAILURES:
        if any(marker in lowered for marker in markers):
            return description
    if looks_rejected(error_text):
        return 'Login rejected'
    return first_line(error_text)


# The run log's columns. This is the STIG walk's record of what happened to
# each switch, not an inventory of the fleet - inventory_l2s.py answers that
# question, in minutes rather than hours, and carries the serial and the
# release. Duplicating them here would leave two files disagreeing about a
# switch the day one of them is a week old.
#
# The model stays, because the walk cannot say what it audited without it: a
# checklist's verdicts mean something different on a C9300 than on a WS-C3850
# whose hardware is past support, and this is the file that lists both.
#
# hostname is the switch's own where the walk got far enough to ask it, and the
# saved session's name where it did not: a row for a device nobody could reach
# still has to be identifiable, and the session name is what the person chasing
# it will recognise. model is blank on those rows for the honest reason -
# nothing read it, because nothing answered - and comment says which of the two
# ways it failed.
LOG_COLUMNS = ('hostname', 'ip_address', 'model', 'comment',
               'outcome', 'session', 'timestamp')


class RunLog:
    """One line per switch: what it is, what happened to it, when.

    This is the coverage record, not just a debugging aid. A STIG audit of six
    hundred switches has to account for all six hundred, and "42 timed out,
    here they are, with what we know about each" is part of the deliverable.

    One file per run, named for when the run started, so each file can be
    opened in a spreadsheet and counted directly. Which is also why a run logs
    the switches it *skipped* as already done: without those rows the second
    pass would produce a log of forty devices and no trace of the other five
    hundred and sixty, and a log that only accounts for the switches it visited
    is not a census. Every run's file is a complete account of the whole list."""

    def __init__(self, directory):
        self.path = unused_path(directory,
                                'run_log_' + time.strftime('%Y%m%d_%H%M%S'), '.csv')
        self.counts = {}
        with open(self.path, 'w', encoding='utf-8') as handle:
            handle.write(','.join(LOG_COLUMNS) + '\n')

    def record(self, session_path, host, outcome, comment='', hostname='', model=''):
        self.counts[outcome] = self.counts.get(outcome, 0) + 1
        row = (hostname or session_path, host, model, comment,
               outcome, session_path, time.strftime('%Y-%m-%d %H:%M:%S'))
        with open(self.path, 'a', encoding='utf-8') as handle:
            handle.write(','.join('"{0}"'.format(str(f).replace('"', "'")) for f in row) + '\n')

    def summary(self):
        return ', '.join('{0}: {1}'.format(name, self.counts[name])
                         for name in sorted(self.counts))


def connect_session(session_path):
    """Connect to a saved session. Returns (outcome, comment), both '' on
    success.

    SecureCRT raises on a failed connect and puts the detail in
    GetLastErrorMessage(). A rejected login is retried once; anything else is
    treated as unreachable and skipped without a retry. The comment is the
    plain sentence for the log - see describe_connect_failure - and the outcome
    is the word the run summary counts by."""
    for attempt in range(1, LOGIN_ATTEMPTS + 1):
        error = ''
        try:
            crt.Session.Connect('/S "{0}"'.format(session_path), True)
        except Exception:
            error = crt.GetLastErrorMessage() or 'connect failed'
        if crt.Session.Connected:
            return '', ''
        if not looks_rejected(error):
            return 'unreachable', describe_connect_failure(error)
        if attempt == LOGIN_ATTEMPTS:
            return 'login rejected', describe_connect_failure(error)
    return 'login rejected', 'Login rejected'


def unused_path(directory, stem, extension):
    """A path in `directory` that does not exist yet, suffixing _2, _3 ... if
    needed. Two runs started inside the same second would otherwise share a
    log file, which is the one thing per-run logs exist to avoid."""
    path = os.path.join(directory, stem + extension)
    counter = 2
    while os.path.exists(path):
        path = os.path.join(directory, '{0}_{1}{2}'.format(stem, counter, extension))
        counter += 1
    return path


def first_line(text):
    """First non-blank line of an error, trimmed for a log column. Returns a
    placeholder rather than raising when SecureCRT gives back nothing useful."""
    for line in (text or '').splitlines():
        if line.strip():
            return line.strip()[:120]
    return 'no detail from SecureCRT'


def disconnect():
    try:
        if crt.Session.Connected:
            crt.Session.Disconnect()
    except Exception:
        pass


def main():
    folder = crt.Dialog.Prompt(
        'Session folder to walk, e.g. "Switches\\Site A".\n'
        'Leave blank to walk every saved session.',
        'Bulk capture - scope', '', False)
    if folder is None:
        return

    sessions, duplicates = dedupe_by_host(find_sessions(folder.strip()))
    if not sessions:
        crt.Dialog.MessageBox(
            'No saved sessions found under:\n{0}\n\nFolder filter: {1}'
            .format(os.path.join(config_path(), 'Sessions'), folder or '(none)'),
            'Nothing to do')
        return

    output_dir = crt.Dialog.Prompt('Write checklists and the run log to:',
                                   'Bulk capture - output folder', OUTPUT_DIR)
    if not output_dir:
        return
    try:
        if not os.path.isdir(output_dir):
            os.makedirs(output_dir)
    except OSError as error:
        crt.Dialog.MessageBox('Could not create {0}:\n{1}'.format(output_dir, error),
                              'Cannot write there')
        return

    # Settled once, here, and not per switch. A walk that cannot audit anything
    # it collects should say so before it connects to six hundred devices, not
    # after - and the answer is the same for all of them, since it is a fact
    # about this machine.
    repo, python, why_not = capture_l2s.find_audit()
    runner = (repo, python) if repo else None
    if not runner:
        if crt.Dialog.MessageBox(
                'The audit cannot run on this machine, so no checklists can be '
                'written here:\n\n{0}\n\nCollect captures instead? They can be '
                'audited on a machine with the repo:\n\n'
                '  python l2_stig_audit.py <name> --from-capture <file> '
                '--to-cklb <folder>\n\nCollect captures only?'.format(why_not),
                'No audit available here', 4 | 48) != 6:  # MB_YESNO | MB_ICONWARNING
            return

    done = read_index(output_dir) if runner else {}
    pending, already = [], []
    for session_path, host in sessions:
        key = index_key(session_path, host)
        if runner:
            finished = key in done
        else:
            # Capture-only mode resumes the way this script always did.
            finished = os.path.exists(os.path.join(output_dir, key))
        (already if finished else pending).append((session_path, host))
    done_already = len(already)

    product = 'checklist' if runner else 'capture'
    if crt.Dialog.MessageBox(
            '{0} device(s) to visit{1}.\n'
            '{2} already have a {6} in this folder and will be skipped.\n'
            '{3} to collect.\n\n'
            'This connects to each one in turn using its saved credentials. '
            'Nothing is configured. Expect roughly {4} minutes.\n\n'
            'To stop early, create a file named {5} in the output folder.\n\n'
            'Begin?'.format(len(sessions),
                            ' ({0} duplicate session(s) collapsed)'.format(len(duplicates))
                            if duplicates else '',
                            done_already, len(pending),
                            max(1, len(pending) // 2), STOP_FILE, product),
            'Bulk capture', 4 | 32) != 6:  # MB_YESNO | MB_ICONQUESTION; 6 = IDYES
        return

    # Which checklist name belongs to which session, so a second switch with
    # the same hostname is kept apart from the first rather than landing on it.
    claimed = dict((checklist, key) for key, checklist in done.items())
    work_dir = os.path.join(output_dir, WORK_DIR)
    if runner:
        try:
            if not os.path.isdir(work_dir):
                os.makedirs(work_dir)
        except OSError as error:
            crt.Dialog.MessageBox('Could not create {0}:\n{1}'.format(work_dir, error),
                                  'Cannot write there')
            return

    log = RunLog(output_dir)
    # Both of these are recorded rather than silently dropped, so that one run's
    # log accounts for every session in the list - the switches this run visited
    # and the ones it had no need to. "Why is this switch not in the results"
    # has to be answerable from a single file.
    for session_path, host, kept in duplicates:
        log.record(session_path, host, 'duplicate', 'same host as ' + kept)
    for session_path, host in already:
        key = index_key(session_path, host)
        log.record(session_path, host, 'already done', done.get(key, key))
    stop_path = os.path.join(output_dir, STOP_FILE)
    stopped = False

    def visit_one(index, session_path, host):
        """Everything one switch gets: connect, collect, audit, record.

        A closure rather than a top-level function because it needs the whole
        run's state - the log, the output folder, the audit runner, the names
        already claimed - and threading six arguments through would make the
        loop harder to read rather than easier."""
        # Progress goes to the status bar, never a dialog: a modal box inside
        # the loop would halt an overnight run until someone clicked.
        crt.Session.SetStatusText('Capturing {0}/{1}: {2}'
                                  .format(index, len(pending), session_path))

        outcome, comment = connect_session(session_path)
        if outcome:
            # Nothing was read off this switch, so its model and release
            # columns stay blank rather than carrying a guess. The comment is
            # what the morning after works from.
            log.record(session_path, host, outcome, comment)
            return

        try:
            hostname, outputs = capture_l2s.collect()
        except capture_l2s.CollectionError as refused:
            log.record(session_path, host, 'refused', refused.reason)
            return

        # Read once, here, and handed to every row this switch produces: the
        # log says what hardware and software were found whatever happens to
        # the checklist afterwards.
        model = capture_l2s.show_version_model(outputs.get('show version', ''))
        # The config's hostname rather than the prompt's, so a row and the
        # checklist it produced name the same switch - the audit reads this one.
        named = capture_l2s.running_config_hostname(
            outputs.get('show running-config', '')) or hostname

        def record(outcome, comment=''):
            log.record(session_path, host, outcome, comment, hostname=named, model=model)

        key = index_key(session_path, host)
        path = os.path.join(output_dir, key)
        try:
            with open(path, 'w', encoding='utf-8') as capture_file:
                capture_file.write(capture_l2s.render(outputs))
        except OSError as error:
            record('write failed', str(error)[:120])
            return

        # The switch has been visited by this point, so an audit that fails
        # keeps its capture: the connection is the expensive half and it is
        # already spent. `audit failed` is its own outcome in the log, which is
        # what keeps it distinguishable from a switch never reached.
        if not runner:
            record('captured', key)
            return

        checklist, detail = capture_l2s.run_audit(path, hostname, work_dir, runner=runner)
        if not checklist:
            record('audit failed', first_line(detail))
            return

        try:
            name, collided = place_checklist(output_dir, checklist, key, claimed)
        except OSError as error:
            record('write failed', str(error)[:120])
            return

        capture_l2s.remove_file(path)
        claimed[name] = key
        append_index(output_dir, key, name, hostname)
        record('checklisted',
               name + (' (hostname already used by another switch)' if collided else ''))

    crt.Screen.Synchronous = True
    try:
        for index, (session_path, host) in enumerate(pending, 1):
            if os.path.exists(stop_path):
                stopped = True
                break
            # Nothing that happens to one switch may end the walk. The failures
            # visit_one names are handled where they happen; this is for the
            # ones it does not - a log or index write failing because the share
            # dropped, a SecureCRT call raising something undocumented, a
            # switch whose output breaks an assumption nobody has met yet. Six
            # hundred devices is enough to make the unhandled case a certainty
            # rather than a worry, and the cost of meeting it at switch 12 used
            # to be the other 588.
            try:
                visit_one(index, session_path, host)
            except Exception as error:
                # The logger is inside this handler because it is one of the
                # things that can fail. If it does the walk still continues: a
                # lost log line is worth less than the rest of the night.
                try:
                    log.record(session_path, host, 'error', first_line(str(error)))
                except Exception:
                    pass
            disconnect()
    finally:
        crt.Screen.Synchronous = False
        try:
            crt.Session.SetStatusText('')
        except Exception:
            pass
        # Empty unless an audit died between writing and being moved, in which
        # case what is in it is a checklist nobody indexed - left where the log
        # can point at it rather than deleted.
        try:
            os.rmdir(work_dir)
        except OSError:
            pass

    crt.Dialog.MessageBox(
        '{0}\n\n{1}\n\n{2} are in:\n{3}\n\nThis run\'s log:\n{4}\n\n'
        'That log accounts for every session in the list, including the ones '
        'already done - so it can be counted in a spreadsheet as it stands. '
        'Re-running this script visits only the switches not yet done; any '
        'switch logged as `audit failed` kept its capture beside the '
        'checklists.'
        .format('Run stopped early by the STOP file.' if stopped else 'Run complete.',
                log.summary() or 'nothing collected',
                'Checklists' if runner else 'Captures', output_dir, log.path),
        'Bulk capture finished')


# See capture_l2s.py's tail: SecureCRT injects `crt` before running, so this is
# truthy there and None on a plain import, which is what lets the tests drive
# main() with a stand-in and no terminal anywhere.
if crt is not None:
    capture_l2s.crt = crt
    main()
