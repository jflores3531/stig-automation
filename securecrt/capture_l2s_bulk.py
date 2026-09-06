# $language = "Python3"
# $interface = "1.0"

"""Collect L2 switch STIG captures from every saved SecureCRT session, unattended.

Run this from SecureCRT (Script > Run...) with no session connected, or with
any session connected - it opens and closes its own. For each saved session it
connects using the credentials SecureCRT already holds, sends the read-only
show commands, writes a capture file, and disconnects. Nothing is
configured on any device. The only non-show command sent is `terminal length 0`,
which is session-scoped.

Afterwards, audit everything collected in one pass:

    for %f in (C:\\Documents\\netauto_captures\\*.capture) do ^
        python l2_stig_audit.py %~nf --from-capture "%f" --to-cklb C:\\Documents\\checklists

Given a directory, the audit names each checklist for the switch it audited, the
date its capture was taken, and the STIG versions in the checklist - so one
output folder holds the whole fleet without any of them writing over another.

Collection and audit stay separate on purpose. Auditing inside the loop would
launch a Python subprocess per switch, and a failed audit would be
indistinguishable from a failed capture in the log.

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


# Where captures and the run log are written. Deliberately a stable path rather
# than a timestamped one: a re-run skips sessions whose capture already exists,
# which is what makes a five-hour job resumable after it dies at switch 400.
OUTPUT_DIR = r'C:\Documents\netauto_captures'

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
    field (a serial or local-shell session, say)."""
    stem = hostname or session_path
    for bad in '\\/:*?"<>| ':
        stem = stem.replace(bad, '_')
    return stem + '.capture'


def looks_rejected(error_text):
    lowered = (error_text or '').lower()
    return any(marker in lowered for marker in REJECTION_MARKERS)


class RunLog:
    """One line per switch: what was tried, what happened, when.

    This is the coverage record, not just a debugging aid. A STIG audit of six
    hundred switches has to account for all six hundred, and "42 unreachable,
    here they are" is part of the deliverable.

    One file per run, named for when the run started, so each file can be
    opened in a spreadsheet and counted directly - no picking the newest row
    per switch out of an accumulated history. Which is also why a run logs the
    switches it *skipped* as already captured: without those rows the second
    pass would produce a log of forty devices and no trace of the other five
    hundred and sixty, and a log that only accounts for the switches it visited
    is not a census. Every run's file is a complete account of the whole list."""

    def __init__(self, directory):
        self.path = unused_path(directory,
                                'run_log_' + time.strftime('%Y%m%d_%H%M%S'), '.csv')
        self.counts = {}
        with open(self.path, 'w', encoding='utf-8') as handle:
            handle.write('timestamp,session,host,outcome,detail\n')

    def record(self, session_path, host, outcome, detail=''):
        self.counts[outcome] = self.counts.get(outcome, 0) + 1
        row = [time.strftime('%Y-%m-%d %H:%M:%S'), session_path, host, outcome, detail]
        with open(self.path, 'a', encoding='utf-8') as handle:
            handle.write(','.join('"{0}"'.format(str(f).replace('"', "'")) for f in row) + '\n')

    def summary(self):
        return ', '.join('{0}: {1}'.format(name, self.counts[name])
                         for name in sorted(self.counts))


def connect_session(session_path):
    """Connect to a saved session. Returns '' on success, or a short reason.

    SecureCRT raises on a failed connect and puts the detail in
    GetLastErrorMessage(). A rejected login is retried once; anything else is
    treated as unreachable and skipped without a retry."""
    for attempt in range(1, LOGIN_ATTEMPTS + 1):
        error = ''
        try:
            crt.Session.Connect('/S "{0}"'.format(session_path), True)
        except Exception:
            error = crt.GetLastErrorMessage() or 'connect failed'
        if crt.Session.Connected:
            return ''
        detail = first_line(error)
        if not looks_rejected(error):
            return 'unreachable: ' + detail
        if attempt == LOGIN_ATTEMPTS:
            return 'login rejected: ' + detail
    return 'login rejected: ' + detail


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

    output_dir = crt.Dialog.Prompt('Write captures and the run log to:',
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

    pending, already = [], []
    for session_path, host in sessions:
        target = os.path.join(output_dir, capture_name(session_path, host))
        (already if os.path.exists(target) else pending).append((session_path, host))
    done_already = len(already)

    if crt.Dialog.MessageBox(
            '{0} device(s) to visit{1}.\n'
            '{2} already have a capture in this folder and will be skipped.\n'
            '{3} to collect.\n\n'
            'This connects to each one in turn using its saved credentials. '
            'Nothing is configured. Expect roughly {4} minutes.\n\n'
            'To stop early, create a file named {5} in the output folder.\n\n'
            'Begin?'.format(len(sessions),
                            ' ({0} duplicate session(s) collapsed)'.format(len(duplicates))
                            if duplicates else '',
                            done_already, len(pending),
                            max(1, len(pending) // 2), STOP_FILE),
            'Bulk capture', 4 | 32) != 6:  # MB_YESNO | MB_ICONQUESTION; 6 = IDYES
        return

    log = RunLog(output_dir)
    # Both of these are recorded rather than silently dropped, so that one run's
    # log accounts for every session in the list - the switches this run visited
    # and the ones it had no need to. "Why is this switch not in the results"
    # has to be answerable from a single file.
    for session_path, host, kept in duplicates:
        log.record(session_path, host, 'duplicate', 'same host as ' + kept)
    for session_path, host in already:
        log.record(session_path, host, 'already captured',
                   capture_name(session_path, host))
    stop_path = os.path.join(output_dir, STOP_FILE)
    stopped = False

    crt.Screen.Synchronous = True
    try:
        for index, (session_path, host) in enumerate(pending, 1):
            if os.path.exists(stop_path):
                stopped = True
                break

            # Progress goes to the status bar, never a dialog: a modal box
            # inside the loop would halt an overnight run until someone clicked.
            crt.Session.SetStatusText('Capturing {0}/{1}: {2}'
                                      .format(index, len(pending), session_path))

            failure = connect_session(session_path)
            if failure:
                log.record(session_path, host, failure.split(':')[0], failure)
                disconnect()
                continue

            try:
                hostname, outputs = capture_l2s.collect()
            except capture_l2s.CollectionError as refused:
                log.record(session_path, host, 'refused', refused.reason)
                disconnect()
                continue
            except Exception as error:
                log.record(session_path, host, 'error', str(error)[:120])
                disconnect()
                continue

            path = os.path.join(output_dir, capture_name(session_path, host))
            try:
                with open(path, 'w', encoding='utf-8') as capture_file:
                    capture_file.write(capture_l2s.render(outputs))
            except OSError as error:
                log.record(session_path, host, 'write failed', str(error)[:120])
                disconnect()
                continue

            log.record(session_path, host, 'captured', hostname)
            disconnect()
    finally:
        crt.Screen.Synchronous = False
        try:
            crt.Session.SetStatusText('')
        except Exception:
            pass

    crt.Dialog.MessageBox(
        '{0}\n\n{1}\n\nCaptures are in:\n{2}\n\nThis run\'s log:\n{3}\n\n'
        'That log accounts for every session in the list, including the ones '
        'already captured - so it can be counted in a spreadsheet as it stands. '
        'Re-running this script visits only the switches with no capture yet.'
        .format('Run stopped early by the STOP file.' if stopped else 'Run complete.',
                log.summary() or 'nothing collected', output_dir, log.path),
        'Bulk capture finished')


# See capture_l2s.py's tail: SecureCRT injects `crt` before running, so this is
# truthy there and None on a plain import, which is what lets the tests drive
# main() with a stand-in and no terminal anywhere.
if crt is not None:
    capture_l2s.crt = crt
    main()
