# $language = "Python3"
# $interface = "1.0"

"""Run backup.py against every saved SecureCRT session, unattended: each
switch's running-config and VLAN database into <hostname>.txt, then a verdict -
how many switches it backed up, out of how many it was pointed at.

Read-only. Each switch gets `terminal length 0`, `show running-config` and
`show vlan brief`, exactly as the single-switch run sends them, and nothing is
configured.

THE FILES
One per switch, named by the hostname in its config, in one folder. A switch
backed up before is REPLACED - written beside the old file and swapped in only
once complete, so a switch that fails this time keeps its last good backup.

Two switches in one run reporting the same hostname would land on one file,
the second silently replacing the first. So the second is written as
<hostname>_<address>.txt instead and its log row says why; nothing is lost and
nothing is overwritten that this run itself wrote.

THE VERDICT AND THE LOG
One CSV row per session in the list, including the ones nothing answered from,
and a closing dialog that counts them:

  Backed up 37 of 40 switch(es).
  Not backed up: unreachable 2, refused 1.

`refused` is a switch that answered but whose output could not be trusted - a
config cut short, paged or empty output, not in enable mode. Nothing was
written for it. The verdict is also written beside the log as
<log>_verdict.txt, so it survives the dialog.

It never aborts a run. A switch that is offline, refusing credentials or not a
Cisco switch is logged and the walk moves on. Drop a file named STOP in the
backup folder to end the run cleanly after the current switch.
"""

import os
import os.path
import time

crt = globals().get('crt')

import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cklb_collect
import cklb_collect_bulk as bulk
import backup as backup

# SecureCRT keeps one Python running between script runs, and Python imports a
# module only once - so without this, the copy of a helper that runs is the one
# loaded the first time, not the one on disk now, until SecureCRT restarts.
# Each helper's `crt` is cleared first: a helper runs its own main() when it
# finds `crt` in its globals, and the last run handed it one - reloaded with it
# still there, every helper would start as if SecureCRT had launched it.
if crt is not None:
    import importlib
    for _module in (cklb_collect, bulk, backup):
        _module.crt = None
        importlib.reload(_module)


OUTPUT_DIR = backup.OUTPUT_DIR
STOP_FILE = 'STOP'
SESSIONS_SHOWN = 12

# SecureCRT MessageBox flags and answers.
MB_YESNO = 4
MB_ICONQUESTION = 32
IDYES = 6

BACKED_UP = 'backed up'
REFUSED = 'refused'

LOG_COLUMNS = ('hostname', 'ip_address', 'outcome', 'detail', 'file', 'session', 'timestamp')


class RunLog:
    def __init__(self, directory):
        self.path = bulk.unused_path(directory,
                                     'backup_log_' + time.strftime('%Y%m%d_%H%M%S'), '.csv')
        self.counts = {}
        with open(self.path, 'w', encoding='utf-8') as handle:
            handle.write(','.join(LOG_COLUMNS) + '\n')

    def record(self, session_path, host, outcome, detail='', hostname='', path=''):
        self.counts[outcome] = self.counts.get(outcome, 0) + 1
        row = (hostname or session_path, host, outcome, detail, path, session_path,
               time.strftime('%Y-%m-%d %H:%M:%S'))
        with open(self.path, 'a', encoding='utf-8') as handle:
            handle.write(','.join('"{0}"'.format(str(f).replace('"', "'")) for f in row) + '\n')


def verdict(counts, total):
    """Counted against every distinct switch in the list, not the ones reached:
    a run stopped at switch 40 of 600 backed up 40 at best."""
    lines = ['Backed up {0} of {1} switch(es).'.format(counts.get(BACKED_UP, 0), total)]
    others = sorted((name, n) for name, n in counts.items()
                    if name not in (BACKED_UP, 'duplicate'))
    if others:
        lines.append('Not backed up: ' + ', '.join('{0} {1}'.format(name, n)
                                                   for name, n in others) + '.')
    if counts.get('duplicate'):
        lines.append('{0} duplicate session(s) collapsed, not counted.'.format(counts['duplicate']))
    return '\n'.join(lines)


def main():
    folder = crt.Dialog.Prompt(
        'Session folder to back up, e.g. "Switches/Site A".\n'
        'Leave blank for every saved session.',
        'Switch backup bulk - scope', '', False)
    if folder is None:
        return
    sessions, duplicates = bulk.dedupe_by_host(bulk.find_sessions(folder.strip()))
    if not sessions:
        crt.Dialog.MessageBox(
            'No saved sessions found under:\n{0}\n\nFolder filter: {1}'
            .format(os.path.join(bulk.config_path(), 'Sessions'), folder or '(none)'),
            'Nothing to do')
        return

    output_dir = crt.Dialog.Prompt('Save the backups (and the run log) into:',
                                   'Switch backup bulk - folder', OUTPUT_DIR)
    if not output_dir:
        return
    if not os.path.isabs(output_dir):
        output_dir = os.path.join(OUTPUT_DIR, output_dir)
    try:
        if not os.path.isdir(output_dir):
            os.makedirs(output_dir)
        log = RunLog(output_dir)
    except OSError as error:
        crt.Dialog.MessageBox('Could not write to {0}:\n{1}'.format(output_dir, error),
                              'Cannot write there')
        return

    listed = '\n'.join('  ' + path for path, _host in sessions[:SESSIONS_SHOWN])
    if len(sessions) > SESSIONS_SHOWN:
        listed += '\n  ...and {0} more'.format(len(sessions) - SESSIONS_SHOWN)
    if crt.Dialog.MessageBox(
            '{0} switch(es) to back up{1}:\n{2}\n\n'
            'Each: show running-config and show vlan brief into <hostname>.txt in\n  {3}\n'
            'A switch backed up there before has its file replaced. Nothing is configured.\n\n'
            'To stop early, create a file named {4} in that folder.\n\nBegin?'
            .format(len(sessions),
                    ' ({0} duplicate session(s) collapsed)'.format(len(duplicates))
                    if duplicates else '', listed, output_dir, STOP_FILE),
            'Switch backup bulk - confirm', MB_YESNO | MB_ICONQUESTION) != IDYES:
        return

    for session_path, host, kept in duplicates:
        log.record(session_path, host, 'duplicate', 'same address as ' + kept)
    stop_path = os.path.join(output_dir, STOP_FILE)
    stopped = False
    connect_state = {}
    # hostname -> the session whose backup this run wrote under that name.
    written = {}

    def visit_one(index, session_path, host):
        crt.Session.SetStatusText('Backup {0}/{1}: {2}'.format(index, len(sessions),
                                                               session_path))
        outcome, comment = bulk.connect_session(session_path, connect_state)
        if outcome:
            _ip, label = bulk.session_name_parts(session_path)
            log.record(session_path, host, outcome, comment, label)
            return
        prompt = cklb_collect.read_prompt()
        try:
            hostname, config, vlans = backup.collect(prompt)
        except backup.BackupError as refused:
            log.record(session_path, host, REFUSED,
                       '{0}: {1}'.format(refused.title, bulk.first_line(str(refused))),
                       prompt.rstrip('#>').strip())
            return
        detail = 'running-config and VLANs' if vlans is not None else 'running-config only'
        name = None
        key = hostname.lower()
        if key in written:
            name = '{0}_{1}'.format(hostname, host or session_path)
            detail += '; hostname also used this run by ' + written[key]
        try:
            path, replaced = backup.save(output_dir, hostname, host, config, vlans, name)
        except OSError as error:
            log.record(session_path, host, 'write failed', bulk.first_line(str(error)), hostname)
            return
        written.setdefault(key, session_path)
        if replaced:
            detail += '; replaced the previous backup'
        log.record(session_path, host, BACKED_UP, detail, hostname, path)

    crt.Screen.Synchronous = True
    try:
        for index, (session_path, host) in enumerate(sessions, 1):
            if os.path.exists(stop_path):
                stopped = True
                break
            # Nothing that happens to one switch may end the walk.
            try:
                visit_one(index, session_path, host)
            except cklb_collect.CollectionError as refused:
                try:
                    log.record(session_path, host, REFUSED, refused.reason)
                except Exception:
                    pass
            except Exception as error:
                try:
                    log.record(session_path, host, 'error', bulk.first_line(str(error)))
                except Exception:
                    pass
            bulk.disconnect()
    finally:
        crt.Screen.Synchronous = False
        try:
            crt.Session.SetStatusText('')
        except Exception:
            pass

    summary = verdict(log.counts, len(sessions))
    if stopped:
        summary += '\nStopped early by the STOP file - {0} switch(es) not visited.'.format(
            len(sessions) - sum(n for name, n in log.counts.items() if name != 'duplicate'))
    verdict_path = log.path[:-len('.csv')] + '_verdict.txt'
    try:
        with open(verdict_path, 'w', encoding='utf-8') as handle:
            handle.write(summary + '\n')
    except OSError:
        verdict_path = '(not written)'
    crt.Dialog.MessageBox(
        '{0}\n\nBackups in:\n{1}\nRun log:\n{2}\nVerdict:\n{3}\n\nOne row per session, including '
        'the ones nothing answered from.'.format(summary, output_dir, log.path, verdict_path),
        'Switch backup bulk - verdict')


if crt is not None:
    cklb_collect.crt = crt
    bulk.crt = crt
    backup.crt = crt
    main()
