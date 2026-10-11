# $language = "Python3"
# $interface = "1.0"

"""Run snmp_acl_l2s.py's push against every saved SecureCRT session,
unattended, and end with a verdict: how many switches it completed, out of how
many it was pointed at.

READ THIS FIRST - THIS SCRIPT CONFIGURES DEVICES
It logs into switches on its own authority and writes to running-config.
Run snmp_acl_l2s.py on ONE production switch first and check that switch by
hand; this is for after that.

SAVING
The run asks once, up front, whether to save. Yes sends `write memory` on each
switch that COMPLETED - the read-back below found every permit in front of the
deny - and only on those, before disconnecting. That read-back is the check a
person would otherwise do by hand on each switch. A switch that failed,
was skipped or never answered is not saved, so a reload still reverts anything
half-applied there. No leaves startup-config alone everywhere, as before.

WHAT EACH SWITCH GETS
Exactly what snmp_acl_l2s.py sends, from the same inventory.yaml `snmp`
section: `snmp-server host ... version 3 priv <user>`, the permits inserted in
front of the ACL's deny at numbers read off THAT switch, `log` added to every
existing permit that lacks it (replaced at its own number, one at a time), and
the resequence.
Each switch's ACL is read before anything is sent, so the sequence numbers are
right for each switch rather than for the one the run was tested on.

WHAT IT DOES DIFFERENTLY FROM THE SINGLE-SWITCH RUN
Nobody is watching, so two decisions are made up front instead of per switch:

  A switch whose ACL is a vty access-class is SKIPPED, not pushed. The single
  run warns and lets a person decide; here nobody would read the warning, and
  a permit in a vty ACL grants an SSH login rather than SNMP polling.

  A switch with no room under the deny is renumbered first only if the run was
  told to at the start. Renumbering keeps the order and changes no access
  decision, but it is still a change, so it is asked once rather than assumed.

THE VERDICT AND THE LOG
One CSV row per session in the list, including the ones nothing answered from,
and a closing dialog that counts them:

  Completed on 37 of 40 switch(es).
    2 of those completed with a warning - see the warnings column.
  FAILED on 1: commands were sent and the read-back disagrees.
  Not changed: skipped 1, unreachable 1.

`completed` is decided from the ACL read back after the push - every permit
present and in front of the deny, no rejected command - not from the commands
having been accepted. `failed` is the only outcome where something was sent
and is wrong; every other one left the switch as it was. The verdict is also
written beside the log as <log>_verdict.txt, so it survives the dialog.
When saving, the verdict also counts how many completed switches were saved;
a `write memory` that does not answer [OK] is named in that switch's warnings.

It never aborts a run. A switch that is offline, refusing credentials, not a
Cisco switch, or missing the ACL is logged and the walk moves on. Drop a file
named STOP in the log folder to end the run cleanly after the current switch.
"""

import os
import os.path
import time

crt = globals().get('crt')

import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import capture_l2s
import capture_l2s_bulk as bulk
import harden_l2s_bulk as harden
import snmp_acl_l2s as snmp

# SecureCRT keeps one Python running between script runs, and Python imports a
# module only once - so without this, the copy of a helper that runs is the one
# loaded the first time, not the one on disk now, until SecureCRT restarts.
if crt is not None:
    import importlib
    for _module in (capture_l2s, bulk, harden, snmp):
        importlib.reload(_module)


OUTPUT_DIR = snmp.OUTPUT_DIR
STOP_FILE = 'STOP'
SESSIONS_SHOWN = 12
SAVE_COMMAND = 'write memory'


def save_config(prompt):
    """Write running-config to startup-config. Returns '' when IOS answered
    [OK], otherwise a short reason for the log."""
    try:
        reply = capture_l2s.run_command(SAVE_COMMAND, prompt)
    except Exception as error:
        return bulk.first_line(str(error))
    if '[OK]' in reply:
        return ''
    return bulk.first_line(reply.strip()) or 'no [OK] in the reply'


def preview(settings):
    """The commands every switch gets, with the per-switch parts named as such."""
    acl_name, permits, hosts, (start, increment), insert_at = settings
    lines = ['  ' + snmp.snmp_host_command(ip, user) for ip, user in hosts]
    lines.append('  ip access-list standard {0}'.format(acl_name))
    for offset, spec in enumerate(permits):
        number = insert_at + offset if insert_at is not None else '<n>'
        lines.append('    {0} {1}'.format(number, snmp.with_log('permit ' + spec)))
    lines.append('  exit')
    lines.append('  ' + snmp.resequence_command(acl_name, start, increment))
    if insert_at is None:
        lines.append('\n  <n> is read off each switch: the gap just below its first deny.')
    else:
        lines.append('\n  Pinned at {0}: a switch where any of those numbers is taken, or sits '
                     'past the deny, is skipped.'.format(insert_at))
    lines.append('  Permits already in a switch\'s list are not added again.')
    lines.append('  Every permit there without log is replaced at its own number with log '
                 '(no N, then N ... log).')
    return '\n'.join(lines)


def main():
    # The two files are updated together; an older snmp_acl_l2s.py beside a
    # newer bulk script would push without adding log to existing permits.
    if not hasattr(snmp, 'relog_plan'):
        crt.Dialog.MessageBox(
            'snmp_acl_l2s.py in this folder is an older version than this script:\n{0}\n\n'
            'Copy the current snmp_acl_l2s.py there and run again. Nothing was sent.'
            .format(snmp.__file__), 'SNMP ACL bulk - out of date')
        return
    try:
        settings = snmp.settings_from_inventory()
    except snmp.AclError as error:
        crt.Dialog.MessageBox('{0}\n\nNothing was sent.'.format(error), 'SNMP ACL bulk - inventory')
        return
    if settings is None:
        return

    folder = crt.Dialog.Prompt(
        'Session folder to push to, e.g. "Switches/Site A".\n'
        'Leave blank for every saved session.',
        'SNMP ACL bulk - scope', '', False)
    if folder is None:
        return
    sessions, duplicates = bulk.dedupe_by_host(bulk.find_sessions(folder.strip()))
    if not sessions:
        crt.Dialog.MessageBox(
            'No saved sessions found under:\n{0}\n\nFolder filter: {1}'
            .format(os.path.join(bulk.config_path(), 'Sessions'), folder or '(none)'),
            'Nothing to do')
        return

    output_dir = crt.Dialog.Prompt('Write the run log to:', 'SNMP ACL bulk - log folder',
                                   OUTPUT_DIR)
    if not output_dir:
        return
    log, why = snmp.make_log(output_dir, 'snmp_acl_bulk_log_')
    if log is None:
        crt.Dialog.MessageBox('Could not write to {0}:\n{1}'.format(output_dir, why),
                              'Cannot write there')
        return

    renumber = False
    if settings[4] is None:
        renumber = crt.Dialog.MessageBox(
            'Where a switch has no room for the permits under its deny, renumber its {0} '
            'first?\n\nThe order is kept and no access decision changes - and it is '
            'renumbered at the end either way. No leaves those switches skipped, for a '
            'person to look at.'.format(settings[0]),
            'SNMP ACL bulk - renumber when needed?', snmp.MB_YESNO) == snmp.IDYES

    save = crt.Dialog.MessageBox(
        'Save to startup-config (write memory) on each switch that completes?\n\n'
        'Only switches whose ACL read back correctly - every permit in front of the '
        'deny - are saved. Failed, skipped and unreachable switches are not.\n\n'
        'No leaves startup-config alone on every switch, so a reload reverts the run.',
        'SNMP ACL bulk - save when completed?', snmp.MB_YESNO) == snmp.IDYES

    listed = '\n'.join('  ' + path for path, _host in sessions[:SESSIONS_SHOWN])
    if len(sessions) > SESSIONS_SHOWN:
        listed += '\n  ...and {0} more'.format(len(sessions) - SESSIONS_SHOWN)
    if crt.Dialog.MessageBox(
            '{0} switch(es) to configure{1}:\n{2}\n\n'
            'THIS WRITES TO running-config ON EVERY ONE OF THEM.\n\n'
            'Each gets:\n{3}\n\n'
            'A switch whose {4} is a vty access-class is skipped.{5}\n'
            '{7}\n\n'
            'To stop early, create a file named {6} in the log folder.\n\nBegin?'
            .format(len(sessions),
                    ' ({0} duplicate session(s) collapsed)'.format(len(duplicates))
                    if duplicates else '', listed, preview(settings), settings[0],
                    '\nNo room under the deny: renumbered first.' if renumber else '',
                    STOP_FILE,
                    'Each COMPLETED switch is saved (write memory).' if save
                    else 'startup-config is NOT written.'),
            'SNMP ACL bulk - confirm', snmp.MB_YESNO | snmp.MB_ICONWARNING) != snmp.IDYES:
        return

    for session_path, host, kept in duplicates:
        log.record(session_path, host, 'duplicate', 'same address as ' + kept)
    stop_path = os.path.join(output_dir, STOP_FILE)
    stopped = False
    connect_state = {}
    saves = {'saved': 0, 'unsaved': 0}

    def visit_one(index, session_path, host):
        crt.Session.SetStatusText('SNMP ACL {0}/{1}: {2}'.format(index, len(sessions),
                                                                 session_path))
        outcome, comment = bulk.connect_session(session_path, connect_state)
        if outcome:
            _ip, label = bulk.session_name_parts(session_path)
            log.record(session_path, host, outcome, comment, label)
            return
        prompt = capture_l2s.read_prompt()
        result = snmp.apply(prompt, settings, renumber_if_no_room=renumber, refuse_vty=True)
        if save and result.outcome == snmp.COMPLETED:
            problem = save_config(prompt)
            if problem:
                saves['unsaved'] += 1
                result.warnings.append('NOT saved to startup-config: ' + problem)
            else:
                saves['saved'] += 1
                result.reason += '; saved to startup-config'
        log.record(session_path, host, result.outcome, result.reason, result.hostname, result)

    crt.Screen.Synchronous = True
    try:
        for index, (session_path, host) in enumerate(sessions, 1):
            if os.path.exists(stop_path):
                stopped = True
                break
            # Nothing that happens to one switch may end the walk.
            try:
                visit_one(index, session_path, host)
            except capture_l2s.CollectionError as refused:
                try:
                    log.record(session_path, host, 'refused', refused.reason)
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

    # Counted against the whole list, not the switches reached: a run stopped
    # at switch 40 of 600 completed 40 at best, and saying "40 of 40" would
    # read as a finished fleet.
    summary = snmp.verdict(log.counts, len(sessions), log.warned)
    if save:
        summary += '\nSaved to startup-config on {0} of {1} completed.'.format(
            saves['saved'], log.counts.get(snmp.COMPLETED, 0))
        if saves['unsaved']:
            summary += ('\n  {0} completed but NOT saved - write memory did not answer [OK]; '
                        'see the warnings column.'.format(saves['unsaved']))
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
        '{0}\n\nRun log:\n{1}\nVerdict:\n{2}\n\nOne row per session, including the ones '
        'nothing answered from.\n{3}'
        .format(summary, log.path, verdict_path,
                'Only completed switches were saved; nothing else was written to startup-config.'
                if save else
                'startup-config was NOT written on any switch. Check, then save deliberately.'),
        'SNMP ACL bulk - verdict')


if crt is not None:
    capture_l2s.crt = crt
    bulk.crt = crt
    harden.crt = crt
    snmp.crt = crt
    main()
