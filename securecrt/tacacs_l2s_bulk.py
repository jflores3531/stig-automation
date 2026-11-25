# $language = "Python3"
# $interface = "1.0"

"""Run tacacs_l2s.py's push against every saved SecureCRT session,
unattended, and end with a verdict: how many switches it completed, out of how
many it was pointed at.

READ THIS FIRST - THIS SCRIPT CONFIGURES DEVICES
It logs into switches on its own authority and writes to running-config.
Run tacacs_l2s.py on ONE production switch first, test a TACACS+ login on it
in a new session, and only then run this.

WHAT EACH SWITCH GETS
Exactly what tacacs_l2s.py sends, from the same inventory.yaml `tacacs`
section and secrets.yaml `tacacs_key`: servers in `remove` taken out of every
TACACS+ group and deleted, servers in `remove_from_group` taken out of
group_name, servers in `add` defined (or reused) and put in group_name. Each
switch is read first, so a server is found under whatever name THAT switch
gave it, and a new server is named with the lowest number free on THAT switch
(TACACS1, TACACS2, ...), so the same server may carry a different number on
different switches. The same refusals apply: no `aaa new-model`, or a push
that would empty a group a login method list uses - each is skipped with
nothing sent.

SAVING
Asked once, up front. Yes sends `write memory` only on switches that
COMPLETED - the read-back matched the declaration. No leaves startup-config
alone everywhere, so a reload reverts the run.

THE VERDICT AND THE LOG
One CSV row per session in the list, including the ones nothing answered from,
and a closing dialog that counts them, also written beside the log as
<log>_verdict.txt. It never aborts a run. Drop a file named STOP in the log
folder to end the run cleanly after the current switch.
"""

import os
import os.path

crt = globals().get('crt')

import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import capture_l2s
import capture_l2s_bulk as bulk
import harden_l2s_bulk as harden
import snmp_acl_l2s as snmp
import snmp_acl_l2s_bulk as snmp_bulk
import tacacs_l2s as tacacs

# See snmp_acl_l2s.py for why each helper is reloaded.
if crt is not None:
    import importlib
    for _module in (capture_l2s, bulk, harden, snmp, snmp_bulk, tacacs):
        _module.crt = None
        importlib.reload(_module)


OUTPUT_DIR = tacacs.OUTPUT_DIR
STOP_FILE = 'STOP'
SESSIONS_SHOWN = 12


def preview(settings):
    """What every switch gets, in the order it is sent."""
    lines = []
    if settings.remove:
        lines.append('  Out of every TACACS+ group, then deleted: ' + ', '.join(settings.remove))
    if settings.remove_from_group:
        lines.append('  Out of {0} (definition kept): {1}'.format(
            settings.group, ', '.join(settings.remove_from_group)))
    if settings.add:
        lines.append('  Into {0}: {1}'.format(settings.group, ', '.join(settings.add)))
        lines.append('    a new one is `tacacs server {0}<n>`, the lowest number free on '
                     'that switch, with the key from secrets.yaml{1}'
                     .format(settings.prefix,
                             ', timeout {0}'.format(settings.timeout)
                             if settings.timeout is not None else ''))
        lines.append('    one already defined is reused and its key left alone')
    return '\n'.join(lines)


def main():
    try:
        settings = tacacs.settings_from_inventory()
    except tacacs.TacacsError as error:
        crt.Dialog.MessageBox('{0}\n\nNothing was sent.'.format(error),
                              'TACACS bulk - inventory')
        return
    if settings is None:
        return

    folder = crt.Dialog.Prompt(
        'Session folder to push to, e.g. "Switches/Site A".\n'
        'Leave blank for every saved session.',
        'TACACS bulk - scope', '', False)
    if folder is None:
        return
    sessions, duplicates = bulk.dedupe_by_host(bulk.find_sessions(folder.strip()))
    if not sessions:
        crt.Dialog.MessageBox(
            'No saved sessions found under:\n{0}\n\nFolder filter: {1}'
            .format(os.path.join(bulk.config_path(), 'Sessions'), folder or '(none)'),
            'Nothing to do')
        return

    output_dir = crt.Dialog.Prompt('Write the run log to:', 'TACACS bulk - log folder',
                                   OUTPUT_DIR)
    if not output_dir:
        return
    log, why = tacacs.make_log(output_dir, 'tacacs_bulk_log_')
    if log is None:
        crt.Dialog.MessageBox('Could not write to {0}:\n{1}'.format(output_dir, why),
                              'Cannot write there')
        return

    save = crt.Dialog.MessageBox(
        'Save to startup-config (write memory) on each switch that completes?\n\n'
        'Only switches whose TACACS+ configuration read back as declared are saved. '
        'Failed, skipped and unreachable switches are not.\n\n'
        'No leaves startup-config alone on every switch, so a reload reverts the run.',
        'TACACS bulk - save when completed?', snmp.MB_YESNO) == snmp.IDYES

    listed = '\n'.join('  ' + path for path, _host in sessions[:SESSIONS_SHOWN])
    if len(sessions) > SESSIONS_SHOWN:
        listed += '\n  ...and {0} more'.format(len(sessions) - SESSIONS_SHOWN)
    if crt.Dialog.MessageBox(
            '{0} switch(es) to configure{1}:\n{2}\n\n'
            'THIS WRITES TO running-config ON EVERY ONE OF THEM.\n\n'
            'Each gets:\n{3}\n\n'
            'Skipped with nothing sent: no aaa new-model, or a push that would empty a '
            'group a login method list uses.\n'
            '{4}\n\n'
            'To stop early, create a file named {5} in the log folder.\n\nBegin?'
            .format(len(sessions),
                    ' ({0} duplicate session(s) collapsed)'.format(len(duplicates))
                    if duplicates else '', listed, preview(settings),
                    'Each COMPLETED switch is saved (write memory).' if save
                    else 'startup-config is NOT written.', STOP_FILE),
            'TACACS bulk - confirm', snmp.MB_YESNO | snmp.MB_ICONWARNING) != snmp.IDYES:
        return

    for session_path, host, kept in duplicates:
        log.record(session_path, host, 'duplicate', 'same address as ' + kept)
    stop_path = os.path.join(output_dir, STOP_FILE)
    stopped = False
    connect_state = {}
    saves = {'saved': 0, 'unsaved': 0}

    def visit_one(index, session_path, host):
        crt.Session.SetStatusText('TACACS {0}/{1}: {2}'.format(index, len(sessions),
                                                               session_path))
        outcome, comment = bulk.connect_session(session_path, connect_state)
        if outcome:
            _ip, label = bulk.session_name_parts(session_path)
            log.record(session_path, host, outcome, comment, label)
            return
        prompt = capture_l2s.read_prompt()
        result = tacacs.apply(prompt, settings)
        if save and result.outcome == tacacs.COMPLETED and result.ops:
            problem = snmp_bulk.save_config(prompt)
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
                text = bulk.first_line(str(error))
                if settings.key:
                    text = text.replace(settings.key, tacacs.KEY_MASK)
                try:
                    log.record(session_path, host, 'error', text)
                except Exception:
                    pass
            bulk.disconnect()
    finally:
        crt.Screen.Synchronous = False
        try:
            crt.Session.SetStatusText('')
        except Exception:
            pass

    summary = snmp.verdict(log.counts, len(sessions), log.warned)
    if save:
        summary += '\nSaved to startup-config on {0} switch(es) that changed.'.format(
            saves['saved'])
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
        'TACACS bulk - verdict')


if crt is not None:
    capture_l2s.crt = crt
    bulk.crt = crt
    harden.crt = crt
    snmp.crt = crt
    snmp_bulk.crt = crt
    tacacs.crt = crt
    main()
