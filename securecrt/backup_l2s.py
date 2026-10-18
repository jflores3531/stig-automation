# $language = "Python3"
# $interface = "1.0"

"""Back up the switch in the current SecureCRT session: its running-config and
its VLAN database, in one file named after the switch.

    <hostname>.txt

Run it from a session that is connected and in enable mode (Script > Run...).
The file is the same layout scripts/backup_config.py writes - a short header,
`show running-config`, then `show vlan brief` - so a backup taken either way
reads the same.

The VLANs are there because they are not in the running-config: a switch in
VTP server or client mode keeps them in vlan.dat, and a restore from the
running-config alone brings the ports back pointing at VLANs that no longer
exist.

The file is named by the hostname alone, so running this again on the same
switch REPLACES its last backup. The new file is written beside the old one
and swapped in only once it is complete, so a run that fails part way leaves
the previous backup as it was.

Nothing is configured. The only command sent that is not a show is
`terminal length 0`, which turns paging off for this session only.
"""

import os
import os.path
import time

# `crt` is injected by SecureCRT into this script's globals, not into the
# modules it imports - so capture_l2s gets it handed over at the bottom.
crt = globals().get('crt')

import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import capture_l2s

# SecureCRT keeps one Python running between script runs, and Python imports a
# module only once - so without this, the copy of a helper that runs is the one
# loaded the first time, not the one on disk now, until SecureCRT restarts.
# Its `crt` is cleared first: capture_l2s runs its own main() when it finds
# `crt` in its globals, and an earlier run may have handed it one.
if crt is not None:
    import importlib
    capture_l2s.crt = None
    importlib.reload(capture_l2s)


# Where backups go. Created if missing; the save dialog shows it and lets it be
# changed for the run.
OUTPUT_DIR = r'C:\Documents\switch_backups'

CONFIG_COMMAND = 'show running-config'
VLAN_COMMAND = 'show vlan brief'

# What IOS answers to a command the platform does not have. A router has no
# VLAN database, and its backup is the running-config alone, as in
# backup_config.py.
NOT_SUPPORTED = ('% Invalid input', '% Unrecognized command', '% Incomplete command')


class BackupError(Exception):
    def __init__(self, message, title='Backup failed'):
        Exception.__init__(self, message)
        self.title = title


def safe_filename(name):
    """A hostname as a Windows filename. IOS hostnames are already letters,
    digits and hyphens, so this only matters for a prompt-derived fallback."""
    cleaned = ''.join(c if c.isalnum() or c in '-_.' else '_' for c in name).strip('._')
    return cleaned or 'switch'


def collect(prompt):
    """(hostname, running_config, vlan_brief or None). Raises BackupError
    rather than returning anything partial."""
    if prompt.endswith('>'):
        raise BackupError('This session is in user EXEC mode ({0}).\n\nRun "enable" first, then '
                          'run this script again.'.format(prompt), 'Not in enable mode')
    if not prompt.endswith('#'):
        raise BackupError('The prompt does not look like a Cisco EXEC prompt: "{0}"\n\nPress '
                          'Enter in the session and try again.'.format(prompt), 'Unexpected prompt')

    wrong_device = capture_l2s.not_a_switch(capture_l2s.run_command('terminal length 0', prompt))
    if wrong_device:
        raise BackupError('This session does not look like a Cisco switch:\n  {0}'
                          .format(wrong_device), 'Not a Cisco switch')

    config = capture_l2s.run_command(CONFIG_COMMAND, prompt)
    for problem in (capture_l2s.not_ios_config(config), capture_l2s.config_cut_short(config)):
        if problem:
            raise BackupError('"{0}" {1}.\n\nNothing was written, and any earlier backup of '
                              'this switch is untouched.'.format(CONFIG_COMMAND, problem),
                              'Config not read')
    if capture_l2s.looks_paginated(config):
        raise BackupError('"{0}" came back paged, so it is incomplete.\n\nNothing was written.'
                          .format(CONFIG_COMMAND), 'Config not read')

    vlans = capture_l2s.run_command(VLAN_COMMAND, prompt)
    if any(marker in vlans for marker in NOT_SUPPORTED):
        vlans = None
    elif not vlans.strip() or capture_l2s.looks_paginated(vlans):
        raise BackupError('"{0}" came back empty or paged.\n\nNothing was written, and any '
                          'earlier backup of this switch is untouched.'.format(VLAN_COMMAND),
                          'VLANs not read')

    hostname = capture_l2s.running_config_hostname(config) or prompt.rstrip('#').strip()
    return hostname, config, vlans


def render(hostname, address, config, vlans, taken):
    lines = ['! Hostname: {0}'.format(hostname)]
    if address:
        lines.append('! IP Address: {0}'.format(address))
    lines.append('! Backup Date/Time: {0}'.format(taken))
    text = '\n'.join(lines) + '\n' + config.rstrip('\n') + '\n'
    if vlans is not None:
        text += '\n! --- {0} ---\n'.format(VLAN_COMMAND) + vlans.rstrip('\n') + '\n'
    return text


def write_replacing(path, text):
    """Write `path` whole or not at all: to a temporary file beside it, then
    swapped in, so a failed write never leaves half a backup where the last
    good one was."""
    temporary = path + '.partial'
    with open(temporary, 'w', encoding='utf-8') as handle:
        handle.write(text)
    os.replace(temporary, path)


def remote_address():
    try:
        return crt.Session.RemoteAddress or ''
    except Exception:
        return ''


def main():
    if not crt.Session.Connected:
        crt.Dialog.MessageBox('Connect and log in to the switch first, then run this script.',
                              'Not connected')
        return

    crt.Screen.Synchronous = True
    try:
        try:
            prompt = capture_l2s.read_prompt()
            hostname, config, vlans = collect(prompt)
        except capture_l2s.CollectionError as refused:
            crt.Dialog.MessageBox(str(refused), refused.title)
            return
        except BackupError as refused:
            crt.Dialog.MessageBox(str(refused), refused.title)
            return

        output_dir = crt.Dialog.Prompt('Save the backup of {0} into:'.format(hostname),
                                       'Switch backup', OUTPUT_DIR)
        if not output_dir:
            return
        # A relative path would resolve against SecureCRT's install folder,
        # where the write fails with Permission denied.
        if not os.path.isabs(output_dir):
            output_dir = os.path.join(OUTPUT_DIR, output_dir)
        path = os.path.join(output_dir, safe_filename(hostname) + '.txt')
        replaced = os.path.exists(path)
        try:
            if not os.path.isdir(output_dir):
                os.makedirs(output_dir)
            write_replacing(path, render(hostname, remote_address(), config, vlans,
                                         time.strftime('%Y-%m-%d %H:%M:%S')))
        except OSError as error:
            crt.Dialog.MessageBox('Could not write {0}:\n{1}\n\nRun the script again and give a '
                                  'folder you can write to.'.format(path, error), 'Backup failed')
            return

        crt.Dialog.MessageBox(
            'Backed up {0}:\n{1}\n\n{2}{3}'.format(
                hostname, path,
                'running-config and VLAN database' if vlans is not None
                else 'running-config (no VLAN database on this device)',
                '\nThe previous backup of this switch was replaced.' if replaced else ''),
            'Backup written')
    except Exception as error:  # SecureCRT hides tracebacks; show it instead
        crt.Dialog.MessageBox('{0}\n\nNothing was written.'.format(error), 'Backup failed')
    finally:
        crt.Screen.Synchronous = False


if crt is not None:
    capture_l2s.crt = crt
    main()
