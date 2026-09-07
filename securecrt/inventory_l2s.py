# $language = "Python3"
# $interface = "1.0"

"""Inventory every saved SecureCRT session: one CSV row per switch, unattended.

Run this from SecureCRT (Script > Run...). For each saved session it connects
using the credentials SecureCRT already holds, sends three short show commands,
reads what the switch is off them, and disconnects. It writes one file:

    inventory_<stamp>.csv

    hostname,ip_address,switch_number,role,model,serial_number,ios_version,
    comment,session,timestamp

A stack is one row per chassis. Each member is its own asset with its own
serial on its own property record, and `show version` names only the active
one - so the walk also asks `show switch` for the members and their roles and
`show license udi` for each member's model and serial, and joins the three on
the member number.

Nothing is configured on any device, no capture or checklist is written, and
the only non-show command sent is `terminal length 0`, which is session-scoped.

WHY THIS IS SEPARATE FROM capture_l2s_bulk.py
That script audits: it collects seven commands per switch, of which
`show running-config` is much the slowest, and produces a STIG Viewer checklist
per device. This one asks three short ones, so a fleet that takes hours to
audit takes minutes to inventory - which is what makes it something you can
re-run whenever you want to know what is out there, rather than a job you plan
an evening around. The two answer different questions and are kept apart so
neither has to compromise for the other.

A switch nobody could reach is a row, not a gap: its model, serial and release
are blank because nothing read them, and its comment says why - "Connection
timed out" where nothing answered, "System refused connection" where the host
answered and said no. Those are different problems with different fixes.

A switch SecureCRT has never connected to before does not stop the walk on its
New Host Key dialog: the connect string carries /ACCEPTHOSTKEYS, which makes
the same trust decision that dialog's default button does. See
capture_l2s_bulk.ACCEPT_HOST_KEYS.

Each run writes its own CSV and visits every session in the list. There is no
resume, and none is wanted: the run is short enough to repeat, and one file per
run is a snapshot of the fleet at a moment rather than an accumulated history
somebody has to de-duplicate.

WHAT IT NEEDS BESIDE IT
capture_l2s.py and capture_l2s_bulk.py. This file reuses their session
discovery, connect handling and `show version` readers rather than carrying a
second copy that could drift - the readers in particular, since an inventory
that disagreed with the audit about which release a switch runs would be worse
than no inventory. All three are standalone: none of them imports anything
from the wider repository.

WHAT IT DOES NOT DO
It never aborts a run. A switch that is offline, in a login quiet period, or
refusing credentials is logged and skipped, because on a fleet of hundreds not
all of them answer on a given night.
"""

import os
import os.path
import time

# `crt` is injected by SecureCRT into this script's globals, not into the
# modules it imports - so those get it handed over explicitly in main().
crt = globals().get('crt')

import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import capture_l2s
import capture_l2s_bulk as bulk


# Where the CSV is written. Created if missing; if it cannot be created the
# script falls back to the user's home directory rather than losing a walk.
OUTPUT_DIR = r'C:\Documents\netauto_inventory'

# Drop a file with this name in the output folder to stop a run cleanly at the
# end of the current switch.
STOP_FILE = 'STOP'

# What this asks for. `terminal length 0` goes first so a stack's output cannot
# come back truncated behind a pager prompt.
#
# `show version` alone would be one round trip rather than three, and would be
# wrong on a stack: it names the active member's serial and no other, while an
# inventory has to account for every chassis. The other two are short, so the
# walk stays a walk - see capture_l2s.stack_members for how they join.
INVENTORY_COMMAND = 'show version'
MEMBER_COMMANDS = capture_l2s.STACK_COMMANDS

# hostname is the switch's own where the walk got far enough to ask, and the
# saved session's name where it did not - a row for a device nobody reached
# still has to be identifiable, and the session name is what the person chasing
# it will recognise. comment is empty on a switch that answered: the data in
# the row is the answer, and a sentence saying "it worked" beside it is noise.
#
# switch_number and role carry the stack. A three-member stack is three rows
# sharing a hostname and an address, one per chassis, because that is what an
# asset record counts - and role is what lets a row be matched to a rack unit
# without opening the cabinet. Both are blank on a standalone switch that
# reports no member numbering, which is not the same as a stack of one.
CSV_COLUMNS = ('hostname', 'ip_address', 'switch_number', 'role', 'model',
               'serial_number', 'ios_version', 'comment', 'session', 'timestamp')


class InventoryCsv:
    """The run's one output, appended to as each switch lands.

    Written row by row rather than at the end, so a run killed at switch 400
    leaves 399 rows behind. One file per run: each is a snapshot of the whole
    list, countable in a spreadsheet as it stands."""

    def __init__(self, directory):
        self.path = bulk.unused_path(
            directory, 'inventory_' + time.strftime('%Y%m%d_%H%M%S'), '.csv')
        self.counts = {}
        with open(self.path, 'w', encoding='utf-8') as handle:
            handle.write(','.join(CSV_COLUMNS) + '\n')

    def record(self, session_path, host, outcome, comment='', hostname='',
               members=()):
        """One switch: one row, or one row per stack member.

        `outcome` is counted for the summary and is not itself a column - what
        a reader needs is in the row already. A switch nothing answered from
        passes no members and gets a single row with its data columns blank."""
        self.counts[outcome] = self.counts.get(outcome, 0) + 1
        rows = members or [{}]
        with open(self.path, 'a', encoding='utf-8') as handle:
            for member in rows:
                row = (hostname or session_path, host,
                       member.get('number', ''), member.get('role', ''),
                       member.get('model', ''), member.get('serial', ''),
                       member.get('release', ''), comment, session_path,
                       time.strftime('%Y-%m-%d %H:%M:%S'))
                handle.write(','.join('"{0}"'.format(str(f).replace('"', "'"))
                                      for f in row) + '\n')

    def summary(self):
        return ', '.join('{0}: {1}'.format(name, self.counts[name])
                         for name in sorted(self.counts))


def read_inventory(prompt=None):
    """Send the inventory commands to the connected session and return
    {command: output}.

    Raises capture_l2s.CollectionError if the session is not a Cisco switch in
    enable mode, or if the output arrives truncated or empty - the same guards
    the capture collector uses, for the same reason: a row built from a shell
    error looks exactly like a row built from a switch."""
    if prompt is None:
        prompt = capture_l2s.read_prompt()
    if not prompt:
        raise capture_l2s.CollectionError(
            'no prompt', 'Could not read the device prompt.', 'No prompt found')
    if prompt.endswith('>'):
        raise capture_l2s.CollectionError(
            'user EXEC mode', 'Session is in user EXEC mode.', 'Not in enable mode')
    if not prompt.endswith('#'):
        raise capture_l2s.CollectionError(
            'unexpected prompt', 'Prompt does not look like a Cisco EXEC prompt.',
            'Unexpected prompt')

    reply = capture_l2s.run_command('terminal length 0', prompt)
    wrong_device = capture_l2s.not_a_switch(reply)
    if wrong_device:
        raise capture_l2s.CollectionError(
            'not a Cisco switch', 'Not a Cisco switch: ' + wrong_device, 'Not a Cisco switch')

    output = capture_l2s.run_command(INVENTORY_COMMAND, prompt)
    if not output.strip():
        raise capture_l2s.CollectionError(
            'empty output: ' + INVENTORY_COMMAND,
            "'{0}' returned nothing.".format(INVENTORY_COMMAND), 'Empty output')
    if capture_l2s.looks_paginated(output):
        raise capture_l2s.CollectionError(
            'paginated: ' + INVENTORY_COMMAND,
            "'{0}' came back truncated.".format(INVENTORY_COMMAND), 'Output truncated')
    # A prompt ending in '#' is not proof of a Cisco switch - root's shell
    # prompt ends in '#' too - and a jump host answering every command with an
    # error passes the checks above. `show version` from a Cisco device says
    # so; anything else is not something to write an inventory row about.
    if 'cisco' not in output.lower():
        raise capture_l2s.CollectionError(
            'not a Cisco switch',
            "'{0}' output does not mention Cisco.".format(INVENTORY_COMMAND),
            'Not a Cisco switch')

    outputs = {INVENTORY_COMMAND: output}
    # Unlike `show version`, these two are allowed to fail: a platform that is
    # not stackable answers `show switch` with an error, and some releases have
    # no `show license udi` at all. Neither is a reason to lose the row - the
    # join falls back to what `show version` said about the one switch.
    for command in MEMBER_COMMANDS:
        outputs[command] = capture_l2s.run_command(command, prompt)
    return outputs


def main():
    folder = crt.Dialog.Prompt(
        'Session folder to walk, e.g. "Switches\\Site A".\n'
        'Leave blank to walk every saved session.',
        'Inventory - scope', '', False)
    if folder is None:
        return

    sessions, duplicates = bulk.dedupe_by_host(bulk.find_sessions(folder.strip()))
    if not sessions:
        crt.Dialog.MessageBox(
            'No saved sessions found under:\n{0}\n\nFolder filter: {1}'
            .format(os.path.join(bulk.config_path(), 'Sessions'), folder or '(none)'),
            'Nothing to do')
        return

    output_dir = crt.Dialog.Prompt('Write the inventory CSV to:',
                                   'Inventory - output folder', OUTPUT_DIR)
    if not output_dir:
        return
    try:
        if not os.path.isdir(output_dir):
            os.makedirs(output_dir)
    except OSError as error:
        crt.Dialog.MessageBox('Could not create {0}:\n{1}'.format(output_dir, error),
                              'Cannot write there')
        return

    if crt.Dialog.MessageBox(
            '{0} device(s) to visit{1}.\n\n'
            'This connects to each one in turn using its saved credentials and '
            'sends three read-only show commands. Nothing is configured and no '
            'capture or checklist is written.\n\n'
            'To stop early, create a file named {2} in the output folder.\n\n'
            'Begin?'.format(len(sessions),
                            ' ({0} duplicate session(s) collapsed)'.format(len(duplicates))
                            if duplicates else '', STOP_FILE),
            'Inventory', 4 | 32) != 6:  # MB_YESNO | MB_ICONQUESTION; 6 = IDYES
        return

    # Carried across every connection: see bulk.connect_session. It also
    # carries the /ACCEPTHOSTKEYS decision, which is what keeps a first
    # connection to an unknown switch from stopping the walk on a modal dialog.
    connect_state = {}

    csv = InventoryCsv(output_dir)
    # Recorded rather than silently dropped, so one run's file accounts for
    # every session in the list - "why is this switch not in the results" has
    # to be answerable from the file itself.
    for session_path, host, kept in duplicates:
        csv.record(session_path, host, 'duplicate', 'Same address as ' + kept)
    stop_path = os.path.join(output_dir, STOP_FILE)
    stopped = False

    def visit_one(index, session_path, host):
        crt.Session.SetStatusText('Inventorying {0}/{1}: {2}'
                                  .format(index, len(sessions), session_path))
        outcome, comment = bulk.connect_session(session_path, connect_state)
        if outcome:
            csv.record(session_path, host, outcome, comment)
            return
        try:
            outputs = read_inventory()
        except capture_l2s.CollectionError as refused:
            csv.record(session_path, host, 'refused', refused.reason)
            return
        version = outputs[INVENTORY_COMMAND]
        csv.record(session_path, host, 'inventoried',
                   hostname=capture_l2s.show_version_hostname(version),
                   members=capture_l2s.stack_members(
                       version,
                       outputs.get('show switch', ''),
                       outputs.get('show license udi', '')))

    crt.Screen.Synchronous = True
    try:
        for index, (session_path, host) in enumerate(sessions, 1):
            if os.path.exists(stop_path):
                stopped = True
                break
            # Nothing that happens to one switch may end the walk - the same
            # rule the bulk collector runs under, and for the same reason.
            try:
                visit_one(index, session_path, host)
            except Exception as error:
                try:
                    csv.record(session_path, host, 'error', bulk.first_line(str(error)))
                except Exception:
                    pass
            bulk.disconnect()
    finally:
        crt.Screen.Synchronous = False
        try:
            crt.Session.SetStatusText('')
        except Exception:
            pass

    crt.Dialog.MessageBox(
        '{0}\n\n{1}\n\nInventory:\n{2}\n\nOne row per session in the list, '
        'including the ones nothing answered from - their comment says why, '
        'and their model, serial and release are blank because nothing read '
        'them.'.format('Run stopped early by the STOP file.' if stopped
                       else 'Run complete.',
                       csv.summary() or 'nothing collected', csv.path),
        'Inventory finished')


# See capture_l2s.py's tail: SecureCRT injects `crt` before running, so this is
# truthy there and None on a plain import, which is what lets the tests drive
# main() with a stand-in and no terminal anywhere.
if crt is not None:
    capture_l2s.crt = crt
    bulk.crt = crt
    main()
