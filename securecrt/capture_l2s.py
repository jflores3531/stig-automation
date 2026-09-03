# $language = "Python3"
# $interface = "1.0"

"""Collect an L2 switch STIG capture from inside SecureCRT.

Run this from an already-connected, already-authenticated SecureCRT session
(Script > Run...). It types five read-only show commands into that session and
writes their output to a capture file, which l2_stig_audit.py then audits
offline:

    python3 l2_stig_audit.py SW01 --from-capture <file>

Nothing is configured and nothing is saved. The only command sent that is not a
show is `terminal length 0`, which disables paging for this session only - it is
session-scoped, so it neither persists nor affects anyone else logged in.

This file is deliberately standalone. It imports nothing from the rest of the
project, because it runs inside SecureCRT's own embedded Python on a machine
that may have nothing else installed - no netmiko, no repository, no venv.
Netmiko in particular is neither needed nor wanted here: it would open its own
SSH connection, which is the thing SecureCRT is being used to avoid. The
capture file is the only interface between this script and the audit.

Because it is standalone, the delimiter format below is duplicated from
capture.py rather than imported. tests/test_securecrt_script.py asserts the two
stay identical, so the duplication cannot drift silently.
"""

# After a successful capture, the script tries to run the audit right here on
# this machine and open the report - one linear flow: connect, Script > Run,
# read the report. That works when this file still lives inside its repo
# (audit script in the parent directory) and a Python that can run it exists.
# When either is missing - e.g. only this one file was copied to a locked-down
# work machine - the capture is still saved and the dialog says where to run
# the audit instead. The audit needs Python only - neither pyyaml nor netmiko
# is required offline: yaml.py in the repo root stands in for pyyaml, and
# netauto imports netmiko lazily, only on connect.
#
# No checklist setting: this runs against IOS XE devices, which is
# l2_stig_audit.py's own default, so the audit is invoked without --checklist
# and there is nothing here to set wrong. A setting existed briefly and was
# removed on purpose - the two STIGs share no rule IDs, so a stale value
# produces a report where nearly every rule reads NOT AUTOMATED, which looks
# like broken tooling rather than a wrong flag. Auditing a classic-IOS device
# (the lab's vios_l2 switches) is still possible, just not from here: run
# `l2_stig_audit.py <name> --checklist ios --from-capture <file>` by hand.

# Pop the finished report in the default .txt viewer. Tests turn this off.
OPEN_REPORT = True

# Where captures and their reports are written. Created if missing; if it
# cannot be created (making a folder at a drive root can need admin rights)
# the script falls back to the user's home directory rather than failing a
# capture that already succeeded. Whatever it lands on is shown in the save
# dialog, so the actual path is never a guess.
CAPTURE_DIR = r'C:\Documents'

# The five commands an L2S audit reads. Four of these exist because the state
# is not in running-config: user VLANs, the STP root port, the VTP password,
# and the SNMPv3 users. Keep in step with capture.AUDIT_COMMANDS_L2S.
COMMANDS = (
    'show running-config',
    'show vlan brief',
    'show spanning-tree',
    'show vtp password',
    'show snmp user',
)

# Commands allowed to come back with nothing. Must match capture.py's
# EMPTY_IS_AN_ANSWER. `show snmp user` prints nothing when no SNMPv3 users are
# defined - a legal switch state, and a non-compliant one that V-220604/605
# exist to catch - so refusing to write the capture would abandon the whole
# collection over the very finding it was sent to collect.
EMPTY_IS_AN_ANSWER = (
    'show snmp user',
)

# Must match capture.py's DELIMITER_PREFIX / DELIMITER_SUFFIX exactly. The
# leading '!' makes each line an IOS comment, so a capture pasted into a
# terminal by accident is inert rather than interpreted.
DELIMITER_PREFIX = '!===== netauto-capture: '
DELIMITER_SUFFIX = ' ====='

# `show running-config` on a large switch is the slow one. Generous, because
# the cost of a short timeout is a truncated capture that still looks valid.
READ_TIMEOUT_SECONDS = 180


def format_delimiter(command):
    """The delimiter line introducing a command's output."""
    return DELIMITER_PREFIX + command + DELIMITER_SUFFIX


def normalise(text):
    """CRLF to LF. SecureCRT hands back the terminal's line endings; the audit
    normalises anyway, but writing LF keeps the file diffable."""
    return text.replace('\r\n', '\n').replace('\r', '\n')


def strip_echo(text, command):
    """Drop the echoed command from the front of a command's output.

    ReadString returns everything typed and received since the send, which
    starts with the switch echoing the command back. Netmiko strips this and so
    must a capture, or the two paths would disagree about where output begins."""
    lines = normalise(text).split('\n')
    while lines and not lines[0].strip():
        lines.pop(0)
    if lines and lines[0].strip() == command.strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()
    return '\n'.join(lines)


def render(outputs):
    """Build the capture file text. Mirrors capture.render()."""
    blocks = []
    for command in COMMANDS:
        blocks.append(format_delimiter(command))
        blocks.append(outputs[command].rstrip('\n'))
        blocks.append('')
    return '\n'.join(blocks)


def looks_paginated(text):
    """True if a pager prompt made it into the output, which means the capture
    is truncated. Checked here as well as in capture.py so the problem is
    reported while the session is still open and it can simply be re-run."""
    lowered = text.lower()
    return '--more--' in lowered.replace(' ', '') or '-- more --' in lowered


# A prompt ending in '#' is not proof of a Cisco switch. root's shell prompt
# ends in '#' too, and so does the prompt on plenty of appliances - so the
# enable-mode check above passes on a Linux box and the five show commands go
# to bash. That mattered little when the only way here was connecting by hand,
# but a walker driving a list of saved sessions will eventually meet a jump
# host, a console server, or an iDRAC, and a junk capture that only fails later
# at audit time is the worst of the available outcomes.
#
# Two cheap confirmations, in order of how early they fire:
#   not_a_switch()  - reads the reply to 'terminal length 0'. A Cisco EXEC
#                     says nothing; a shell says "command not found". One
#                     command has been sent at that point, and it is harmless
#                     anywhere it lands.
#   not_ios_config()- reads 'show running-config' itself, in case a device
#                     accepts unknown commands silently.
SHELL_ERRORS = ('command not found', 'not recognized', 'no such file',
                'permission denied', 'syntax error', 'unknown command')


def not_a_switch(terminal_length_reply):
    """Return the offending line if this session is clearly not a Cisco EXEC,
    or '' when the reply looks the way IOS answers (silence)."""
    for line in terminal_length_reply.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        lowered = stripped.lower()
        if any(error in lowered for error in SHELL_ERRORS):
            return stripped
    return ''


def not_ios_config(running_config):
    """Return a reason if 'show running-config' output is not a Cisco config.

    Deliberately loose: it only has to tell a running-config apart from a
    shell error or an appliance's help text, not validate the config. Any one
    marker is enough, because platforms vary in which they emit."""
    lowered = running_config.lower()
    markers = ('current configuration', '\nhostname ', '\nend', 'building configuration',
               '\ninterface ', '\nversion ')
    if any(marker in lowered for marker in markers):
        return ''
    return ('no Cisco configuration markers found (expected one of: Current '
            'configuration, hostname, interface, version, end)')


def read_prompt():
    """Return the device prompt from the current cursor line.

    This is the most fragile part of the script - everything else depends on
    knowing what to read up to. If a capture comes back empty, check this
    first: an unusual prompt, a banner still on screen, or a session sitting at
    a --More-- is what breaks it."""
    row = crt.Screen.CurrentRow
    column = crt.Screen.CurrentColumn - 1
    if column < 1:
        return ''
    return crt.Screen.Get(row, 1, row, column).strip()


def run_command(command, prompt):
    """Send one command and return its output, without echo or trailing prompt."""
    crt.Screen.Send(command + '\r')
    output = crt.Screen.ReadString(prompt, READ_TIMEOUT_SECONDS)
    if output is None:
        raise RuntimeError(
            "Timed out after {0}s waiting for the prompt after '{1}'.\n\n"
            'Nothing was written. The session may still be paging, or the '
            'prompt may have changed mid-command.'.format(READ_TIMEOUT_SECONDS, command))
    return strip_echo(output, command)


class CollectionError(Exception):
    """A reason this session could not be captured.

    Carries two forms of the same problem: `.reason` is a short phrase for a
    bulk run's log (one line per switch, six hundred of them), and str() is the
    full explanation a single-switch run puts in a dialog. Splitting them is
    what lets capture_l2s_bulk.py reuse every guard below without any of the
    dialogs - a modal box inside an unattended overnight loop would stop the
    run dead until someone clicked it."""

    def __init__(self, reason, message, title='Capture failed'):
        Exception.__init__(self, message)
        self.reason = reason
        self.title = title


def collect(prompt=None):
    """Send the five show commands to the current session and return
    (hostname, outputs). Raises CollectionError if the session is not a Cisco
    switch in enable mode, or if any output arrives truncated or empty.

    Assumes the session is connected and crt.Screen.Synchronous is set; both
    callers handle that, since the bulk walker sets Synchronous once for a
    whole run rather than per switch."""
    if prompt is None:
        prompt = read_prompt()
    if not prompt:
        raise CollectionError(
            'no prompt',
            'Could not read the device prompt from the current line.\n\n'
            'Press Enter in the session so the prompt is the last thing on '
            'screen, then run this script again.', 'No prompt found')
    if prompt.endswith('>'):
        raise CollectionError(
            'user EXEC mode',
            'This session is in user EXEC mode ({0}).\n\n'
            'show running-config needs privileged EXEC. Run "enable" first, '
            'then run this script again.'.format(prompt), 'Not in enable mode')
    if not prompt.endswith('#'):
        raise CollectionError(
            'unexpected prompt',
            'The prompt does not look like a Cisco EXEC prompt: "{0}"\n\n'
            'Press Enter in the session and try again.'.format(prompt),
            'Unexpected prompt')

    hostname = prompt.rstrip('#').strip() or 'switch'

    # Paging off, or running-config comes back full of --More-- prompts and
    # backspace padding. Session-scoped, so nothing is left behind.
    #
    # Its response is also the first evidence of what this session is
    # actually attached to. A Cisco EXEC returns nothing; a shell returns
    # "terminal: command not found" or similar. See not_a_switch().
    reply = run_command('terminal length 0', prompt)
    wrong_device = not_a_switch(reply)
    if wrong_device:
        raise CollectionError(
            'not a Cisco switch',
            'This session does not look like a Cisco switch.\n\n'
            '"terminal length 0" came back with:\n  {0}\n\n'
            'Nothing was sent beyond that one command and no capture was '
            'written. Connect to the switch, run "enable", and try '
            'again.'.format(wrong_device), 'Not a Cisco switch')

    outputs = {}
    for command in COMMANDS:
        outputs[command] = run_command(command, prompt)
        if not outputs[command].strip() and command not in EMPTY_IS_AN_ANSWER:
            raise CollectionError(
                'empty output: ' + command,
                "'{0}' returned nothing.\n\nNothing was written - a command that "
                'returns nothing is indistinguishable from a feature that is '
                'switched off, and the audit refuses captures like that rather '
                'than reporting against them.'.format(command), 'Empty output')
        if looks_paginated(outputs[command]):
            raise CollectionError(
                'paginated: ' + command,
                "'{0}' came back with a pager prompt, so its output is "
                'truncated.\n\nNothing was written. Run "terminal length 0" by '
                'hand and try again.'.format(command), 'Output truncated')
        if command == 'show running-config':
            wrong_output = not_ios_config(outputs[command])
            if wrong_output:
                raise CollectionError(
                    'not a Cisco config',
                    '"show running-config" did not return a Cisco '
                    'configuration - {0}.\n\nNo capture was written. Check '
                    'that this session is on the switch you meant.'
                    .format(wrong_output), 'Not a Cisco switch')
    return hostname, outputs


def main():
    if not crt.Session.Connected:
        crt.Dialog.MessageBox('Connect and log in to the switch first, then run this script.',
                              'Not connected')
        return

    crt.Screen.Synchronous = True
    try:
        try:
            hostname, outputs = collect()
        except CollectionError as refused:
            crt.Dialog.MessageBox(str(refused), refused.title)
            return

        # Always an absolute path. A bare filename resolves against SecureCRT's
        # working directory - its own install folder under Program Files - and
        # the write dies with Permission denied after a perfectly good capture
        # (found on the first real-terminal run, 2026-08-28, all five commands
        # captured and then thrown away).
        import os
        import os.path
        capture_dir = CAPTURE_DIR
        try:
            if not os.path.isdir(capture_dir):
                os.makedirs(capture_dir)
        except OSError:
            capture_dir = os.path.expanduser('~')
        default_path = os.path.join(
            capture_dir, '{0}_{1}.capture'.format(hostname, _timestamp()))
        path = crt.Dialog.Prompt('Write the capture to:', 'Save capture', default_path)
        if not path:
            return
        if not os.path.isabs(path):
            path = os.path.join(capture_dir, path)

        try:
            with open(path, 'w', encoding='utf-8') as capture_file:
                capture_file.write(render(outputs))
        except OSError as error:
            crt.Dialog.MessageBox(
                'Could not write {0}:\n{1}\n\nThe capture is intact in memory but '
                'was not saved. Run the script again and give a full path to a '
                'folder you can write to.'.format(path, error), 'Capture failed')
            return

        import os

        report_path, detail = run_audit(path, hostname)
        if report_path:
            crt.Dialog.MessageBox(
                'Captured {0} commands from {1} and audited the capture.\n\n'
                '{2}\n\nCapture: {3}\nReport:  {4}'
                .format(len(COMMANDS), hostname, detail, path, report_path),
                'Capture and audit complete')
            if OPEN_REPORT and hasattr(os, 'startfile'):
                os.startfile(report_path)
        else:
            crt.Dialog.MessageBox(
                'Captured {0} commands from {1}.\n\nWritten to:\n{2}\n\n'
                'The audit did not run here - {3}'
                .format(len(COMMANDS), hostname, path, detail), 'Capture complete')
    except Exception as error:  # surfaced in a dialog; SecureCRT hides tracebacks
        crt.Dialog.MessageBox('{0}\n\nNo capture was written.'.format(error), 'Capture failed')
    finally:
        crt.Screen.Synchronous = False


def _timestamp():
    import time
    return time.strftime('%Y%m%d_%H%M%S')


def run_audit(capture_path, hostname):
    """Run l2_stig_audit.py --from-capture against the just-saved capture,
    writing the report next to it. Returns (report_path, summary_line) on
    success, (None, why_not) when the audit cannot run here - which is not a
    capture failure, just a machine without the repo."""
    import os.path
    import subprocess

    script_dir = os.path.dirname(os.path.abspath(__file__))
    repo = os.path.dirname(script_dir)
    audit = os.path.join(repo, 'l2_stig_audit.py')
    if not os.path.exists(audit):
        return None, ('l2_stig_audit.py not found next to this script - run the audit '
                      'on a machine with the repo:\n'
                      'python l2_stig_audit.py {0} --from-capture <capture>'.format(hostname))

    # Prefer the repo's own venv; fall back to whatever python is on PATH.
    candidates = [os.path.join(repo, '.venv', 'Scripts', 'python.exe'),
                  os.path.join(repo, '.venv', 'bin', 'python'),
                  'python', 'python3']
    last_error = ''
    for python in candidates:
        try:
            # No --checklist: the audit defaults to IOS XE, which is what this
            # script captures from. See the note at the top of the file.
            result = subprocess.run(
                [python, audit, hostname, '--from-capture', capture_path],
                capture_output=True, text=True, cwd=repo, timeout=180)
        except (OSError, subprocess.TimeoutExpired) as error:
            last_error = '{0}: {1}'.format(python, error)
            continue
        if result.returncode != 0:
            return None, ('the audit itself failed:\n'
                          + (result.stdout + result.stderr).strip()[-500:])
        # Strip the .capture extension before appending, so the report is a
        # clean .txt (S1_<stamp>_report.txt) rather than a double-extensioned
        # .capture_report.txt that Windows file associations mishandle.
        base = capture_path[:-len('.capture')] if capture_path.endswith('.capture') else capture_path
        report_path = base + '_report.txt'
        with open(report_path, 'w', encoding='utf-8') as report_file:
            report_file.write(result.stdout)
        summary = next((line for line in result.stdout.splitlines() if 'out of' in line),
                       'report written')
        return report_path, summary
    return None, 'no runnable python found (tried the repo venv and PATH): ' + last_error


# `crt` is supplied by SecureCRT at runtime, not imported. Declared here only so
# linters and IDEs stop flagging the references above as undefined; SecureCRT's
# own injection takes precedence when the script actually runs.
crt = globals().get('crt')

# SecureCRT injects `crt` into this script's globals before running it, so this
# is truthy there and None on a plain import - which is what lets the test suite
# import the module, substitute a stand-in for `crt`, and drive main() without a
# terminal anywhere in sight.
if crt is not None:
    main()
