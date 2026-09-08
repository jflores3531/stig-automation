# $language = "Python3"
# $interface = "1.0"

"""Collect an L2 switch STIG capture from inside SecureCRT and leave a filled-in
STIG Viewer 3 checklist behind.

Run this from an already-connected, already-authenticated SecureCRT session
(Script > Run...). It types the read-only show commands an audit needs into that
session, audits their output, and writes ONE file:

    <hostname>_<DDMMMYYYY>_L2S_V3R2_NDM_V3R6.cklb

Open it with STIG Viewer 3 (File > Open Checklist). The capture the audit read
is a working file and is deleted once the checklist exists; no report .txt is
written, because the checklist carries every verdict and its reason. The one
exception is an audit that could not run on this machine - see run_audit() -
where the capture is kept rather than thrown away, since it is then the only
record of a trip to the switch.

Nothing is configured and nothing else is saved. The only command sent that is
not a show is `terminal length 0`, which disables paging for this session only -
it is session-scoped, so it neither persists nor affects anyone else logged in.

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

# After a successful capture, the script runs the audit right here on this
# machine and leaves the checklist - one linear flow: connect, Script > Run,
# open the .cklb. That works when this file still lives inside its repo
# (audit script in the parent directory) and a Python that can run it exists.
# When either is missing - e.g. only this one file was copied to a locked-down
# work machine - the capture is kept and the dialog says where to run the audit
# instead. The audit needs Python only - neither pyyaml nor netmiko is required
# offline: yaml.py in the repo's scripts/ stands in for pyyaml, and netauto
# imports netmiko lazily, only on connect.
#
# No checklist setting: this runs against IOS XE devices, which is
# l2_stig_audit.py's own default, so the audit is invoked without --checklist
# and there is nothing here to set wrong. A setting existed briefly and was
# removed on purpose - the two STIGs share no rule IDs, so a stale value
# produces a report where nearly every rule reads NOT AUTOMATED, which looks
# like broken tooling rather than a wrong flag. Auditing a classic-IOS device
# (the lab's vios_l2 switches) is still possible, just not from here: run
# `scripts/l2_stig_audit.py <name> --checklist ios --from-capture <file>` by hand.

# Open the folder the checklist landed in when the run finishes, so the file is
# in front of whoever ran it rather than at a path they have to go find. The
# folder rather than the file itself: .cklb is only associated with an
# application on a machine where STIG Viewer 3 is installed, and startfile() on
# an unassociated extension raises rather than doing nothing. Tests turn it off.
OPEN_OUTPUT_FOLDER = True

# Where the finished checklist is written. Created if missing; if it cannot be
# created (making a folder at a drive root can need admin rights) the script
# falls back to the user's home directory rather than failing a capture that
# already succeeded. Whatever it lands on is shown in the save dialog, so the
# actual path is never a guess.
OUTPUT_DIR = r'C:\Documents'

# The seven commands every L2S audit reads. Five of them exist because the state
# is not in running-config: user VLANs, the STP root port, the VTP password,
# the SNMPv3 users, and the model and release the switch is running. The last,
# `show ip interface brief`, answers no rule - it carries the management
# address for the checklist's asset block. Keep in step with
# capture.AUDIT_COMMANDS_L2S + capture.OPTIONAL_COMMANDS_L2S.
COMMANDS = (
    'show running-config',
    'show vlan brief',
    'show spanning-tree',
    'show vtp password',
    'show snmp user',
    'show version',
    'show ip interface brief',
)

# And then one more per interface template the config turns out to use. An
# IOS XE port configured by `source template <name>` shows that single line in
# running-config and none of the commands it stands for, so a capture with only
# the six above hands the audit interfaces that look unconfigured - a false
# FAIL on every per-port rule at once. The names cannot be known before the
# config is read, which is why this is a second pass rather than a longer
# COMMANDS tuple. Must match capture.TEMPLATE_COMMAND_PREFIX.
TEMPLATE_COMMAND_PREFIX = 'show template interface source user '


def template_command(name):
    return TEMPLATE_COMMAND_PREFIX + name


def sourced_template_names(running_config):
    """Distinct interface-template names a running-config sources, in the order
    they first appear. Mirrors capture.sourced_template_names."""
    names = []
    for line in running_config.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[0] == 'source' and parts[1] == 'template':
            if parts[2] not in names:
                names.append(parts[2])
    return names


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
    """Build the capture file text. Mirrors capture.render().

    COMMANDS first, in their fixed order, then whatever else was collected -
    the per-device template commands - in the order they were read. A command
    in `outputs` and not written here would be one the audit then refuses the
    capture for missing."""
    blocks = []
    ordered = list(COMMANDS) + [c for c in outputs if c not in COMMANDS]
    for command in ordered:
        blocks.append(format_delimiter(command))
        blocks.append(outputs[command].rstrip('\n'))
        blocks.append('')
    return '\n'.join(blocks)


# Model and release out of `show version`, for the bulk walker's run log. It
# writes a row per switch naming the hardware and the software found on it, and
# it cannot import l2_stig_audit's readers - nothing in securecrt/ may import
# from the repository, since these two files get copied to a machine that has
# none of it. tests/test_securecrt_script.py asserts these agree with the
# audit's own readers on the same output, so the duplication cannot drift into
# a log that disagrees with the checklist beside it.
#
# That includes the switch table `show version` ends with on a stackable
# Catalyst, which on some images is the only place the model and release
# appear. Skipping it here would leave the log's columns blank for a switch
# whose checklist names both - the two disagreeing about the same device, which
# is the thing this duplication most has to avoid.
def _switch_table(output):
    """(number, model, release) for the member the table marks active, or
    (0, '', ''). Mirrors stig_common.active_member."""
    import re
    header = re.search(r'^\s*Switch\s+Ports\s+Model\s+SW\s+Version', output or '',
                       re.M | re.I)
    if not header:
        return 0, '', ''
    rest = (output or '').find('\n', header.end())
    if rest == -1:
        return 0, '', ''
    rows = []
    for line in output[rest + 1:].splitlines():
        if not line.strip() or set(line.strip()) <= set('- '):
            continue
        match = re.match(r'^\s*(\*?)\s*(\d+)\s+\d+\s+(\S+)\s+(\d\S*)', line)
        if not match:
            break
        rows.append((bool(match.group(1)), int(match.group(2)),
                     match.group(3), match.group(4)))
    if not rows:
        return 0, '', ''
    active = next((row for row in rows if row[0]), rows[0])
    return active[1], active[2], active[3]


def _active_member_field(output, pattern):
    """A per-member field - model, serial, base MAC - preferring the active
    member's copy. Each is printed once per member under a `Switch NN` heading,
    in member order, so the first match is switch 1's and only right when
    switch 1 is the member in charge. Mirrors stig_common._active_member_field."""
    import re
    number = _switch_table(output)[0]
    if number:
        heading = re.search(r'^Switch\s+0*{0}\s*$'.format(number), output or '', re.M)
        if heading:
            following = re.search(r'^Switch\s+\d+\s*$', output[heading.end():], re.M)
            section = (output[heading.end():heading.end() + following.start()]
                       if following else output[heading.end():])
            match = re.search(pattern, section)
            if match:
                return match.group(1)
    match = re.search(pattern, output or '')
    return match.group(1) if match else ''


def running_config_hostname(output):
    """The switch's own `hostname` line, or ''.

    The prompt gives a name too, and collect() uses it - but a prompt can carry
    a suffix, a location, or whatever someone set it to, while this is the name
    the audit puts in the checklist and in the checklist's filename. The log
    and the checklist beside it have to agree about which switch a row is."""
    import re
    match = re.search(r'^hostname (\S+)', output or '', re.M)
    return match.group(1) if match else ''


# Table first, then the banner - same order and for the same reason as the
# audit's readers. `Model Number :` is printed once per stack member, so its
# first match is switch 1's model while the banner gives the active member's
# release: on a mixed stack that names one switch's hardware beside another
# switch's software. The table marks the active member and carries both on one
# row.
def show_version_model(output):
    """The switch model, or '' - the table's Model column for the active stack
    member, else `Model Number : C9300-48P`, else the `cisco <model> (<cpu>)
    processor` line that everything without a table prints."""
    import re
    model = _switch_table(output)[1]
    if model:
        return model
    for pattern in (r'^Model [Nn]umber\s*:\s*(\S+)',
                    r'^\s*[Cc]isco (\S+) \(.*\) processor'):
        match = re.search(pattern, output or '', re.M)
        if match:
            return match.group(1)
    return ''


def show_version_hostname(output):
    """The switch's own name from `show version`'s `<name> uptime is ...` line,
    or ''.

    The inventory walk asks for `show version` and nothing else, so this is
    where the name comes from there. It agrees with the config's `hostname` on
    every switch that has one - IOS builds the line from it - and unlike the
    prompt it cannot carry a suffix somebody added to the terminal."""
    import re
    match = re.search(r'^(\S+) uptime is ', output or '', re.M)
    return match.group(1) if match else ''


def show_version_serial(output):
    """The switch's serial, or '' - `System Serial Number` on Catalyst, the
    `Processor board ID` line elsewhere. The active member's on a stack."""
    import re
    serial = _active_member_field(output, r'System Serial Number\s*:\s*(\S+)')
    if serial:
        return serial
    match = re.search(r'^Processor board ID\s+(\S+)', output or '', re.M)
    return match.group(1) if match else ''


def show_version_release(output):
    """The IOS/IOS XE release, or ''. Normalised the way the audit normalises
    it, so 17.12.04 and 17.12.4 do not read as two different switches."""
    import re
    release = _switch_table(output)[2]
    if not release:
        for pattern in (r'Cisco IOS XE Software, Version (\S+)',
                        r'Cisco IOS Software.*?,\s*(?:Experimental )?Version ([^\s,]+)',
                        r'^Version (\S+)'):
            match = re.search(pattern, output or '', re.M)
            if match:
                release = match.group(1).strip().rstrip(',')
                break
    return re.sub(r'(^|\.)0+(\d)', r'\1\2', release) if release else ''


# --- Stack members ------------------------------------------------------------
#
# `show version` describes one switch: the active member's model and serial, and
# a table of every member's model and release. That is the right answer for an
# audit, which is about the software running the stack - but it is the wrong
# answer for an inventory, where each chassis is its own asset with its own
# serial on its own property record. A three-member stack is three things to
# account for and `show version` names one of them.
#
# So two more commands, and a join:
#
#   `show switch`       - which members exist, and which is Active, Standby or
#                         Member. The roles are the reason this is asked rather
#                         than inferred: an inventory that cannot say which
#                         chassis is which cannot be reconciled with a rack.
#   `show license udi`  - each member's PID and SN. `show version` prints the
#                         serial only for the active member, which is the whole
#                         of why this is here.
#   `show version`      - each member's release, off the switch table.
#
# Keyed by member number, which all three agree on. Anything the join cannot
# find is left blank rather than filled from another member: a serial beside
# the wrong chassis number is worse in an asset record than an empty cell.
STACK_COMMANDS = ('show switch', 'show license udi')


def _normalise_release(release):
    """17.12.04 and 17.12.4 are one release printed two ways. Matches what the
    audit does, so an inventory row and a checklist name the same release."""
    import re
    return re.sub(r'(^|\.)0+(\d)', r'\1\2', release.strip()) if release else ''


def parse_show_switch(output):
    """{number: role} from `show switch`.

    Empty for a platform that has no such command, which answers with an error
    - and for anything else this does not recognise, which then falls back to
    the single-switch reading rather than inventing members."""
    import re
    members = {}
    for line in (output or '').splitlines():
        # Number, role, then a Cisco-form MAC: specific enough not to match the
        # header, the separator rule, or the `Switch/Stack Mac Address` line.
        match = re.match(r'^\s*\*?\s*(\d+)\s+(\S+)\s+'
                         r'[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}', line)
        if match:
            members[int(match.group(1))] = match.group(2)
    return members


def parse_license_udi(output):
    """{number: (model, serial)} from `show license udi`.

    Two shapes are in the wild and both are read: the `PID:...,VID:...,SN:...`
    form, which carries a `Switch N` on its line in a stack's HA UDI LIST, and
    the plain columnar table some releases print instead. A standalone switch
    prints one PID/SN line with no member number at all, which is recorded as
    member 0 - the caller treats that as "the only switch there is"."""
    import re
    members = {}
    for line in (output or '').splitlines():
        pid_sn = re.search(r'PID:\s*(\S+?)\s*,\s*VID:[^,]*,\s*SN:\s*(\S+)', line)
        if pid_sn:
            number = re.search(r'Switch\s+(\d+)', line)
            members[int(number.group(1)) if number else 0] = (pid_sn.group(1),
                                                              pid_sn.group(2))
            continue
        # `1    C9300-48P    V01    FOC1111X1XX`, optionally `Switch 1  ...`.
        row = re.match(r'^\s*(?:Switch\s+)?(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s*$', line)
        if row and not row.group(2).isdigit():
            members[int(row.group(1))] = (row.group(2), row.group(4))
    return members


def switch_table_rows(output):
    """({number: (model, release)}, whole_table) for `show version`'s switch
    table, every row of it and not only the active one.

    `whole_table` is False when the walk stopped on a line that begins like a
    member row and could not be read. Reading stops at the first line that is
    not a row either way - that is how the end of the table is found - but the
    two are not the same fact, and one caller badly needs to tell them apart:
    a three-member stack whose second row this cannot parse yields exactly one
    member, which is indistinguishable from a standalone switch unless the
    partial read is reported as partial. See is_standalone."""
    import re
    header = re.search(r'^\s*Switch\s+Ports\s+Model\s+SW\s+Version', output or '',
                       re.M | re.I)
    if not header:
        return {}, False
    rest = (output or '').find('\n', header.end())
    if rest == -1:
        return {}, False
    members = {}
    whole_table = True
    for line in output[rest + 1:].splitlines():
        if not line.strip() or set(line.strip()) <= set('- '):
            continue
        match = re.match(r'^\s*(\*?)\s*(\d+)\s+\d+\s+(\S+)\s+(\d\S*)', line)
        if not match:
            # A line that opens with a member number is a row this could not
            # read; anything else is the table having ended, which is normal.
            whole_table = re.match(r'^\s*\*?\s*\d+\s', line) is None
            break
        members[int(match.group(2))] = (match.group(3), match.group(4))
    return members, whole_table


def switch_table_members(output):
    """{number: (model, release)} for every row of `show version`'s switch
    table, not only the active one."""
    return switch_table_rows(output)[0]


def is_standalone(version_output):
    """Whether this switch is positively, provably one chassis.

    What it is for: `show switch` and `show license udi` exist to account for
    the members `show version` does not describe, and a switch that is its own
    whole stack has none. Asking anyway is two round trips per switch spent
    confirming what the first command already said, which on a fleet of
    hundreds is the difference between an inventory somebody re-runs whenever
    they want to know what is out there and one they plan an evening around.

    Every uncertainty answers False, and the asymmetry is deliberate. Being
    wrong the other way costs two commands; being wrong this way reports a
    three-member stack as a standalone switch, with two chassis missing from
    an asset record and nothing in the row admitting it - a walk that finishes
    looking healthy while quietly leaving hardware out. So this wants proof of
    one, not absence of proof of more:

      * a table read only in part is not proof of anything. A stack whose
        second row cannot be parsed leaves exactly one member behind, which is
        why switch_table_rows reports the partial read as partial.
      * no table at all is not "one switch". It is also the case where
        `show version` is least able to answer for the hardware - see
        show_version_model - and where `show license udi` is the fallback that
        names the model and serial.
      * a second opinion that costs nothing: `show version` prints a section
        per member on a stack, so more than one of those is a stack whatever
        the table said."""
    members, whole_table = switch_table_rows(version_output)
    if not whole_table or len(members) != 1:
        return False
    return len(version_member_serials(version_output)) <= 1


def version_member_serials(output):
    """{number: serial} from `show version`'s own per-member `Switch NN`
    sections. The fallback when `show license udi` is unavailable - it names
    only some members on some releases, and none at all where the command is
    not supported."""
    import re
    serials = {}
    for match in re.finditer(r'^Switch\s+0*(\d+)\s*$', output or '', re.M):
        following = re.search(r'^Switch\s+\d+\s*$', output[match.end():], re.M)
        section = (output[match.end():match.end() + following.start()]
                   if following else output[match.end():])
        serial = re.search(r'System Serial Number\s*:\s*(\S+)', section)
        if serial:
            serials[int(match.group(1))] = serial.group(1)
    return serials


def stack_members(version_output, switch_output='', udi_output=''):
    """[{number, role, model, serial, release}, ...] - one entry per chassis,
    in member order.

    A standalone switch, and a stack whose extra commands came back as errors,
    both produce exactly one entry built from `show version` alone: the same
    row the inventory wrote before any of this existed."""
    import re
    roles = parse_show_switch(switch_output)
    udi = parse_license_udi(udi_output)
    table = switch_table_members(version_output)
    section_serials = version_member_serials(version_output)

    numbers = sorted(set(roles) | set(n for n in udi if n) | set(table))
    if not numbers:
        # No member numbering anywhere: one switch, described by the readers
        # that already answer for a standalone.
        standalone_udi = udi.get(0, ('', ''))
        return [{
            'number': '',
            'role': '',
            'model': show_version_model(version_output) or standalone_udi[0],
            'serial': show_version_serial(version_output) or standalone_udi[1],
            'release': show_version_release(version_output),
        }]

    # Which member `show version`'s own top-level readers describe, so their
    # answers are attached to that member and to no other.
    active = next((number for number, role in roles.items()
                   if role.lower() == 'active'), None)
    if active is None:
        # No `show switch` to ask, so the switch table's own `*` marker - the
        # same one every other reader here uses to mean "the member in charge".
        active = _switch_table(version_output)[0] or None
    if active is None and len(numbers) == 1:
        active = numbers[0]

    members = []
    for number in numbers:
        model, serial = udi.get(number, ('', ''))
        table_model, release = table.get(number, ('', ''))
        if not serial:
            # `show license udi` is the only command that names every member's
            # serial, so where it is missing this falls back to what the switch
            # says about itself - its own section, then, for the active member
            # only, the top-level reading.
            serial = section_serials.get(number, '')
        if not serial and number == active:
            serial = show_version_serial(version_output)
        members.append({
            'number': number,
            'role': roles.get(number, ''),
            # The UDI's PID is the authority on what a chassis is; the switch
            # table's Model column says the same thing and is the fallback for
            # a release that prints no HA UDI list.
            'model': model or table_model or (
                show_version_model(version_output) if number == active else ''),
            'serial': serial,
            'release': _normalise_release(release) or (
                show_version_release(version_output) if number == active else ''),
        })
    return members


def looks_paginated(text):
    """True if a pager prompt made it into the output, which means the capture
    is truncated. Checked here as well as in capture.py so the problem is
    reported while the session is still open and it can simply be re-run."""
    lowered = text.lower()
    return '--more--' in lowered.replace(' ', '') or '-- more --' in lowered


# A prompt ending in '#' is not proof of a Cisco switch. root's shell prompt
# ends in '#' too, and so does the prompt on plenty of appliances - so the
# enable-mode check above passes on a Linux box and the show commands go
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


# How long to wait for a prompt on a freshly connected session before giving
# up on it. A switch hardened to the STIG this tool audits answers a new SSH
# session with the DoD notice and consent banner - V-220521's requirement, so
# every switch worth auditing has one - and it is still arriving when Connect()
# returns. Measured at 20 seconds on real hardware; 45 leaves better than twice
# that, and costs nothing on a switch that prompts straight away, because the
# wait ends the moment a prompt appears. Raise it if a slow link needs longer.
PROMPT_TIMEOUT_SECONDS = 45
PROMPT_POLL_MS = 500

# Polls between carriage returns while waiting. The screen is read first and
# nudged only if nothing has arrived, so a session already sitting at its
# prompt - which is how capture_l2s.py has always found one - is read exactly
# as it used to be, without anything being sent to it at all.
PROMPT_NUDGE_EVERY = 10


def _sleep(milliseconds):
    """crt.Sleep, where the host provides it. A stand-in SecureCRT in the
    tests does not, and does not need to - nothing there is still arriving."""
    try:
        crt.Sleep(milliseconds)
    except AttributeError:
        pass


def _still_connected():
    """Whether the session is still up, as far as SecureCRT will say.

    Assumed up where nothing answers the question - a stand-in without a
    Session, say. Guessing "dropped" there would turn a healthy run into a
    fleet of dropped sessions, which is the worse of the two mistakes."""
    try:
        return bool(crt.Session.Connected)
    except AttributeError:
        return True


def _tail(text, length=30):
    """The end of a line, for a log column. The end rather than the start
    because that is where a prompt would be if there were one."""
    text = (text or '').strip()
    return text if len(text) <= length else '...' + text[-length:]


def _looks_like_a_prompt(line):
    """Whether the cursor's line is a Cisco EXEC prompt rather than banner.

    Ending in '#' is not enough on its own, and assuming it was is how a wait
    for the prompt would end by reading the banner instead: the DoD notice
    every switch here carries is commonly ruled off in exactly that character,
    so its own lines end in one. What a banner line has and a prompt never
    does is a space - `SW01#` and `SW01(config-if)#` are single words, because
    a Cisco hostname cannot contain whitespace."""
    if not line or (not line.endswith('#') and not line.endswith('>')):
        return False
    return not any(character.isspace() for character in line)


def read_prompt(timeout_seconds=PROMPT_TIMEOUT_SECONDS):
    """Return the device prompt, waiting for the session to settle first.

    This is the most fragile part of the script - everything else depends on
    knowing what to read up to. Reading the cursor line the instant this is
    called is what a person driving the script by hand gets away with: by the
    time they run it, the login banner finished scrolling minutes ago. An
    unattended walk has no such luck. It calls this the moment Connect()
    returns, with the banner still coming down the wire, and reads a line of
    banner instead of a prompt - which the guards above then refuse as "no
    prompt", on a switch that was answering perfectly well.

    So the prompt is waited for rather than assumed. The screen is read first,
    so a session already sitting at its prompt - which is how capture_l2s.py
    has always found one - is read exactly as it used to be, immediately and
    without anything being sent to it. Only if nothing prompt-like is there
    does this start nudging with a bare carriage return, which at an EXEC
    prompt does nothing except make the switch draw a fresh prompt on a clean
    line. Nothing is configured by it.

    Raises CollectionError if no prompt appears within PROMPT_TIMEOUT_SECONDS,
    or if the session drops while waiting - two different problems, and the
    reason says which, along with how long it waited and what it was looking
    at when it gave up. "no prompt" on its own sends whoever reads the log
    back to the switch to find out what that meant.

    The banner has to be allowed to drain while this waits, which is why
    Synchronous is turned off for the duration. In synchronous mode SecureCRT
    holds the incoming stream until the script reads it, and Screen.Get() -
    what this polls - reads the painted screen rather than consuming that
    stream. So a walk that set Synchronous once for the whole run and then sat
    here watching would let twenty seconds of banner back up behind a buffer
    nothing was emptying, until the switch gave up on the channel: a protocol
    error a few seconds in, on a switch that had answered fine. Nothing worth
    keeping arrives before the prompt does, so there is nothing to lose by
    letting it through, and the caller's setting is put back before any
    command is sent."""
    was_synchronous = getattr(crt.Screen, 'Synchronous', False)
    crt.Screen.Synchronous = False
    last_seen = ''
    waited_ms = 0
    try:
        polls = max(1, int(timeout_seconds * 1000 / PROMPT_POLL_MS))
        for poll in range(polls):
            # A session that has gone is not a session with an unreadable
            # prompt, and the two want opposite things done about them: one is
            # the switch or the link, the other is this function. Waiting out
            # the full timeout on a dropped session would also cost 45 seconds
            # a switch on a night when something is dropping all of them.
            if not _still_connected():
                raise CollectionError(
                    'session dropped after {0}s waiting for the prompt'
                    .format(waited_ms // 1000),
                    'The session closed while waiting for the switch to finish '
                    'its banner and show a prompt.\n\nThe switch answered and '
                    'then went away, which is not something this script can '
                    'read its way past.', 'Session dropped')
            row = crt.Screen.CurrentRow
            column = crt.Screen.CurrentColumn - 1
            if column >= 1:
                line = crt.Screen.Get(row, 1, row, column).strip()
                if _looks_like_a_prompt(line):
                    return line
                if line:
                    last_seen = line
            # Nudged only after it has had a chance to arrive on its own, and
            # then rarely: a banner is not waiting on us, it is simply long.
            if poll and poll % PROMPT_NUDGE_EVERY == 0:
                crt.Screen.Send('\r')
            _sleep(PROMPT_POLL_MS)
            waited_ms += PROMPT_POLL_MS
        # What it was looking at is the thing that explains this, and a log
        # saying only "no prompt" sends whoever reads it back to the switch to
        # find out. The tail rather than the whole line: it is a log column,
        # and a prompt would be at the end of it.
        raise CollectionError(
            'no prompt after {0}s; last saw "{1}"'.format(
                waited_ms // 1000, _tail(last_seen)) if last_seen
            else 'no prompt after {0}s; screen stayed blank'.format(waited_ms // 1000),
            'Could not read the device prompt from the current line.\n\n'
            'Press Enter in the session so the prompt is the last thing on '
            'screen, then run this script again.', 'No prompt found')
    finally:
        crt.Screen.Synchronous = was_synchronous


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
    """Send the six show commands to the current session and return
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

    def collect(command):
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

    for command in COMMANDS:
        collect(command)
    # The second pass: one command per interface template the config just read
    # turns out to source. A switch that uses none adds nothing here, and the
    # capture is exactly what it always was.
    for name in sourced_template_names(outputs['show running-config']):
        collect(template_command(name))
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
        output_dir = OUTPUT_DIR
        try:
            if not os.path.isdir(output_dir):
                os.makedirs(output_dir)
        except OSError:
            output_dir = os.path.expanduser('~')
        default_dir = output_dir
        output_dir = crt.Dialog.Prompt(
            'Write the STIG Viewer checklist into:', 'Save checklist', default_dir)
        if not output_dir:
            return
        # A relative path resolves against SecureCRT's working directory - its
        # own install folder under Program Files - where the write dies with
        # Permission denied after a perfectly good capture.
        if not os.path.isabs(output_dir):
            output_dir = os.path.join(default_dir, output_dir)
        try:
            if not os.path.isdir(output_dir):
                os.makedirs(output_dir)
        except OSError as error:
            crt.Dialog.MessageBox(
                'Could not create {0}:\n{1}\n\nNothing was written. Run the script '
                'again and give a folder you can write to.'.format(output_dir, error),
                'Capture failed')
            return

        # The capture is the audit's input, not an output anyone asked for, so
        # it is written where the checklist is going and removed once the
        # checklist exists. It is only kept when the audit could not run here,
        # where it is the sole record of having been to the switch.
        capture_path = os.path.join(
            output_dir, '{0}_{1}.capture'.format(hostname, _timestamp()))
        try:
            with open(capture_path, 'w', encoding='utf-8') as capture_file:
                capture_file.write(render(outputs))
        except OSError as error:
            crt.Dialog.MessageBox(
                'Could not write {0}:\n{1}\n\nThe capture is intact in memory but '
                'was not saved. Run the script again and give a full path to a '
                'folder you can write to.'.format(capture_path, error), 'Capture failed')
            return

        checklist_path, detail = run_audit(capture_path, hostname, output_dir)
        if checklist_path:
            remove_file(capture_path)
            crt.Dialog.MessageBox(
                'Captured {0} commands from {1} and audited them.\n\n{2}\n\n'
                'Checklist: {3}\n\nOpen it with STIG Viewer 3: '
                'File > Open Checklist.'
                .format(len(outputs), hostname, detail, checklist_path),
                'Checklist written')
            if OPEN_OUTPUT_FOLDER and hasattr(os, 'startfile'):
                os.startfile(output_dir)
        else:
            crt.Dialog.MessageBox(
                'Captured {0} commands from {1}, but no checklist was written.\n\n'
                'The audit did not run here - {2}\n\nThe capture is kept so the trip '
                'to the switch is not wasted:\n{3}'
                .format(len(outputs), hostname, detail, capture_path), 'Capture complete')
    except Exception as error:  # surfaced in a dialog; SecureCRT hides tracebacks
        crt.Dialog.MessageBox('{0}\n\nNothing was written.'.format(error), 'Capture failed')
    finally:
        crt.Screen.Synchronous = False


def _timestamp():
    import time
    return time.strftime('%Y%m%d_%H%M%S')


def remove_file(path):
    """Delete a file, ignoring a failure. Used only on the working capture once
    the checklist it produced exists: a file left behind is untidy, and raising
    over it would report a successful run as a failed one."""
    import os
    try:
        os.remove(path)
    except OSError:
        pass


def find_audit():
    """(repo, python, audit_path) for running the audit here, or (None, None,
    why_not) when this machine cannot - no repo beside this file, or no Python
    that will run it.

    Answered by asking the audit for its own --help, which parses argv and
    exits before it reads a capture, opens a file or touches the network. That
    is a real check rather than "does an executable named python exist": a
    Microsoft Store stub answers to the name and runs nothing.

    Separate from run_audit() so a bulk walker can ask this once, before
    connecting to six hundred switches, rather than discovering per switch that
    nothing here can audit what it just collected."""
    import os.path
    import subprocess

    script_dir = os.path.dirname(os.path.abspath(__file__))
    repo = os.path.dirname(script_dir)
    audit = os.path.join(repo, 'scripts', 'l2_stig_audit.py')
    if not os.path.exists(audit):
        return None, None, ('l2_stig_audit.py not found next to this script - run the '
                            'audit on a machine with the repo:\n'
                            'python scripts/l2_stig_audit.py <name> --from-capture <capture>')

    # Prefer the repo's own venv; fall back to whatever python is on PATH.
    candidates = [os.path.join(repo, '.venv', 'Scripts', 'python.exe'),
                  os.path.join(repo, '.venv', 'bin', 'python'),
                  'python', 'python3']
    last_error = ''
    for python in candidates:
        try:
            probe = subprocess.run([python, audit, '--help'],
                                   capture_output=True, text=True, cwd=repo, timeout=60)
        except (OSError, subprocess.TimeoutExpired) as error:
            last_error = '{0}: {1}'.format(python, error)
            continue
        if probe.returncode == 0:
            return repo, python, ''
        last_error = '{0}: {1}'.format(python, (probe.stderr or probe.stdout).strip()[:200])
    return None, None, ('no runnable python found (tried the repo venv and PATH): '
                        + last_error)


def run_audit(capture_path, hostname, output_dir, runner=None):
    """Run l2_stig_audit.py --from-capture against the just-saved capture,
    writing a STIG Viewer 3 checklist into output_dir. Returns
    (checklist_path, summary_line) on success, (None, why_not) when the audit
    cannot run here - which is not a capture failure, just a machine without
    the repo.

    The audit names the file itself (hostname, capture date, and the STIG
    versions out of the checklist it audited against), which is why it is
    handed a directory rather than a path.

    `runner` is a (repo, python) pair from find_audit(), for a caller that has
    already established one; without it, this finds one per call."""
    import os.path
    import re
    import subprocess

    if runner:
        repo, python = runner
    else:
        repo, python, why_not = find_audit()
        if repo is None:
            return None, why_not

    try:
        # No --checklist: the audit defaults to IOS XE, which is what this
        # script captures from. See the note at the top of the file.
        result = subprocess.run(
            [python, os.path.join(repo, 'scripts', 'l2_stig_audit.py'), hostname,
             '--from-capture', capture_path, '--to-cklb', output_dir],
            capture_output=True, text=True, cwd=repo, timeout=180)
    except (OSError, subprocess.TimeoutExpired) as error:
        return None, 'the audit could not be run: {0}'.format(error)
    if result.returncode != 0:
        return None, ('the audit itself failed:\n'
                      + (result.stdout + result.stderr).strip()[-500:])
    # The audit prints "Wrote <path> for STIG Viewer 3: ..." as its last line,
    # and that path is the one it derived - read it back rather than rebuilding
    # the name here, where a second copy of the naming rule would eventually
    # disagree with the first.
    written = re.search(r'^Wrote (.+?) for STIG Viewer 3: (.*)$', result.stdout, re.M)
    if not written:
        return None, ('the audit ran but wrote no checklist:\n'
                      + result.stdout.strip()[-500:])
    summary = next((line for line in result.stdout.splitlines() if 'out of' in line),
                   written.group(2))
    return written.group(1), summary


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
