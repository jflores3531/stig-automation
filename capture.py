#!/usr/bin/env python
"""Run a STIG audit against text captured from a device instead of connecting
to it.

Every check in l2_stig_audit.py is a pure function of command output, so the
only part of an audit that needs a live session is collecting that output.
This module supplies a stand-in for a Netmiko connection that serves output
from a capture file, which lets the audit run where the device isn't reachable
- or where nothing may be pointed at the network but an already-approved
terminal emulator. Collect the file by logging a SecureCRT session and running
the commands in AUDIT_COMMANDS_L2S; both the delimited form this project's own
capture tooling writes and a plain session log are accepted.

A capture is a verbatim copy of a device's configuration. On a production
network that means real addressing, hostnames and password hashes, so captures
belong in the gitignored captures/ directory and nowhere near a commit.
"""

import codecs
import os
import re

import netauto

CAPTURE_DIR = os.path.join(netauto.PROJECT_ROOT, 'captures')

# The complete set of commands an L2S audit reads. Four rules need live state
# that never appears in running-config: user VLANs for V-220633/635, the STP
# root port for V-220629 (Root Guard must never be pushed there), the VTP
# password for V-220624 and the SNMPv3 users for V-220604/605 - IOS classic
# never writes `snmp-server user` to running-config at all. Anything added to
# a discovery step in l2_stig_audit.py has to be added here too, or a capture
# that looks complete will be missing it.
AUDIT_COMMANDS_L2S = (
    'show running-config',
    'show vlan brief',
    'show spanning-tree',
    'show vtp password',
    'show snmp user',
)

# Commands whose empty output is an answer rather than a failed read. Refusing
# a capture because a command returned nothing is right in general - nothing
# read and nothing configured look identical - but `show snmp user` prints
# nothing at all when no SNMPv3 users are defined, and that is a real, legal,
# and non-compliant switch state: exactly what V-220604/605 exist to catch.
# Refusing it would block the whole audit on the very configuration it is meant
# to report, so the section must still be present (see load()'s `missing`
# check) but is allowed to be empty. _snmpv3_user_live_check reads empty output
# as "no SNMPv3 user with an authentication protocol found" and FAILs, which is
# the correct verdict.
EMPTY_IS_AN_ANSWER = ('show snmp user',)


def empty_is_an_answer(command):
    return _normalise(command) in {_normalise(c) for c in EMPTY_IS_AN_ANSWER}


# A sixth command, but a per-device one, so it cannot live in the tuple above.
# An IOS XE interface can be configured by `source template <name>` instead of
# carrying the commands itself, and running-config then shows only that one
# line - the access VLAN, the mode, PortFast, BPDU Guard, 802.1x all sit in the
# template and appear nowhere in the config text. Read against config alone
# those ports look bare, which is a false FAIL on every per-port rule at once
# (V-220649/656/668/671 on the work fleet). The template body has to be asked
# for by name, and the names are only knowable from the config, so which
# commands a capture must cover depends on the config it carries. load_l2s
# below does that in two passes.
TEMPLATE_COMMAND_PREFIX = 'show template interface source user '


def template_command(name):
    return TEMPLATE_COMMAND_PREFIX + name


def sourced_template_names(running_config):
    """Distinct interface-template names a running-config sources, in the order
    they first appear. Empty for a switch that uses no templates, which is why
    nothing about this is required of a capture that does not need it."""
    names = []
    for name in re.findall(r'^\s*source template (\S+)\s*$', running_config, re.M):
        if name not in names:
            names.append(name)
    return names


# Deliberately loose. This only has to tell a running-config apart from shell
# error text or an appliance's help output - not validate the configuration,
# which is the audit's whole job. Any single marker is enough, since platforms
# differ in which of these they emit and a trimmed capture may lack the header.
IOS_CONFIG_MARKERS = ('current configuration', '\nhostname ', '\nend',
                      'building configuration', '\ninterface ', '\nversion ')


def looks_like_ios_config(text):
    lowered = text.lower()
    return any(marker in lowered for marker in IOS_CONFIG_MARKERS)


# Written before each command's output by the capture tooling. The leading '!'
# makes the whole line an IOS comment, so a capture pasted into a terminal by
# mistake is inert rather than interpreted.
DELIMITER_PREFIX = '!===== netauto-capture: '
DELIMITER_SUFFIX = ' ====='

# A prompt line: hostname, then '#' or '>'. Used only to recognise the command
# echo in a plain session log, and to drop the trailing prompt from a section.
PROMPT = r'^\S*[#>]\s*'


class CaptureError(Exception):
    """A capture file is missing, malformed, or doesn't cover a command the
    audit asked for. Always raised rather than degrading to empty output: a
    check handed '' returns a verdict with the same confidence as one handed
    real config, and a false PASS on a rule nobody re-reads is worse than a
    crash."""


def format_delimiter(command):
    """The delimiter line introducing `command`'s output in a capture file."""
    return f'{DELIMITER_PREFIX}{command}{DELIMITER_SUFFIX}'


def render(outputs):
    """Render {command: output} into capture-file text.

    The counterpart to parse(), and the reason an offline run can be checked
    against a live one: audit a switch with --capture-to, re-run the same audit
    with --from-capture against the file it wrote, and any difference in the
    two reports is a defect in this module rather than a difference between
    the switches."""
    blocks = []
    for command, output in outputs.items():
        blocks.append(format_delimiter(command))
        blocks.append(str(output).rstrip('\n'))
        blocks.append('')
    return '\n'.join(blocks)


def write(path, outputs):
    """Write a capture file, creating its parent directory if needed."""
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, 'w', encoding='utf-8') as capture_file:
        capture_file.write(render(outputs))
    return path


def _normalise(command):
    """Collapse whitespace so 'show  vlan brief' and 'show vlan brief' match."""
    return ' '.join(command.split())


def _trim_blank_edges(text):
    """Drop leading and trailing blank lines without touching indentation -
    running-config leans on leading spaces to delimit interface blocks, so a
    plain .strip() would corrupt the first line of a section."""
    lines = text.replace('\r\n', '\n').replace('\r', '\n').split('\n')
    while lines and not lines[0].strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()
    return '\n'.join(lines)


def _drop_trailing_prompt(text):
    """Remove a trailing bare prompt line ('S1#'). Netmiko strips the prompt
    from send_command()'s return value, so a capture has to as well or checks
    anchored to end-of-output behave differently offline than they did live."""
    lines = text.split('\n')
    while lines and re.match(PROMPT + r'$', lines[-1]):
        lines.pop()
    return '\n'.join(lines)


def _reject_paginated(text, source):
    """Refuse a capture taken without 'terminal length 0'. A --More-- prompt
    truncates output mid-config and leaves the pager's backspace padding
    behind; the audit would read a partial running-config as the whole thing
    and fail every rule whose evidence sat past the first screen."""
    if re.search(r'--\s*[Mm]ore\s*--', text):
        raise CaptureError(
            f'{source} contains a --More-- pager prompt, so its output is truncated.\n'
            "Run 'terminal length 0' before the show commands and capture again."
        )


def _split_on_delimiters(text):
    """Parse the delimited form. Returns None if the file carries no delimiters
    at all, so the caller can fall back to reading it as a session log."""
    pattern = re.compile(
        '^' + re.escape(DELIMITER_PREFIX) + r'(.+?)' + re.escape(DELIMITER_SUFFIX) + r'\s*$',
        re.M,
    )
    matches = list(pattern.finditer(text))
    if not matches:
        return None
    sections = {}
    for i, match in enumerate(matches):
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        sections[_normalise(match.group(1))] = text[match.end():end]
    return sections


def _split_on_prompt_echo(text, known_commands):
    """Parse a plain SecureCRT session log, splitting on the echoed command.

    Only the commands actually being looked for are treated as separators. A
    generic 'prompt followed by anything' pattern would split inside
    running-config output, which is full of lines that read like commands -
    and each bogus split would silently shorten the section before it."""
    alternation = '|'.join(
        re.escape(command) for command in sorted(known_commands, key=len, reverse=True)
    )
    pattern = re.compile(PROMPT + f'({alternation})' + r'\s*$', re.M)
    matches = list(pattern.finditer(text))
    if not matches:
        return {}
    sections = {}
    for i, match in enumerate(matches):
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        sections[_normalise(match.group(1))] = text[match.end():end]
    return sections


def parse(text, known_commands=AUDIT_COMMANDS_L2S, source='capture'):
    """Parse capture text into {command: output}, trying the delimited form
    first and falling back to a plain session log."""
    text = text.replace('\r\n', '\n').replace('\r', '\n')
    _reject_paginated(text, source)
    sections = _split_on_delimiters(text)
    if sections is None:
        sections = _split_on_prompt_echo(text, known_commands)
    return {
        command: _trim_blank_edges(_drop_trailing_prompt(_trim_blank_edges(output)))
        for command, output in sections.items()
    }


class CaptureSession:
    """Stands in for a Netmiko connection, serving output from a capture.

    Only send_command() and disconnect() are implemented, which is all the
    audit path uses - stig_common.run_stig_audit, discover_user_vlans and
    discover_root_port_interfaces all reach a device solely through those two.
    That is what lets those functions run offline unmodified."""

    def __init__(self, sections, source):
        self._sections = {_normalise(k): v for k, v in sections.items()}
        self.source = source

    def send_command(self, command, *_args, **_kwargs):
        key = _normalise(command)
        if key not in self._sections:
            available = ', '.join(sorted(self._sections)) or '(none)'
            raise CaptureError(
                f"{self.source} has no output for '{command}'.\n"
                f'It covers: {available}\n'
                'Capture that command and try again - the audit will not guess at '
                'output it was not given.'
            )
        return self._sections[key]

    def disconnect(self):
        """No-op. Present so the audit's connect/read/disconnect flow runs
        unchanged offline rather than needing a branch at every call site."""


# A capture does not always arrive the way the capture tooling wrote it. The
# work switches are reachable only through PowerShell or SecureCRT, and both of
# PowerShell's obvious ways to save output add a byte order mark: `>` and
# Out-File default to UTF-16LE on Windows PowerShell 5.1, and
# `Out-File -Encoding utf8` writes UTF-8 with a BOM. Decoding either as plain
# UTF-8 fails in a way that does not name its cause - a UTF-8 BOM glues itself
# to the first delimiter line so only that section goes missing ("missing
# output for: show running-config"), and UTF-16 decodes to NUL-riddled text
# that matches nothing at all ("no recognisable command output"). Both are a
# wasted trip to a switch, so the BOM decides the encoding here instead.
BOMS = (
    (codecs.BOM_UTF8, 'utf-8-sig'),
    (codecs.BOM_UTF32_LE, 'utf-32'),
    (codecs.BOM_UTF32_BE, 'utf-32'),
    (codecs.BOM_UTF16_LE, 'utf-16'),
    (codecs.BOM_UTF16_BE, 'utf-16'),
)


def _read_text(path, source):
    with open(path, 'rb') as capture_file:
        raw = capture_file.read()
    # UTF-32's BOMs start with UTF-16's, so the longer marks are tested first.
    encoding = 'utf-8'
    for bom, bom_encoding in BOMS:
        if raw.startswith(bom):
            encoding = bom_encoding
            break
    text = raw.decode(encoding, errors='replace')
    if '\x00' in text:
        raise CaptureError(
            f'{source} is not text this can read - it contains NUL bytes, which '
            'usually means a UTF-16 file saved without a byte order mark.\n'
            'Re-save it as UTF-8 (PowerShell: '
            "`Set-Content -Encoding utf8`, or `Out-File -Encoding utf8`)."
        )
    return text


def load(path, required_commands=AUDIT_COMMANDS_L2S):
    """Read a capture file and return a CaptureSession.

    Every command in required_commands must be present, and non-empty unless
    it is in EMPTY_IS_AN_ANSWER. Validating up front means a capture missing
    'show vtp password' is rejected before the audit prints its first verdict,
    rather than 50 rules in."""
    if not os.path.exists(path):
        raise CaptureError(f'No such capture file: {path}')
    source = os.path.basename(path)
    text = _read_text(path, source)

    sections = parse(text, required_commands, source=source)
    if not sections:
        raise CaptureError(
            f'{source} has no recognisable command output.\n'
            'Expected either delimiter lines written by the capture tooling '
            f'("{format_delimiter("show running-config")}"), or a session log '
            'showing each command echoed after the device prompt.'
        )

    missing = [
        command for command in required_commands
        if _normalise(command) not in {_normalise(k) for k in sections}
    ]
    if missing:
        raise CaptureError(
            f'{source} is missing output for: {", ".join(missing)}\n'
            f'It covers: {", ".join(sorted(sections))}\n'
            'An audit run against a partial capture would report those rules '
            'against empty output, so it is refused rather than reported.'
        )

    empty = [
        command for command in required_commands
        if not sections[_normalise(command)].strip() and not empty_is_an_answer(command)
    ]
    if empty:
        raise CaptureError(
            f'{source} has empty output for: {", ".join(empty)}\n'
            'A command that returned nothing is indistinguishable from a feature '
            'that is switched off, so this is refused rather than audited.'
        )

    # Last line of defence, and the only one that applies however the capture
    # was collected. A session driven against something that is not a Cisco
    # switch - a jump host, a console server, an appliance answering on :22 -
    # produces a file with all five sections present and none of them config.
    # Every rule would then be answered against shell error text, and a report
    # of 60 findings is indistinguishable from a switch that is genuinely
    # non-compliant. Refuse it instead.
    config = sections[_normalise('show running-config')]
    if not looks_like_ios_config(config):
        raise CaptureError(
            f'{source} does not contain a Cisco configuration.\n'
            "'show running-config' returned text with none of the expected "
            'markers (Current configuration, hostname, interface, version, end). '
            'This usually means the capture was taken against something other '
            'than a Cisco switch.'
        )
    return CaptureSession(sections, source)


def load_l2s(path):
    """Load an L2S capture, including the interface templates its own config
    says the interfaces are configured from.

    Two passes, because the second list of required commands is written in the
    first pass's output: the config names the templates, and each name is its
    own show command. A capture that sources templates but does not carry them
    is refused by the same rule as one missing `show vtp password` - the audit
    would report every per-port rule against interfaces whose configuration it
    cannot see, and those verdicts would read exactly like real findings.

    Re-loading rather than patching the first session also fixes a plain
    session log, where sections are split on the echoed command and the
    template commands were not among the ones being looked for."""
    session = load(path, AUDIT_COMMANDS_L2S)
    names = sourced_template_names(str(session.send_command('show running-config')))
    if not names:
        return session
    return load(path, AUDIT_COMMANDS_L2S + tuple(template_command(name) for name in names))
