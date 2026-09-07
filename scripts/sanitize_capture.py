#!/usr/bin/env python
"""Redact a capture so it can leave the network it came from.

A capture is a verbatim copy of a switch's configuration and live state: real
addressing, hostnames, VLAN names, ACLs, community strings and password
hashes. That is why captures/ is gitignored and why nothing here ever offered
to send one anywhere. But a capture is also the only artifact that reproduces
a report exactly, so there is a standing need to show one to someone - a
vendor case, a screenshot in a ticket, a question in a chat - and the way that
need gets met without a tool is by hand, under time pressure, on the one line
that gets missed.

This does it mechanically, and blunt on purpose: values are overwritten with
placeholders (`x.x.x.x`, `HOSTNAME`, `VLAN-NAME`), not swapped for consistent
fakes. Nothing in the output can be mapped back to what it replaced, because
every value of a kind is replaced by the same token - two interfaces on
different subnets both read `x.x.x.x`.

The cost of that is real and worth stating plainly: **a redacted capture is
for reading, not for re-auditing.** Feeding one back into l2_stig_audit.py
produces a report, and the report is wrong in ways that look right - a
redacted ACL source no longer falls inside `management_subnet`, redacted VLAN
IDs no longer match the user-VLAN list, and both come out as findings against
a switch that has none. The audit is not stopped from running (there is no
honest way to detect this from the text alone), so it is said here instead,
and the tool writes the same warning into the top of every file it produces.

What is deliberately kept: command names, interface names and types, the
structure of every block, IOS keywords, model and release. Without those the
file stops being a configuration and becomes a shape, and nothing useful can
be asked about it. Model and release are not CUI, and V-220569 needs them.

Written as importable functions with a main guard, unlike the audit scripts,
because the redaction rules have to be testable one at a time - a rule that
silently stops matching is exactly the failure this tool cannot have.

Usage:
    python3 sanitize_capture.py captures/S1.capture
    python3 sanitize_capture.py captures/S1.capture -o /tmp/for-the-vendor.txt
"""

import argparse
import os
import re
import sys

WARNING_BANNER = (
    '! ===== REDACTED CAPTURE =====\n'
    '! Addressing, hostnames, VLAN names and IDs, ACL names, descriptions,\n'
    '! credentials and certificates have been overwritten with placeholders by\n'
    '! sanitize_capture.py. Every value of a kind reads the same, so nothing\n'
    '! here maps back to the device.\n'
    '! Do not audit this file: redacted values change verdicts, and the report\n'
    '! would show findings against a switch that does not have them.\n'
    '! =============================\n'
)


class SanitizeError(Exception):
    """The file could not be redacted safely. Always raised rather than
    writing a partial result: a file that says REDACTED at the top and still
    carries an address in the middle is worse than no file, because it will be
    treated as safe by whoever receives it."""


# ---------------------------------------------------------------------------
# Block-scoped redactions: content whose sensitivity is decided by the block it
# is in rather than by the line itself. A run of hex is only a certificate
# because of the `crypto pki certificate chain` above it, and a line of prose
# is only a banner because of the `banner login` above it.
# ---------------------------------------------------------------------------

BANNER_START = re.compile(r'^\s*banner\s+(login|motd|exec|incoming|slip-ppp)\s+(\S)')
# Both of these open a run of encoded bytes: a certificate under
# `crypto pki certificate chain`, and an SSH public key under `key-string` in
# an `ip ssh pubkey-chain`. A public key is not a secret, but it identifies the
# host as surely as its name does, and its hex would trip the leftover scan and
# refuse the whole file - so both are dropped the same way.
BLOB_START = re.compile(r'^\s*(?:crypto pki certificate chain\b|key-string\b)')
HEXISH = re.compile(r'^\s*[0-9A-Fa-f\s]{16,}$')
# An SSH public key under `key-string` is base64, not hex, and went straight
# through a rule that only knew hex runs.
BASE64ISH = re.compile(r'^\s*[A-Za-z0-9+/=]{20,}\s*$')


def _redact_blocks(lines, counts):
    """Redact banner text, certificate bodies and key blobs.

    Certificates carry the switch's serial number in their subject name, and a
    banner is where a site writes what it is - both are why this runs before
    the line rules rather than leaving them to a generic pattern."""
    out = []
    banner_delimiter = None
    in_blob = False
    blob_marked = False
    for line in lines:
        if banner_delimiter is not None:
            # Inside a banner. The delimiter character ends it; everything
            # between is the site's own words.
            if banner_delimiter in line:
                out.append(line[line.index(banner_delimiter):])
                banner_delimiter = None
            elif line.strip():
                counts['banner text'] += 1
            continue

        if in_blob:
            if HEXISH.match(line) or BASE64ISH.match(line):
                counts['certificate or key body'] += 1
                if not blob_marked:
                    out.append('  <encoded body redacted>')
                    blob_marked = True
                continue
            if line.strip() in ('quit', 'quit-less', 'exit'):
                out.append(line)
                in_blob = line.strip() == 'exit'
                continue
            if not line.startswith((' ', '\t')):
                in_blob = False
            else:
                out.append(line)
                continue

        banner = BANNER_START.match(line)
        if banner:
            out.append(line)
            rest = line.split(banner.group(2), 1)[1]
            # A one-line banner (`banner login ^C text ^C`) closes on the same
            # line; anything else opens a block.
            if banner.group(2) in rest:
                counts['banner text'] += 1
                out[-1] = line[:line.index(banner.group(2)) + 1] + (
                    ' <banner text redacted> ' + banner.group(2))
            else:
                banner_delimiter = banner.group(2)
                out.append('<banner text redacted>')
            continue

        if BLOB_START.match(line):
            in_blob, blob_marked = True, False
            out.append(line)
            continue

        out.append(line)
    return out


# ---------------------------------------------------------------------------
# Line rules. Order matters: the specific ones name what they are redacting so
# the output still reads as configuration, and the address patterns at the end
# sweep up whatever a specific rule did not recognise.
#
# Each entry is (category, pattern, replacement). The category is what the
# summary counts and what the leftover scan reports, so it is worded for
# someone deciding whether the file is safe to send.
# ---------------------------------------------------------------------------

LINE_RULES = [
    # Identity of the device and its site.
    ('hostname', re.compile(r'^(\s*hostname\s+)\S+'), r'\1HOSTNAME'),
    ('domain name', re.compile(r'^(\s*ip domain[- ]name\s+)\S+'), r'\1DOMAIN.EXAMPLE'),
    ('description', re.compile(r'^(\s*description\s+).*$'), r'\1<redacted>'),
    ('SNMP location/contact',
     re.compile(r'^(\s*snmp-server\s+(?:location|contact)\s+).*$'), r'\1<redacted>'),
    ('serial number',
     re.compile(r'^(\s*(?:System Serial Number|Motherboard Serial Number|Processor board ID)'
                r'\s*:?\s*)\S+'), r'\1<redacted>'),
    ('SNMP engine ID', re.compile(r'^(\s*Engine ID\s*:\s*)\S+'), r'\1<redacted>'),
    # IOS XE names its self-signed trustpoint, its key pair and that
    # certificate's subject after the switch's serial number, so the serial is
    # in the config three times over on a switch nobody configured PKI on.
    ('serial number', re.compile(r'\bTP-self-signed-\d+'), 'TP-self-signed-XXXX'),
    ('serial number',
     re.compile(r'\b(IOS-Self-Signed-Certificate-)\d+'), r'\1XXXX'),
    ('VTP domain', re.compile(r'^(\s*(?:vtp domain|VTP Domain Name\s*:)\s*)\S+'), r'\1VTP-DOMAIN'),

    # Credentials, and the order within them is the whole of their
    # correctness. Three leaks and one mangling came out of running these
    # against a config shaped like a real one rather than the test fixture:
    #
    #   * `snmp-server user X G v3 auth sha <pass> priv aes 128 <pass>` kept
    #     both passphrases. SNMPv3 is the one place a switch keeps cleartext
    #     credentials in running-config, so it gets its own two rules.
    #   * `ntp authentication-key 1 md5 <hash> 7` redacted the key *id*, which
    #     is not a secret, and left the hash, which is - the generic `key` rule
    #     was matching the tail of "authentication-key" and eating the md5
    #     keyword with it. The hash rules now run first, and the lookbehind
    #     keeps `key` off the end of a longer word.
    #   * `ntp server x.x.x.x key 1` is a reference to a key, not a key.
    #     Redacting it hides nothing and costs the reader the correlation.
    #   * `show vtp password` answers in English - "The VTP password is not
    #     configured." - which became "The VTP password <redacted> not
    #     configured.": a mangled file and a redaction of nothing. Hence the
    #     negative lookahead on ordinary words.
    ('credential', re.compile(r'\b(md5|hmac-sha1|pre-shared-key)\s+(?:\d+\s+)?\S+'),
     r'\1 <redacted>'),
    ('credential', re.compile(r'\b(auth\s+(?:md5|sha\d*)\s+)\S+'), r'\1<redacted>'),
    ('credential',
     re.compile(r'\b(priv\s+(?:des|3des|aes)(?:\s+(?:128|192|256))?\s+)\S+'),
     r'\1<redacted>'),
    ('credential', re.compile(r'(?<![-\w])key\s+\d+\s+\S+'), 'key <redacted>'),
    ('credential',
     re.compile(r'(?<![-\w])key\s+'
                r'(?!chain\b|generate\b|zeroize\b|config-key\b|is\b|not\b|\d)\S+'),
     'key <redacted>'),
    ('credential',
     re.compile(r'\b(secret|password|community)\s+'
                r'(?!is\b|not\b|was\b|has\b|for\b|will\b|encryption\b)'
                r'(?:\d+\s+)?\S+'), r'\1 <redacted>'),
    ('credential', re.compile(r'^(\s*VTP Password\s*:\s*).*$'), r'\1<redacted>'),

    # Accounts and the names that identify who runs the box.
    ('username', re.compile(r'^(\s*username\s+)\S+'), r'\1USERNAME'),
    ('SSH key fingerprint', re.compile(r'^(\s*key-hash\s+\S+\s+)\S+'), r'\1<redacted>'),
    ('username', re.compile(r'^(\s*User name\s*:\s*)\S+'), r'\1USERNAME'),
    ('username', re.compile(r'^(\s*snmp-server\s+user\s+)\S+(\s+)\S+'), r'\1SNMP-USER\2SNMP-GROUP'),
    ('username', re.compile(r'^(\s*snmp-server\s+group\s+)\S+'), r'\1SNMP-GROUP'),
    ('username', re.compile(r'^(\s*Group-name\s*:\s*)\S+'), r'\1SNMP-GROUP'),
    ('AAA server name', re.compile(r'^(\s*(?:radius|tacacs) server\s+)\S+'), r'\1AAA-SERVER'),
    ('AAA server name',
     re.compile(r'^(\s*aaa group server\s+\S+\s+)\S+'), r'\1AAA-GROUP'),

    # ACLs: the name says what it is for, and the entries say what the network
    # looks like. The addresses inside them are caught by the address rules.
    ('ACL name',
     re.compile(r'^(\s*ip(?:v6)? access-list\s+(?:standard\s+|extended\s+|resequence\s+)?)\S+'),
     r'\1ACL-NAME'),
    ('ACL name', re.compile(r'^(\s*access-list\s+)\d+'), r'\1NNN'),
    ('ACL name', re.compile(r'^(\s*access-class\s+)\S+'), r'\1ACL-NAME'),
    ('ACL name', re.compile(r'^(\s*ip access-group\s+)\S+'), r'\1ACL-NAME'),
    ('ACL name', re.compile(r'\bobject-group\s+\S+'), 'object-group OBJECT-GROUP'),

    # VLANs. Only in contexts that are unambiguously a VLAN reference - a bare
    # number rule would rewrite privilege levels, timers and severities.
    ('VLAN id', re.compile(r'^(\s*vlan\s+)[\d,\- ]+$'), r'\1XXX'),
    ('VLAN id', re.compile(r'^(\s*interface\s+Vlan)\d+'), r'\1XXX'),
    ('VLAN id',
     re.compile(r'^(\s*switchport\s+(?:access|voice)\s+vlan\s+)[\d,\-]+'), r'\1XXX'),
    ('VLAN id',
     re.compile(r'^(\s*switchport\s+trunk\s+(?:native\s+vlan|allowed\s+vlan'
                r'(?:\s+(?:add|remove|except))?)\s+)[\d,\-]+'), r'\1XXX'),
    ('VLAN id',
     re.compile(r'^(\s*(?:ip dhcp snooping|ip arp inspection|spanning-tree)\s+vlan\s+)[\d,\-]+'),
     r'\1XXX'),
    ('VLAN id', re.compile(r'^(VLAN)\d{4}\b'), r'\1XXXX'),
    # `show vlan brief` is columnar, and a redaction that shifts every column
    # left turns a table someone can read into one they cannot: each value is
    # padded back to the width of what it replaced.
    ('VLAN name/id',
     re.compile(r'^(\s*)(\d{1,4})(\s+)(\S+)(\s+)(active|suspended|act/unsup|sus/lshut)'),
     lambda m: (m.group(1) + 'XXX'.ljust(len(m.group(2)))
                + m.group(3) + 'VLAN-NAME'.ljust(len(m.group(4)))
                + ' ' * max(1, len(m.group(5)) - max(0, 9 - len(m.group(4))))
                + m.group(6))),

    # Addressing last, so the specific rules above have already named what they
    # redacted. Masks and wildcards go too: on their own they are not
    # sensitive, but keeping them would leave the size and shape of every
    # subnet in a file whose whole purpose is that it no longer describes a
    # real network.
    ('MAC address',
     re.compile(r'\b[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\b'), 'xxxx.xxxx.xxxx'),
    ('MAC address',
     re.compile(r'\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b'), 'xx:xx:xx:xx:xx:xx'),
    ('IPv4 address', re.compile(r'\b\d{1,3}(?:\.\d{1,3}){3}\b'), 'x.x.x.x'),
    ('IPv6 address',
     re.compile(r'(?<![\w:.])(?:'
                r'(?:[0-9A-Fa-f]{1,4}:){3,7}[0-9A-Fa-f]{1,4}'
                r'|(?:[0-9A-Fa-f]{1,4}:){1,7}:(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?'
                r')(?![\w:.])'), 'x:x:x:x::x'),
]


# What the output is checked against before it is allowed to be written. These
# are the same shapes the rules above remove; anything still matching means a
# rule did not fire where it was needed, which is the one failure mode of a
# redaction tool that matters.
LEFTOVER_PATTERNS = [
    ('an IPv4 address', re.compile(r'\b\d{1,3}(?:\.\d{1,3}){3}\b')),
    ('a MAC address', re.compile(r'\b[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\b')),
    ('a MAC address', re.compile(r'\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b')),
    ('a password hash', re.compile(r'\$\d[$a-zA-Z0-9./]{8,}')),
    # The second lookahead is what stops this flagging its own success:
    # `priv aes 128 <redacted>` is redacted, and without it the scan reads the
    # key size as the passphrase and refuses to write a file that is fine.
    ('an SNMPv3 auth or priv passphrase',
     re.compile(r'\b(?:auth\s+(?:md5|sha\d*)|priv\s+(?:des|3des|aes))\s+'
                r'(?!<redacted>)(?!(?:128|192|256)\s+<redacted>)\S+')),
    ('an IPv6 address',
     re.compile(r'(?<![\w:.])(?:[0-9A-Fa-f]{1,4}:){3,7}[0-9A-Fa-f]{1,4}(?![\w:.])')),
    ('a long hex string, which may be a key or certificate',
     re.compile(r'\b[0-9A-Fa-f]{40,}\b')),
]


def find_hostnames(text):
    """Every name this device answers to, from the config and from the prompts
    a session log carries. Returned longest-first so `SW1-CORE` is replaced
    before a `SW1` that is a prefix of it - the other order leaves `-CORE`
    behind, which is exactly the kind of fragment that identifies a site."""
    names = set(re.findall(r'^\s*hostname\s+(\S+)', text, re.M))
    names |= set(re.findall(r'^([A-Za-z][\w.\-]{1,62})[#>]\s*$', text, re.M))
    names |= set(re.findall(r'^([A-Za-z][\w.\-]{1,62})[#>]\s*show\s', text, re.M))
    # A prompt-shaped line inside output ('Router#') is worth replacing too, but
    # single common words are not names worth the collateral: 'Switch' is IOS's
    # own default prompt and appears in prose.
    return sorted((name for name in names if len(name) > 3), key=len, reverse=True)


# The capture tooling's own delimiter lines name a command, and one of those
# commands is `show vtp password`. Left to the rules below, that delimiter came
# out as `show vtp password <redacted>` - a section header capture.py can no
# longer match, so the redacted file stopped being loadable at all. A command
# name is not a secret; these lines are skipped.
DELIMITER_LINE = re.compile(r'^\s*!=+\s*netauto-capture:')


def sanitize(text, extra_terms=()):
    """Redact `text`. Returns (sanitized text, {category: count})."""
    counts = {category: 0 for category, _pattern, _replacement in LINE_RULES}
    counts.update({'banner text': 0, 'certificate or key body': 0, 'hostname': 0})

    lines = _redact_blocks(text.replace('\r\n', '\n').replace('\r', '\n').split('\n'), counts)

    # Hostnames are literal strings rather than a pattern, and they appear
    # everywhere - prompts, banners, certificate subject names, log lines - so
    # they are replaced across the whole text rather than per rule.
    names = list(find_hostnames(text)) + [term for term in extra_terms if term]
    body = '\n'.join(lines)
    for name in sorted(set(names), key=len, reverse=True):
        pattern = re.compile(r'\b' + re.escape(name) + r'\b', re.I)
        body, hits = pattern.subn('HOSTNAME', body)
        counts['hostname'] += hits

    out = []
    in_vlan_block = False
    for line in body.split('\n'):
        # `name X` is a VLAN's name only inside a `vlan <id>` block; elsewhere
        # it is part of some other command entirely.
        if re.match(r'^\s*vlan\s', line):
            in_vlan_block = True
        elif line[:1] not in (' ', '\t'):
            in_vlan_block = False
        if in_vlan_block:
            line, hits = re.subn(r'^(\s+name\s+).*$', r'\1VLAN-NAME', line)
            counts['VLAN name/id'] = counts.get('VLAN name/id', 0) + hits

        if not DELIMITER_LINE.match(line):
            for category, pattern, replacement in LINE_RULES:
                line, hits = pattern.subn(replacement, line)
                counts[category] += hits
        out.append(line)

    return '\n'.join(out), {k: v for k, v in counts.items() if v}


def find_leftovers(text):
    """[(line number, what it looks like)] for anything the rules should have
    removed. The line's content is deliberately not returned: the point of
    this function is to be printed, and printing the value would put the thing
    being redacted on someone's terminal."""
    found = []
    for number, line in enumerate(text.split('\n'), 1):
        for description, pattern in LEFTOVER_PATTERNS:
            if pattern.search(line):
                found.append((number, description))
                break
    return found


def default_output_path(input_path):
    stem, extension = os.path.splitext(input_path)
    return f'{stem}.redacted{extension or ".capture"}'


def sanitize_file(input_path, output_path=None, extra_terms=(), force=False):
    """Redact a capture file. Returns (output path, counts)."""
    if not os.path.exists(input_path):
        raise SanitizeError(f'No such capture file: {input_path}')
    output_path = output_path or default_output_path(input_path)
    if os.path.abspath(output_path) == os.path.abspath(input_path):
        raise SanitizeError(
            'Refusing to redact a capture in place - the original is the only copy of what '
            'the switch actually said, and the audit needs it.')
    if os.path.exists(output_path) and not force:
        raise SanitizeError(
            f'{output_path} already exists. Pass --force to replace it, or -o to write '
            'somewhere else.')

    with open(input_path, 'rb') as capture_file:
        raw = capture_file.read()
    # Same encodings capture.py accepts: these files come off PowerShell and
    # SecureCRT, which write BOMs and UTF-16 without being asked.
    for bom, encoding in (('\xef\xbb\xbf'.encode('latin-1'), 'utf-8-sig'),
                          (b'\xff\xfe', 'utf-16'), (b'\xfe\xff', 'utf-16')):
        if raw.startswith(bom):
            text = raw.decode(encoding, errors='replace')
            break
    else:
        text = raw.decode('utf-8', errors='replace')

    sanitized, counts = sanitize(text, extra_terms=extra_terms)
    leftovers = find_leftovers(sanitized)
    if leftovers:
        listed = ', '.join(f'line {number} ({what})' for number, what in leftovers[:10])
        raise SanitizeError(
            f'{len(leftovers)} line(s) still look sensitive after redaction, so nothing was '
            f'written: {listed}'
            f'{" ..." if len(leftovers) > 10 else ""}\n'
            'The value itself is not printed here - open the input at those lines to see what '
            'shape it takes, and add a rule to LINE_RULES for it. A partially redacted file is '
            'more dangerous than none, because it will be treated as safe.')

    with open(output_path, 'w', encoding='utf-8') as out_file:
        out_file.write(WARNING_BANNER + sanitized)
    return output_path, counts


def main(argv=None):
    parser = argparse.ArgumentParser(
        description='Redact a capture (or any Cisco config/show output) so it can be shared '
                    'off the network it came from.')
    parser.add_argument('capture', help='The capture file to redact. Never modified.')
    parser.add_argument('-o', '--output', metavar='PATH',
                        help='Where to write the redacted copy. Default: alongside the input, '
                             'named <name>.redacted<ext>.')
    parser.add_argument('--also-redact', metavar='TERM', action='append', default=[],
                        help='An extra literal string to remove everywhere - a site name, a '
                             'building, a project. Repeatable. Case-insensitive.')
    parser.add_argument('--force', action='store_true',
                        help='Replace the output file if it already exists.')
    args = parser.parse_args(argv)

    try:
        output_path, counts = sanitize_file(args.capture, args.output,
                                            extra_terms=args.also_redact, force=args.force)
    except SanitizeError as error:
        print(error)
        return 2

    print(f'Wrote {output_path}')
    for category in sorted(counts):
        print(f'  {counts[category]:5}  {category}')
    print('\nRead it before sending it. This removes what it has rules for, and a capture can '
          'carry anything.\nDo not audit the redacted file - the placeholders change verdicts.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
