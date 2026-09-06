#!/usr/bin/env python
"""sanitize_capture.py: what must not survive, and what must.

Run directly: `python3 tests/test_sanitize_capture.py`. No framework, no device.

A redaction tool has one failure mode that matters - a value that survives in a
file everyone downstream now believes is safe - and one that costs it its
users: redacting so much that the output is no longer a configuration. Both
are asserted here against SENSITIVE below, which is written to carry one of
each shape this tool claims to handle.

Every leak in it was a real bug before it was a test: the SNMPv3 auth and priv
passphrases survived untouched (running-config keeps those in the clear); the
NTP hash survived while its key *id* was redacted instead; and the capture's
own `show vtp password` delimiter was rewritten into something capture.py
could no longer parse. The negative cases in test_reads_as_config are the
mirror: `The VTP password is not configured.` came out as `The VTP password
<redacted> not configured.`
"""

import os
import sys
import tempfile

PROJECT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import capture
import fixtures
import sanitize_capture

failures = []


def check(name, condition, detail=''):
    print(f'  {"ok  " if condition else "FAIL"} {name}')
    if not condition:
        if detail:
            print(f'       {detail}')
        failures.append(name)


# Invented, not taken from anything: RFC 5737 documentation addressing, RFC
# 3849 documentation IPv6, and hashes that are the right shape and no one's.
SENSITIVE = """SW-BLDG3-IDF2#show running-config
!
hostname SW-BLDG3-IDF2
!
ip domain name bldg3.example.mil
!
enable secret 9 $9$vFxG8mQ1kL2pQ.$aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789
username netadmin privilege 15 secret 9 $9$abcdEFGH1234$zyxwvutsrq
username backup password 7 070C285F4D06
!
vlan 812
 name BLDG3-USERS
!
interface GigabitEthernet1/0/7
 description Uplink to BLDG3 MDF room 214
 switchport access vlan 812
!
interface Vlan812
 ip address 192.0.2.13 255.255.255.0
 ipv6 address 2001:db8:aaaa:1::5/64
!
ip access-list extended MGMT-VTY-BLDG3
 permit tcp 192.0.2.0 0.0.0.255 any eq 22 log
!
line vty 0 4
 access-class MGMT-VTY-BLDG3 in
!
snmp-server community Str0ngC0mmun1ty RO
snmp-server location BLDG3 IDF2 rack 4
snmp-server user stigadmin STIGGRP v3 auth sha S3cretAuth priv aes 128 S3cretPriv
!
radius server RAD-BLDG3
 address ipv4 192.0.2.20 auth-port 1812 acct-port 1813
 key 7 14141B180F0B
!
ntp authentication-key 1 md5 0215552D5D08 7
ntp server 192.0.2.30 key 1
!
banner login ^C
You are accessing the BLDG3 network of the 123rd Example Battalion.
^C
!
end

SW-BLDG3-IDF2#show mac address-table
   10    aabb.ccdd.eeff    DYNAMIC     Gi1/0/7

SW-BLDG3-IDF2#show running-config | section pubkey
ip ssh pubkey-chain
  username netadmin
   key-hash ssh-rsa AABBCCDDEEFF00112233445566778899
   key-string
    AAAAB3NzaC1yc2EAAAADAQABAAABgQCnotarealkey0000
   exit
  exit
!
crypto pki certificate chain TP-self-signed-4242424242
 certificate self-signed 01
  30820330 30820218 A0030201 02024101 300D0609 2A864886
  quit
"""

MUST_NOT_SURVIVE = [
    ('the hostname', 'SW-BLDG3-IDF2'),
    ('the domain name', 'bldg3.example.mil'),
    ('the enable secret', '$9$vFxG8mQ1kL2pQ.'),
    ('a user secret', '$9$abcdEFGH1234'),
    ('a type 7 password', '070C285F4D06'),
    ('the VLAN name', 'BLDG3-USERS'),
    # Not a bare '812': that is a substring of the RADIUS port 1812, which is
    # not sensitive and must not be redacted. The VLAN contexts are.
    ('the VLAN id where a VLAN is named', 'vlan 812'),
    ('the VLAN id in an SVI', 'Vlan812'),
    ('an interface description', 'MDF room 214'),
    ('an IPv4 address', '192.0.2.13'),
    ('a subnet mask', '255.255.255.0'),
    ('an ACL wildcard', '0.0.0.255'),
    ('an IPv6 address', '2001:db8:aaaa:1::5'),
    ('the ACL name', 'MGMT-VTY-BLDG3'),
    ('the SNMP community', 'Str0ngC0mmun1ty'),
    ('the SNMP location', 'IDF2 rack 4'),
    ('the SNMPv3 auth passphrase', 'S3cretAuth'),
    ('the SNMPv3 priv passphrase', 'S3cretPriv'),
    ('the SNMP user', 'stigadmin'),
    ('the RADIUS key', '14141B180F0B'),
    ('the NTP authentication hash', '0215552D5D08'),
    ('the unit named in the banner', '123rd Example Battalion'),
    ('a MAC address', 'aabb.ccdd.eeff'),
    # A public key is not a secret, but it identifies the host as surely as its
    # name does - and it is base64, which a hex-shaped rule walked straight
    # past the first time.
    ('an SSH public key', 'AAAAB3NzaC1yc2EAAAADAQAB'),
    ('an SSH key fingerprint', 'AABBCCDDEEFF00112233445566778899'),
    ('a certificate body', '30820330 30820218'),
    ('the serial in the self-signed trustpoint name', '4242424242'),
]


def test_nothing_sensitive_survives():
    print('nothing in the sample survives redaction')
    out, _counts = sanitize_capture.sanitize(SENSITIVE)
    for what, value in MUST_NOT_SURVIVE:
        check(f'{what} is gone', value not in out,
              [line for line in out.split('\n') if value in line][:1])
    check('and the tool agrees the output is clean',
          sanitize_capture.find_leftovers(out) == [],
          sanitize_capture.find_leftovers(out))


def test_reads_as_config():
    print('\nand what is left is still a configuration')
    out, counts = sanitize_capture.sanitize(SENSITIVE)
    for what, kept in (
            ('interface names', 'interface GigabitEthernet1/0/7'),
            ('the commands themselves', 'switchport access vlan'),
            ('ACL structure', 'permit tcp'),
            ('the port an ACL permits', 'eq 22 log'),
            ('block markers', 'ip access-list extended'),
            ('that a banner exists at all', 'banner login'),
            ('that SNMPv3 uses SHA and AES', 'auth sha'),
    ):
        check(f'{what} survive', kept in out, out)

    check('a key id is not a key: `key 1` is left to read',
          'ntp server x.x.x.x key 1' in out,
          [line for line in out.split('\n') if 'ntp server' in line])
    check('and the counts say what was done', counts.get('credential', 0) >= 6, counts)


def test_prose_in_show_output_is_not_mangled():
    print('\nshow output is English, and English is not a password')
    out, _counts = sanitize_capture.sanitize(
        'The VTP password is not configured.\nVTP Password is configured\n'
        'VTP Password: Sup3rSecret!\n')
    check('"is not configured" is left alone', 'The VTP password is not configured.' in out, out)
    check('"is configured" too', 'VTP Password is configured' in out, out)
    check('but a disclosed password is not', 'Sup3rSecret!' not in out, out)


def test_capture_still_parses(tmpdir):
    print('\na redacted capture is still a capture')
    source = capture.write(os.path.join(tmpdir, 'S1.capture'), fixtures.OUTPUTS)
    out, _counts = sanitize_capture.sanitize_file(source)
    check('the redacted copy loads', bool(capture.load(out)))
    text = open(out, encoding='utf-8').read()
    for command in capture.AUDIT_COMMANDS_L2S:
        check(f"the '{command}' section header is intact",
              capture.format_delimiter(command) in text)
    check('and it says at the top what it is', 'REDACTED CAPTURE' in text.split('\n')[0], text[:80])
    check('including that it must not be audited', 'Do not audit this file' in text)


def test_refuses_to_write_a_partial_redaction(tmpdir):
    print('\nan unredacted value stops the file being written at all')
    # A shape no rule covers: an address written the way a switch never writes
    # one, which is exactly how a leak reaches a file nobody re-reads.
    leaky = os.path.join(tmpdir, 'leaky.capture')
    with open(leaky, 'w', encoding='utf-8') as leaky_file:
        leaky_file.write('hostname SW1\n! reachable at 198.51.100.7 via the jump host\n')
    original = sanitize_capture.LINE_RULES
    sanitize_capture.LINE_RULES = [rule for rule in original if rule[0] != 'IPv4 address']
    try:
        error = None
        try:
            sanitize_capture.sanitize_file(leaky, os.path.join(tmpdir, 'out.capture'))
        except sanitize_capture.SanitizeError as raised:
            error = str(raised)
    finally:
        sanitize_capture.LINE_RULES = original
    check('it refuses', error is not None)
    check('names the line', error and 'line 2' in error, error)
    check('says what shape it saw', error and 'IPv4' in error, error)
    check('does not print the value itself', error and '198.51.100.7' not in error, error)
    check('and writes nothing', not os.path.exists(os.path.join(tmpdir, 'out.capture')))


def test_guards_the_original(tmpdir):
    print('\nthe original capture is not something to redact in place')
    source = capture.write(os.path.join(tmpdir, 'guard.capture'), fixtures.OUTPUTS)
    before = open(source, encoding='utf-8').read()

    error = None
    try:
        sanitize_capture.sanitize_file(source, source)
    except sanitize_capture.SanitizeError as raised:
        error = str(raised)
    check('redacting in place is refused', error is not None and 'in place' in (error or ''), error)
    check('and the original is untouched', open(source, encoding='utf-8').read() == before)

    out, _counts = sanitize_capture.sanitize_file(source)
    check('a second run refuses to clobber its own output',
          _raises(sanitize_capture.SanitizeError,
                  lambda: sanitize_capture.sanitize_file(source)))
    check('unless told to', bool(sanitize_capture.sanitize_file(source, force=True)))
    check('the default output sits beside the input', out.endswith('.redacted.capture'), out)


def test_extra_terms(tmpdir):
    print('\n--also-redact takes what only the operator knows is sensitive')
    out, _counts = sanitize_capture.sanitize(
        'interface GigabitEthernet1/0/1\n description PROJECT BLUEBIRD uplink\n'
        'snmp-server contact ops\n! PROJECT BLUEBIRD\n',
        extra_terms=['PROJECT BLUEBIRD'])
    check('the term is gone everywhere, not just in the fields with rules',
          'BLUEBIRD' not in out, out)


def _raises(exception_type, call):
    try:
        call()
    except exception_type:
        return True
    return False


if __name__ == '__main__':
    with tempfile.TemporaryDirectory() as tmp:
        test_nothing_sensitive_survives()
        test_reads_as_config()
        test_prose_in_show_output_is_not_mangled()
        test_capture_still_parses(tmp)
        test_refuses_to_write_a_partial_redaction(tmp)
        test_guards_the_original(tmp)
        test_extra_terms(tmp)
    print('\n' + ('ALL CHECKS PASSED' if not failures
                  else f'{len(failures)} FAILED: {", ".join(failures)}'))
    sys.exit(1 if failures else 0)
