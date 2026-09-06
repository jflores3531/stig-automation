#!/usr/bin/env python
"""The exported checklist's asset block and its file name.

Run directly: `python3 tests/test_checklist_target.py`. No framework, no device.

STIG Viewer 3's asset fields - host name, IP address, MAC address, FQDN - are
the four a reviewer would otherwise fill in per switch, from the switch. None of
them changes a verdict, which is exactly why they need testing: a wrong value
here cannot turn a finding into a pass, so nothing else in the run will
contradict it. What it can do is attach one switch's 64 verdicts to another
switch's name.

The file name is the same problem one level up. `SW01_06AUG2026_L2S_V3R2_NDM_V3R6`
says which switch, which day, and which benchmark revision - and the versions
are read out of the checklist that was audited against rather than written down
anywhere, so pointing the audit at next quarter's .cklb moves them without
anyone remembering to.
"""

import datetime
import json
import os
import re
import subprocess
import sys
import tempfile

PROJECT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import capture
import fixtures
import stig_common

IOS_XE_CHECKLIST = os.path.join(PROJECT, 'checklists', 'IOS-XE Checklist.cklb')

failures = []


def check(name, condition, detail=''):
    print(f'  {"ok  " if condition else "FAIL"} {name}')
    if not condition:
        if detail:
            print(f'       {detail}')
        failures.append(name)


def test_reads_each_field():
    print('each asset field is read from the output the verdicts came from')
    check('hostname from the config, not the label the audit was run under',
          stig_common.parse_hostname(fixtures.RUNNING_CONFIG) == 'TESTSW01')
    check('domain from `ip domain name`',
          stig_common.parse_domain_name(fixtures.RUNNING_CONFIG) == 'example.test')
    check('classic IOS spells it `ip domain-name`, and that is read too',
          stig_common.parse_domain_name('ip domain-name example.test') == 'example.test')
    check('a VRF between the command and the domain is stepped over, not read as one',
          stig_common.parse_domain_name('ip domain name vrf Mgmt-vrf example.test')
          == 'example.test')
    check('FQDN is <hostname>.<domain name>',
          stig_common.parse_fqdn(fixtures.RUNNING_CONFIG) == 'TESTSW01.example.test')

    # A hostname with no domain is not an FQDN. Writing one anyway would put a
    # value in the field that looks answered and is wrong.
    no_domain = fixtures.RUNNING_CONFIG.replace('ip domain name example.test', '')
    check('no domain means no FQDN, rather than a half-qualified name',
          stig_common.parse_fqdn(no_domain) is None, stig_common.parse_fqdn(no_domain))

    check('MAC from `show version`',
          stig_common.parse_base_mac(fixtures.SHOW_VERSION) == '00:1A:2B:3C:4D:5E')
    check('and the dotted form platforms print instead is normalised to it',
          stig_common.parse_base_mac('Base Ethernet MAC Address : 001a.2b3c.4d5e')
          == '00:1A:2B:3C:4D:5E')
    check('output with no MAC line yields nothing, not an empty-looking value',
          stig_common.parse_base_mac('Cisco IOS XE Software, Version 17.12.04') is None)


def test_management_ip():
    print('\nthe management address: two commands, neither sufficient alone')
    address, why = stig_common.find_management_ip(
        fixtures.VLAN_BRIEF, fixtures.IP_INTERFACE_BRIEF)
    check('the management SVI is the one picked', address == '192.0.2.5', f'{address} ({why})')
    check('and the reason names the VLAN it came from, by number and name',
          'Vlan10' in why and 'MGMT' in why, why)

    # Gi0/0 is the out-of-band port and carries an address. It is a plausible
    # wrong answer, and it is not an SVI, so it must not be the one chosen.
    check('the out-of-band port is not mistaken for the management SVI',
          address != '198.51.100.5', address)

    # A fleet naming its management VLAN <site>-mgt is the case the default
    # patterns exist for - and the number moves per site while the name does not.
    renamed = fixtures.VLAN_BRIEF.replace('10   MGMT   ', '10   army-xxx-abc-mgt')
    address, why = stig_common.find_management_ip(renamed, fixtures.IP_INTERFACE_BRIEF)
    check('a name ending in mgt matches as well as MGMT', address == '192.0.2.5', why)

    none, why = stig_common.find_management_ip(
        fixtures.VLAN_BRIEF.replace('MGMT', 'CONTROL'), fixtures.IP_INTERFACE_BRIEF)
    check('no management-named VLAN yields no address', none is None, none)
    check('and says what it looked for, so the fix is one flag away',
          '*mgt' in why, why)

    # Two of them means the pattern is wrong for this fleet. Picking one would
    # put a plausible address in a signed artifact.
    two = fixtures.VLAN_BRIEF.replace('20   USERS ', '20   OOB-mgt')
    ambiguous, why = stig_common.find_management_ip(
        two, fixtures.IP_INTERFACE_BRIEF + '\nVlan20                 192.0.2.9       YES NVRAM  up  up')
    check('two management-named VLANs with addresses is reported, not resolved',
          ambiguous is None and 'more than one' in why, f'{ambiguous} ({why})')

    check('an SVI with no address is not an answer either',
          stig_common.find_management_ip(fixtures.VLAN_BRIEF, 'Interface  IP-Address\n'
                                         'Vlan10     unassigned  YES NVRAM up up')[0] is None)


def test_filename():
    print('\nthe file name says which switch, which day, and which benchmark')
    on = datetime.date(2026, 8, 6)
    name = stig_common.checklist_filename(IOS_XE_CHECKLIST, 'SW01', on)
    check('shaped like the example', re.match(
        r'^SW01_06AUG2026_L2S_V\d+R\d+_NDM_V\d+R\d+\.cklb$', name), name)
    check('the versions are the ones in the checklist, not ones written down here',
          stig_common.checklist_stig_label(IOS_XE_CHECKLIST) in name, name)
    check('no time of day anywhere in it',
          not re.search(r'\d{2}[:_-]\d{2}[:_-]\d{2}', name), name)

    check('a device label that would escape its directory cannot',
          '/' not in stig_common.checklist_filename(IOS_XE_CHECKLIST, '../etc/SW01', on)
          and '\\' not in stig_common.checklist_filename(IOS_XE_CHECKLIST, r'..\SW01', on),
          stig_common.checklist_filename(IOS_XE_CHECKLIST, '../etc/SW01', on))

    # A checklist that names nothing readable still gets a usable name rather
    # than one with a hole in it.
    check('an unreadable checklist costs the versions, not the file',
          stig_common.checklist_filename('/nonexistent.cklb', 'SW01', on)
          == 'SW01_06AUG2026.cklb',
          stig_common.checklist_filename('/nonexistent.cklb', 'SW01', on))


def test_resolve_path(tmpdir):
    print('\n--to-cklb takes a file or a directory, and says which by the extension')
    on = datetime.date(2026, 8, 6)
    explicit = os.path.join(tmpdir, 'chosen.cklb')
    check('a path with an extension is used exactly as given',
          stig_common.resolve_cklb_path(explicit, IOS_XE_CHECKLIST, 'SW01', on) == explicit)

    into = stig_common.resolve_cklb_path(tmpdir, IOS_XE_CHECKLIST, 'SW01', on)
    check('an existing directory gets the derived name inside it',
          os.path.dirname(into) == tmpdir and os.path.basename(into).startswith('SW01_06AUG2026'),
          into)

    missing = os.path.join(tmpdir, 'not-created-yet')
    check('a directory that does not exist yet is still a directory',
          os.path.dirname(stig_common.resolve_cklb_path(
              missing, IOS_XE_CHECKLIST, 'SW01', on)) == missing)

    # `--from-capture` takes any label, so the switch's own name is what the
    # file should carry - a file named after a label is the thing this prevents.
    named = stig_common.resolve_cklb_path(tmpdir, IOS_XE_CHECKLIST, 'whatever-label', on,
                                          target_data={'host_name': 'TESTSW01'})
    check("the switch's own hostname names the file, not the label on the command line",
          os.path.basename(named).startswith('TESTSW01_'), named)


def test_end_to_end(tmpdir):
    print('\nthe audit fills the block and names the file, from a capture')
    capture_path = capture.write(os.path.join(tmpdir, 'sw.capture'), fixtures.OUTPUTS)
    out = os.path.join(tmpdir, 'exports')
    result = subprocess.run(
        [sys.executable, os.path.join(PROJECT, 'l2_stig_audit.py'), 'any-old-label',
         '--from-capture', capture_path, '--non-user-vlans', '1,10,999,1000',
         '--to-cklb', out],
        capture_output=True, text=True, cwd=PROJECT, timeout=120)
    check('the audit exits cleanly', result.returncode == 0, result.stderr[-500:])

    written = os.listdir(out) if os.path.isdir(out) else []
    check('one checklist written', len(written) == 1, written)
    if not written:
        return
    # The capture was written seconds ago, so its date is today's.
    stamp = datetime.date.today().strftime('%d%b%Y').upper()
    check('named for the switch and the day the capture was taken',
          written[0].startswith(f'TESTSW01_{stamp}_'), written[0])

    with open(os.path.join(out, written[0]), encoding='utf-8') as checklist_file:
        target = json.load(checklist_file)['target_data']
    check('host name', target['host_name'] == 'TESTSW01', target['host_name'])
    check('IP address', target['ip_address'] == '192.0.2.5', target['ip_address'])
    check('MAC address', target['mac_address'] == '00:1A:2B:3C:4D:5E', target['mac_address'])
    check('FQDN', target['fqdn'] == 'TESTSW01.example.test', target['fqdn'])
    check('and the comment carries a date with no time on it',
          re.search(r'\d{4}-\d{2}-\d{2}\.$', target['comments']), target['comments'])

    # The report says what it put in each field. A field STIG Viewer shows as
    # blank looks the same whether nothing was found or nothing was looked for.
    check('the report states the asset fields it filled',
          'Checklist asset fields:' in result.stdout and '192.0.2.5' in result.stdout,
          [l for l in result.stdout.splitlines() if 'asset' in l.lower()])


def test_older_capture(tmpdir):
    print('\na capture taken before the address command existed still audits')
    without = {k: v for k, v in fixtures.OUTPUTS.items() if k != 'show ip interface brief'}
    capture_path = capture.write(os.path.join(tmpdir, 'older.capture'), without)
    out = os.path.join(tmpdir, 'older-exports')
    result = subprocess.run(
        [sys.executable, os.path.join(PROJECT, 'l2_stig_audit.py'), 'TESTSW01',
         '--from-capture', capture_path, '--non-user-vlans', '1,10,999,1000',
         '--to-cklb', out],
        capture_output=True, text=True, cwd=PROJECT, timeout=120)
    check('it is audited rather than refused', result.returncode == 0,
          (result.stdout + result.stderr)[-400:])
    check('and the report says why the address field is empty',
          'IP address' in result.stdout,
          [l for l in result.stdout.splitlines() if 'IP address' in l])

    written = os.listdir(out) if os.path.isdir(out) else []
    if written:
        with open(os.path.join(out, written[0]), encoding='utf-8') as checklist_file:
            target = json.load(checklist_file)['target_data']
        # The fields that do not depend on the missing command are still filled.
        check('the fields that do not need it are still filled',
              target['mac_address'] == '00:1A:2B:3C:4D:5E'
              and target['fqdn'] == 'TESTSW01.example.test', target)


if __name__ == '__main__':
    test_reads_each_field()
    test_management_ip()
    test_filename()
    with tempfile.TemporaryDirectory() as tmpdir:
        test_resolve_path(tmpdir)
        test_end_to_end(tmpdir)
        test_older_capture(tmpdir)
    print('\n' + ('ALL CHECKS PASSED' if not failures
                  else f'{len(failures)} FAILED: {", ".join(failures)}'))
