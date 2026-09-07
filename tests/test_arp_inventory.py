#!/usr/bin/env python
"""arp_inventory.py: the ARP table as a list someone can work from.

Run directly: `python3 tests/test_arp_inventory.py`. No framework, no device.

The parsing is the whole tool, and the cases that decide whether its output is
trustworthy are the ones that are not a plain host entry: the router's own
address on the subinterface (age `-`), an incomplete entry (an ARP request
nothing answered, which prints no hardware address and no interface), and the
short interface names IOS accepts but never prints.

Sorting is asserted too, because the reason to produce this file is to read it:
.5 belongs before .11, and string order puts .11 first.
"""

import csv
import io
import os
import subprocess
import sys
import tempfile

PROJECT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(PROJECT, 'scripts'))

import arp_inventory

failures = []


def check(name, condition, detail=''):
    print(f'  {"ok  " if condition else "FAIL"} {name}')
    if not condition:
        if detail:
            print(f'       {detail}')
        failures.append(name)


# RFC 5737 documentation addressing; MACs invented.
ARP_OUTPUT = """Protocol  Address          Age (min)  Hardware Addr   Type   Interface
Internet  192.0.2.1               -   aabb.cc00.0100  ARPA   GigabitEthernet0/0.100
Internet  192.0.2.11             12   0011.2233.4455  ARPA   GigabitEthernet0/0.100
Internet  192.0.2.5             237   0011.2233.99aa  ARPA   GigabitEthernet0/0.100
Internet  192.0.2.77              0   Incomplete      ARPA
Internet  198.51.100.7           44   0011.2233.bbcc  ARPA   GigabitEthernet0/0.200
"""


def test_parses_every_kind_of_entry():
    print('every row a real ARP table has')
    rows, skipped = arp_inventory.parse_arp(ARP_OUTPUT, device='R1')
    by_ip = {row['ip_address']: row for row in rows}
    check('all five entries are read', len(rows) == 5, rows)
    check("the router's own address is marked as its own",
          by_ip['192.0.2.1']['type'] == 'router interface', by_ip.get('192.0.2.1'))
    check('and carries no age, because it never expires',
          by_ip['192.0.2.1']['age_minutes'] == '', by_ip.get('192.0.2.1'))
    check('a host is a host, with its age', by_ip['192.0.2.11']['type'] == 'host'
          and by_ip['192.0.2.11']['age_minutes'] == '12', by_ip.get('192.0.2.11'))
    check('an unanswered request is kept and marked incomplete',
          by_ip['192.0.2.77']['type'] == 'incomplete', by_ip.get('192.0.2.77'))
    check('with no MAC, because there is none', by_ip['192.0.2.77']['mac_address'] == '',
          by_ip.get('192.0.2.77'))
    check('nothing was skipped when nothing was filtered', skipped == 0)


def test_sorted_as_addresses():
    print('\nsorted the way addresses sort, not the way strings do')
    rows, _skipped = arp_inventory.parse_arp(ARP_OUTPUT, device='R1')
    order = [row['ip_address'] for row in rows]
    check('.5 comes before .11', order.index('192.0.2.5') < order.index('192.0.2.11'), order)
    check('and 192.0.2.x before 198.51.100.x',
          order.index('192.0.2.77') < order.index('198.51.100.7'), order)


def test_interface_filter():
    print('\nfiltering by a name typed the way it is typed at a terminal')
    for typed in ('GigabitEthernet0/0.100', 'Gi0/0.100', 'gi0/0.100'):
        rows, _skipped = arp_inventory.parse_arp(ARP_OUTPUT, device='R1', interface=typed)
        check(f"'{typed}' selects the same three entries", len(rows) == 3,
              [row['ip_address'] for row in rows])
    rows, _skipped = arp_inventory.parse_arp(ARP_OUTPUT, device='R1', interface='Gi0/0.200')
    check('another subinterface selects its own',
          [row['ip_address'] for row in rows] == ['198.51.100.7'], rows)


def test_incomplete_entries_and_the_filter():
    print('\nan incomplete entry names no interface, so who it belongs to depends on the source')
    pasted, skipped = arp_inventory.parse_arp(ARP_OUTPUT, device='R1', interface='Gi0/0.100')
    check('a pasted whole table does not attribute it to the filtered interface',
          '192.0.2.77' not in [row['ip_address'] for row in pasted], pasted)
    check('and says one entry was left out rather than dropping it quietly', skipped == 1)

    filtered, skipped = arp_inventory.parse_arp(
        ARP_OUTPUT, device='R1', interface='Gi0/0.100', include_unattributed=True)
    check('output the router itself filtered keeps it',
          '192.0.2.77' in [row['ip_address'] for row in filtered], filtered)
    check('under the interface that was asked for',
          all(row['interface'] == 'Gi0/0.100' or row['interface'].startswith('Gigabit')
              for row in filtered), filtered)
    check('and skips nothing', skipped == 0)


def test_command_built():
    print('\nthe command it would send')
    check('plain', arp_inventory.arp_command() == 'show ip arp')
    check('with an interface',
          arp_inventory.arp_command('Gi0/0.100') == 'show ip arp Gi0/0.100')
    check('with a VRF, which goes before the interface',
          arp_inventory.arp_command('Gi0/0.100', 'MGMT') == 'show ip arp vrf MGMT Gi0/0.100')


def run_cli(tmpdir, *args):
    return subprocess.run([sys.executable, os.path.join(PROJECT, 'scripts', 'arp_inventory.py'), *args],
                          capture_output=True, text=True, cwd=PROJECT, timeout=60)


def test_cli_from_file(tmpdir):
    print('\n--from-file: no device, no credentials, same parsing')
    source = os.path.join(tmpdir, 'arp.txt')
    with open(source, 'w', encoding='utf-8') as arp_file:
        arp_file.write(ARP_OUTPUT)
    out = os.path.join(tmpdir, 'vlan100.csv')
    result = run_cli(tmpdir, 'R1', '--from-file', source, '--interface', 'Gi0/0.100', '-o', out)
    check('it runs without an inventory entry', result.returncode == 0,
          result.stdout + result.stderr)
    check('and never prompts for credentials', 'assword' not in result.stdout, result.stdout)
    rows = list(csv.DictReader(io.open(out, encoding='utf-8', newline='')))
    check('the CSV has the filtered entries', len(rows) == 3, rows)
    check('with the device named', all(row['device'] == 'R1' for row in rows), rows)
    check('the summary goes to stderr, so stdout can be piped as CSV',
          'ARP entries' in result.stderr, result.stderr)

    piped = run_cli(tmpdir, 'R1', '--from-file', source)
    check('and with no -o the CSV is stdout', piped.stdout.startswith('device,interface,'),
          piped.stdout[:80])


def test_cli_empty_is_explained(tmpdir):
    print('\nan empty result is a real answer and a common typo, so it says both')
    source = os.path.join(tmpdir, 'arp.txt')
    result = run_cli(tmpdir, 'R1', '--from-file', source, '--interface', 'Gi9/9.999')
    check('it still exits cleanly', result.returncode == 0, result.stderr)
    check('and explains the two ways to get here', 'does not match' in result.stderr,
          result.stderr)
    check('naming the way to find the right name', 'without --interface' in result.stderr,
          result.stderr)


if __name__ == '__main__':
    with tempfile.TemporaryDirectory() as tmp:
        test_parses_every_kind_of_entry()
        test_sorted_as_addresses()
        test_interface_filter()
        test_incomplete_entries_and_the_filter()
        test_command_built()
        test_cli_from_file(tmp)
        test_cli_empty_is_explained(tmp)
    print('\n' + ('ALL CHECKS PASSED' if not failures
                  else f'{len(failures)} FAILED: {", ".join(failures)}'))
    sys.exit(1 if failures else 0)
