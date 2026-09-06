#!/usr/bin/env python
"""Turn a router's ARP table into a CSV of what is actually on a subinterface.

The question this answers is "which addresses are live on VLAN 100", and the
place a router knows it is the ARP table: `show ip arp GigabitEthernet0/0.100`
lists every host that has spoken recently, whether or not anything documents
it. That is one command, and then a slow retype into a spreadsheet - which is
where the addresses get transposed, and where the entry that mattered gets
dropped.

Reads a live device from inventory.yaml, or a pasted `show ip arp` from a file
so the same parsing serves a switch nothing here can reach. Read-only either
way: the only command sent is a show.

An ARP table is a snapshot of who has spoken, not an inventory of what exists.
A host that has been quiet longer than the ARP timeout (four hours by default
on IOS) is simply absent, and a stale entry can outlive the host that made it.
The CSV carries the age column for exactly that reason - a row is evidence
that an address answered, that long ago, and nothing more.

Usage:
    python3 arp_inventory.py R1 --interface GigabitEthernet0/0.100
    python3 arp_inventory.py R1 --interface Gi0/0.100 -o vlan100.csv
    python3 arp_inventory.py R1 --from-file pasted-arp.txt --interface Gi0/0.100
"""

import argparse
import csv
import ipaddress
import os
import re
import sys

import netauto

# `show ip arp` on IOS and IOS XE:
#
#   Protocol  Address       Age (min)  Hardware Addr   Type   Interface
#   Internet  10.1.1.1              -   aabb.cc00.0100  ARPA   GigabitEthernet0/0.100
#   Internet  10.1.1.5             12   0011.2233.4455  ARPA   GigabitEthernet0/0.100
#   Internet  10.1.1.9              0   Incomplete      ARPA
#
# Age is '-' for the router's own addresses, a number of minutes otherwise, and
# an incomplete entry has no hardware address and no interface at all: an ARP
# request that went unanswered. Those are kept rather than dropped, because
# "this address was asked for and did not answer" is a different fact from
# "this address was never mentioned", and the difference matters when the table
# is being read to find out what is on a segment.
ARP_LINE = re.compile(
    r'^\s*(?P<protocol>Internet)\s+'
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+'
    r'(?P<age>[-\d]+)\s+'
    r'(?P<mac>[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}|Incomplete)\s*'
    r'(?P<type>ARPA|SNAP|SAP)?\s*'
    r'(?P<interface>\S+)?\s*$')

FIELDS = ('device', 'interface', 'ip_address', 'mac_address', 'age_minutes', 'type', 'vrf')


def _short_name(interface):
    """`Gi0/0.100` and `GigabitEthernet0/0.100` are the same interface. IOS
    accepts the short form on the command line and prints the long one, so a
    filter typed the way it is typed at a terminal has to match the way the
    table spells it."""
    if not interface:
        return ''
    match = re.match(r'^([A-Za-z\-]+)(.*)$', interface.strip())
    if not match:
        return interface.strip().lower()
    return match.group(1)[:2].lower() + match.group(2)


def parse_arp(output, device='', interface=None, vrf='', include_unattributed=False):
    """Rows for every ARP entry in `output`, optionally only those on
    `interface`. Returns (rows, skipped), where skipped counts entries dropped
    by the interface filter for naming no interface at all.

    An incomplete entry - an ARP request nothing answered - prints no interface
    column, so filtering by interface drops it. That is right for a pasted
    whole-table output, where nothing says which segment the request went out
    of, and wrong for output the router itself already filtered with
    `show ip arp <interface>`, where every line is that interface's by
    construction. `include_unattributed` is how the caller says which of the
    two it has."""
    wanted = _short_name(interface) if interface else None
    rows, skipped = [], 0
    for line in output.splitlines():
        match = ARP_LINE.match(line)
        if not match:
            continue
        entry_interface = match.group('interface') or ''
        if wanted and _short_name(entry_interface) != wanted:
            if not entry_interface and include_unattributed:
                entry_interface = interface
            else:
                skipped += 1 if not entry_interface else 0
                continue
        rows.append({
            'device': device,
            'interface': entry_interface,
            'ip_address': match.group('ip'),
            'mac_address': '' if match.group('mac') == 'Incomplete' else match.group('mac'),
            'age_minutes': '' if match.group('age') == '-' else match.group('age'),
            # A dash in the age column is IOS's way of saying "this one is
            # mine": the router's own interface address, which is not a host on
            # the segment and is worth being able to tell apart in the CSV.
            'type': 'router interface' if match.group('age') == '-' else (
                'incomplete' if match.group('mac') == 'Incomplete' else 'host'),
            'vrf': vrf,
        })

    def sort_key(row):
        try:
            return (0, ipaddress.ip_address(row['ip_address']))
        except ValueError:
            return (1, row['ip_address'])

    return sorted(rows, key=sort_key), skipped


def arp_command(interface=None, vrf=''):
    command = 'show ip arp'
    if vrf:
        command += f' vrf {vrf}'
    if interface:
        command += f' {interface}'
    return command


def write_csv(rows, output_path=None):
    """Write rows as CSV to `output_path`, or to stdout when there is none.

    newline='' is required of csv on Windows; without it every row is followed
    by a blank one, which Excel shows and a diff does not."""
    if output_path:
        parent = os.path.dirname(os.path.abspath(output_path))
        if parent:
            os.makedirs(parent, exist_ok=True)
        handle = open(output_path, 'w', newline='', encoding='utf-8')
    else:
        handle = sys.stdout
    try:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    finally:
        if output_path:
            handle.close()
    return output_path


def main(argv=None):
    parser = argparse.ArgumentParser(
        description='Collect the addresses on a router subinterface from its ARP table.')
    parser.add_argument('device', help='Device name as it appears in inventory.yaml (e.g. R1) - '
                                       'with --from-file, any label to record in the CSV.')
    parser.add_argument('--interface', metavar='NAME',
                        help='Subinterface to ask about, long or short form '
                             '(GigabitEthernet0/0.100 or Gi0/0.100). Omit for the whole table.')
    parser.add_argument('--vrf', default='', metavar='NAME',
                        help='Read the ARP table of a VRF rather than the global one.')
    parser.add_argument('--from-file', metavar='PATH', dest='from_file',
                        help='Parse `show ip arp` output saved to a file instead of connecting. '
                             'No inventory entry and no credentials are needed.')
    parser.add_argument('-o', '--output', metavar='PATH',
                        help='Write the CSV here. Default: stdout, so it can be piped.')
    args = parser.parse_args(argv)

    if args.from_file:
        if not os.path.exists(args.from_file):
            print(f'No such file: {args.from_file}', file=sys.stderr)
            return 2
        with open(args.from_file, encoding='utf-8', errors='replace') as arp_file:
            output = arp_file.read()
        source = args.from_file
    else:
        all_devices = netauto.load_inventory()
        device_info = netauto.require_devices(all_devices, [args.device])[args.device]
        username, password = netauto.get_credentials()
        connection = netauto.connect(args.device, device_info, username, password)
        if connection is None:
            return 1
        command = arp_command(args.interface, args.vrf)
        output = str(connection.send_command(command))
        connection.disconnect()
        source = f'{args.device} ({command})'

    # Output the router filtered for us carries only the asked-for interface,
    # so an entry with no interface column is still that interface's. A pasted
    # file could be either, and guessing wrong would attribute a host to the
    # wrong segment - the one error in a list of addresses that is worse than a
    # missing row.
    rows, skipped = parse_arp(output, device=args.device, interface=args.interface,
                              vrf=args.vrf,
                              include_unattributed=bool(args.interface and not args.from_file))
    if skipped:
        print(f'{skipped} incomplete ARP entr(ies) named no interface and were left out of the '
              f'filter for {args.interface}.\nRe-run without --interface to see them.',
              file=sys.stderr)
    if not rows:
        # Empty is a real answer - a subinterface nothing has spoken on - but
        # it is also what a misspelled interface name looks like, and the two
        # are worth telling apart before someone reports an empty VLAN.
        print(f'No ARP entries found in {source}'
              + (f' for {args.interface}' if args.interface else '')
              + '.\nAn interface with no traffic answers this way, and so does an interface '
                'name that does not match\nwhat the table calls it - run the command without '
                '--interface to see the names it uses.', file=sys.stderr)

    write_csv(rows, args.output)
    hosts = sum(1 for row in rows if row['type'] == 'host')
    print(f'{len(rows)} ARP entries ({hosts} host(s)) from {source}'
          + (f' -> {args.output}' if args.output else ''), file=sys.stderr)
    return 0


if __name__ == '__main__':
    sys.exit(main())
