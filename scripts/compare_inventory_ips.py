#!/usr/bin/env python
"""Which IP addresses an older inventory CSV has that a newer one does not.

    python3 scripts/compare_inventory_ips.py <old.csv> <new.csv>

Prints the addresses in the old file and missing from the new one, each with
whatever the old file said about it (hostname, model - the columns it has), so
the list can be chased without opening the old file. Then, shorter, the
addresses that are new. --out writes the missing ones to a CSV as well.

Made for securecrt/inventory_l2s.py's inventory_<stamp>.csv, or a merged one
from merge_walk_csvs.py, but it reads any CSV. The address comes from:

  --column NAME, if given;
  else a column named ip_address, ip, ip address, ipaddress, host, hostname
  or address - the first one whose values actually are addresses, since a
  `hostname` column usually holds names;
  else every IPv4 address found in any cell of the row.

A stack is one row per member and one address, so addresses are compared, not
rows: a stack that lost a member is not an address gone missing.

Standard library only.
"""

import argparse
import csv
import ipaddress
import os
import re
import sys

ADDRESS_COLUMNS = ('ip_address', 'ip', 'ip address', 'ipaddress', 'host', 'hostname', 'address')

# Columns worth repeating beside a missing address, in this order, where the
# file has them. Anything else is left in the old file.
DESCRIBE_COLUMNS = ('hostname', 'model', 'role', 'serial_number', 'ios_version', 'session',
                    'outcome', 'comment', 'timestamp')

IPV4_RE = re.compile(r'(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])')


def as_address(text):
    """The canonical form of an IPv4 address, or None. Canonical so that
    ' 10.1.2.3 ' and '10.1.2.3' are one address - and a leading-zero
    '10.01.2.3', which the ipaddress module refuses, is not silently dropped."""
    text = str(text or '').strip()
    if not re.fullmatch(r'\d{1,3}(?:\.\d{1,3}){3}', text):
        return None
    parts = [int(part) for part in text.split('.')]
    if any(part > 255 for part in parts):
        return None
    return '.'.join(str(part) for part in parts)


def read_csv(path):
    """(header, rows). utf-8-sig so a file saved from Excel, which starts with
    a byte-order mark, still has `ip_address` as its first column name."""
    try:
        with open(path, encoding='utf-8-sig', newline='') as handle:
            reader = csv.DictReader(handle)
            rows = list(reader)
            return list(reader.fieldnames or []), rows
    except OSError as error:
        raise SystemExit('Could not read {0}: {1}'.format(path, error))


def pick_column(header, rows, wanted=None):
    """The column the addresses are in, or None to scan every cell."""
    if wanted:
        for name in header:
            if name.strip().lower() == wanted.strip().lower():
                return name
        raise SystemExit('No column named "{0}". The columns are: {1}'
                         .format(wanted, ', '.join(header)))
    by_name = {name.strip().lower(): name for name in header}
    for candidate in ADDRESS_COLUMNS:
        name = by_name.get(candidate)
        if name and any(as_address(row.get(name)) for row in rows):
            return name
    return None


def addresses(header, rows, column):
    """{address: first row it appeared on}."""
    found = {}
    for row in rows:
        if column:
            cells = [row.get(column)]
        else:
            cells = [found_ip for value in row.values() if isinstance(value, str)
                     for found_ip in IPV4_RE.findall(value)]
        for cell in cells:
            address = as_address(cell)
            if address and address not in found:
                found[address] = row
    return found


def sort_key(address):
    return ipaddress.IPv4Address(address)


def describe(row, header, column):
    parts = []
    for name in DESCRIBE_COLUMNS:
        for real in header:
            if real.strip().lower() == name and real != column and str(row.get(real) or '').strip():
                parts.append('{0}={1}'.format(name, row[real].strip()))
    return ', '.join(parts)


def compare(old_path, new_path, column=None):
    """(missing, added, old_header, old_rows_by_address, old_column, new_column,
    old_count, new_count)."""
    old_header, old_rows = read_csv(old_path)
    new_header, new_rows = read_csv(new_path)
    old_column = pick_column(old_header, old_rows, column)
    new_column = pick_column(new_header, new_rows, column)
    old = addresses(old_header, old_rows, old_column)
    new = addresses(new_header, new_rows, new_column)
    missing = sorted(set(old) - set(new), key=sort_key)
    added = sorted(set(new) - set(old), key=sort_key)
    return missing, added, old_header, old, old_column, new_column, len(old), len(new)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description='List the IP addresses in an older inventory CSV that a newer one is missing.')
    parser.add_argument('old', help='The older CSV')
    parser.add_argument('new', help='The newer CSV')
    parser.add_argument('--column', metavar='NAME',
                        help='Column holding the address in both files. Default: ip_address or '
                             'another address-named column, else any address in any cell.')
    parser.add_argument('--out', metavar='PATH',
                        help='Also write the missing addresses, with their old rows, to this CSV.')
    args = parser.parse_args(argv)

    missing, added, old_header, old, old_column, new_column, old_count, new_count = compare(
        args.old, args.new, args.column)

    def source(column):
        return 'column "{0}"'.format(column) if column else 'every cell (no address column found)'

    print('Old: {0} - {1} address(es), from {2}'.format(args.old, old_count, source(old_column)))
    print('New: {0} - {1} address(es), from {2}'.format(args.new, new_count, source(new_column)))
    if not old_count:
        print('\nThe old file has no IPv4 addresses in it - check it is the right file, or pass '
              '--column.')
        return 1

    print('\nMISSING from the new file: {0}'.format(len(missing)))
    for address in missing:
        detail = describe(old[address], old_header, old_column)
        print('  {0:<15}  {1}'.format(address, detail) if detail else '  ' + address)

    print('\nNew in the new file: {0}'.format(len(added)))
    for address in added:
        print('  ' + address)

    if args.out:
        columns = ['missing_ip'] + old_header
        try:
            with open(args.out, 'w', encoding='utf-8', newline='') as handle:
                writer = csv.writer(handle)
                writer.writerow(columns)
                for address in missing:
                    writer.writerow([address] + [old[address].get(name, '') for name in old_header])
        except OSError as error:
            print('\nCould not write {0}: {1}'.format(args.out, error), file=sys.stderr)
            return 1
        print('\nMissing addresses written to {0}'.format(os.path.abspath(args.out)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
