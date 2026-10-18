#!/usr/bin/env python
"""Verification for scripts/compare_inventory_ips.py.

Run directly: `python3 tests/test_compare_inventory_ips.py`. No framework.

The one mistake that matters here is a false "missing": an address reported
gone that is in the new file, written slightly differently. So the checks
lean on the ways the same address arrives looking different - whitespace, a
leading zero, an Excel byte-order mark, a stack's repeated rows.
"""

import io
import os
import shutil
import sys
import tempfile
from contextlib import redirect_stdout

PROJECT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(PROJECT, 'scripts'))

import compare_inventory_ips as cmp

failures = []


def check(name, condition, detail=''):
    print(f'  {"ok  " if condition else "FAIL"} {name}')
    if not condition:
        if detail:
            print(f'       {detail}')
        failures.append(name)


HEADER = 'hostname,ip_address,switch_number,role,model,serial_number,ios_version,session,timestamp\n'

OLD = HEADER + (
    'SW1,192.0.2.1,1,Active,C9300-48P,FOC1,17.12.4,site/sw1,2026-09-01 10:00:00\n'
    'SW1,192.0.2.1,2,Standby,C9300-48P,FOC2,17.12.4,site/sw1,2026-09-01 10:00:00\n'
    'SW2,192.0.2.2,1,Active,C9300-24T,FOC3,17.12.4,site/sw2,2026-09-01 10:00:00\n'
    'SW10,192.0.2.10,1,Active,WS-C3850-48P,FOC4,16.12.9,site/sw10,2026-09-01 10:00:00\n'
    'SW3,192.0.2.3,1,Active,C9300-48P,FOC5,17.12.4,site/sw3,2026-09-01 10:00:00\n'
    'site/sw9,192.0.2.9,,,,,,site/sw9,2026-09-01 10:00:00\n'
)
# SW1 lost its second member (not missing), SW2's address has a stray space,
# SW3's a leading zero; SW10 and the unreachable sw9 are gone; SW4 is new.
NEW = '﻿' + HEADER + (
    'SW1,192.0.2.1,1,Active,C9300-48P,FOC1,17.12.4,site/sw1,2026-10-01 10:00:00\n'
    'SW2, 192.0.2.2 ,1,Active,C9300-24T,FOC3,17.12.4,site/sw2,2026-10-01 10:00:00\n'
    'SW3,192.0.2.003,1,Active,C9300-48P,FOC5,17.12.4,site/sw3,2026-10-01 10:00:00\n'
    'SW4,192.0.2.4,1,Active,C9300-48P,FOC6,17.12.4,site/sw4,2026-10-01 10:00:00\n'
)


def write(directory, name, text):
    path = os.path.join(directory, name)
    with open(path, 'w', encoding='utf-8', newline='') as handle:
        handle.write(text)
    return path


def run(argv):
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        code = cmp.main(argv)
    return code, buffer.getvalue()


def main():
    tmp = tempfile.mkdtemp()
    try:
        old = write(tmp, 'inventory_old.csv', OLD)
        new = write(tmp, 'inventory_new.csv', NEW)

        print('an inventory_l2s.py CSV against a newer one')
        missing, added, *_rest = cmp.compare(old, new)
        check('exactly the two gone addresses are missing, in numeric order',
              missing == ['192.0.2.9', '192.0.2.10'], missing)
        check('the new switch is reported as new', added == ['192.0.2.4'], added)
        check('a stack member dropping is not a missing address', '192.0.2.1' not in missing)
        check('whitespace around an address is not a different address',
              '192.0.2.2' not in missing)
        check('a leading zero is not a different address', '192.0.2.3' not in missing)

        code, out = run([old, new])
        check('exit 0', code == 0, out)
        check('the missing line carries the old hostname and model',
              'SW10' in out and 'WS-C3850-48P' in out, out)
        check('the counts are stated', 'MISSING from the new file: 2' in out, out)
        check('the address column was used, not every cell', 'column "ip_address"' in out, out)

        print('\n--out writes the missing rows')
        out_path = os.path.join(tmp, 'missing.csv')
        run([old, new, '--out', out_path])
        with open(out_path, encoding='utf-8') as handle:
            lines = handle.read().splitlines()
        check('a header and two rows', len(lines) == 3, lines)
        check('the header leads with missing_ip', lines and lines[0].startswith('missing_ip,hostname'),
              lines[:1])

        print('\na CSV with no address column falls back to every cell')
        loose_old = write(tmp, 'a.csv', 'name,notes\nSW1,mgmt 192.0.2.1 / oob 198.51.100.1\n'
                                        'SW2,192.0.2.2\n')
        loose_new = write(tmp, 'b.csv', 'name,notes\nSW1,192.0.2.1\n')
        missing, *_rest = cmp.compare(loose_old, loose_new)
        check('both addresses on the shared row and the second row are found',
              missing == ['192.0.2.2', '198.51.100.1'], missing)
        check('a version string is not an address',
              cmp.IPV4_RE.findall('17.12.4.1.5') == [], cmp.IPV4_RE.findall('17.12.4.1.5'))

        print('\n--column picks the column')
        named_old = write(tmp, 'c.csv', 'Device,Mgmt IP\nSW1,192.0.2.1\nSW2,192.0.2.2\n')
        named_new = write(tmp, 'd.csv', 'Device,Mgmt IP\nSW1,192.0.2.1\n')
        missing, *_rest = cmp.compare(named_old, named_new, 'mgmt ip')
        check('matched case-insensitively', missing == ['192.0.2.2'], missing)
        try:
            cmp.compare(named_old, named_new, 'nope')
            check('an unknown column is refused', False)
        except SystemExit as stop:
            check('an unknown column is refused, naming the real ones', 'Mgmt IP' in str(stop),
                  str(stop))

        print('\nnot an address')
        for text in ('256.1.1.1', '10.1.1', 'x.x.x.x', '', None):
            check(f'{text!r} is not an address', cmp.as_address(text) is None)
    finally:
        shutil.rmtree(tmp)

    print()
    if failures:
        print(f'{len(failures)} FAILED: ' + ', '.join(failures))
        sys.exit(1)
    print('all checks passed')


if __name__ == '__main__':
    main()
