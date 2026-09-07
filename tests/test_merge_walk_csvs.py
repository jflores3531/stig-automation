#!/usr/bin/env python
"""Verification for scripts/merge_walk_csvs.py.

Run directly: `python3 tests/test_merge_walk_csvs.py`. No framework, no
SecureCRT.

Scoping the SecureCRT walkers by distribution node turns one CSV into one per
node, so what matters here is that merging them back gives the fleet-wide
view a spreadsheet actually wants: every switch once, on its newest data, and
a stack's members never collapsed into each other. Refusing to merge two
different kinds of file (inventory vs. run log) matters just as much as the
merge itself - a file that looks complete under the wrong columns is worse
than no merge at all.
"""

import csv
import io
import os
import sys
import tempfile

PROJECT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(PROJECT, 'scripts'))

import merge_walk_csvs as merge_tool

failures = []


def check(name, condition, detail=''):
    print(f'  {"ok  " if condition else "FAIL"} {name}')
    if not condition:
        if detail:
            print(f'       {detail}')
        failures.append(name)


INVENTORY_COLUMNS = ('hostname', 'ip_address', 'switch_number', 'role', 'model',
                     'serial_number', 'ios_version', 'comment', 'session', 'timestamp')
RUN_LOG_COLUMNS = ('hostname', 'ip_address', 'model', 'comment', 'outcome', 'session',
                  'timestamp')


def write_csv(path, columns, rows):
    with open(path, 'w', encoding='utf-8', newline='') as handle:
        writer = csv.writer(handle, quoting=csv.QUOTE_ALL)
        writer.writerow(columns)
        writer.writerows(rows)


def read_csv(path):
    with io.open(path, encoding='utf-8') as handle:
        rows = list(csv.reader(handle))
    return rows[0], rows[1:]


def test_merges_disjoint_files(tmpdir):
    print('\ntwo runs with no overlap merge into one file')
    write_csv(os.path.join(tmpdir, 'inventory_20260101_100000.csv'), INVENTORY_COLUMNS,
              [('SW01', '10.0.0.1', '', '', 'C9300', 'FOC1', '17.12.4', '', 'node-a\\sw-1',
                '2026-01-01 10:00:00')])
    write_csv(os.path.join(tmpdir, 'inventory_20260101_110000.csv'), INVENTORY_COLUMNS,
              [('SW02', '10.0.0.2', '', '', 'C9300', 'FOC2', '17.12.4', '', 'node-b\\sw-1',
                '2026-01-01 11:00:00')])
    code = merge_tool.main([tmpdir])
    check('exits cleanly', code == 0, code)
    merged = [name for name in os.listdir(tmpdir) if name.startswith('merged_')]
    check('exactly one merged file written', len(merged) == 1, os.listdir(tmpdir))
    if not merged:
        return
    columns, rows = read_csv(os.path.join(tmpdir, merged[0]))
    check('the header is preserved', tuple(columns) == INVENTORY_COLUMNS, columns)
    check('both rows are present', len(rows) == 2, rows)


def test_dedupes_to_the_newest_row_per_switch(tmpdir):
    """A node re-run because its first pass missed some switches should not
    leave the switch's earlier, blank row sitting beside its real one."""
    print('\na switch collected twice keeps only its newest row')
    write_csv(os.path.join(tmpdir, 'run_log_20260101_100000.csv'), RUN_LOG_COLUMNS,
              [('node-a\\sw-1', '10.0.1.1', '', 'Connection timed out', 'unreachable',
                'node-a\\sw-1', '2026-01-01 10:00:00')])
    write_csv(os.path.join(tmpdir, 'run_log_20260101_120000.csv'), RUN_LOG_COLUMNS,
              [('SW01', '10.0.1.1', 'C9300-48P', '', 'checklisted', 'node-a\\sw-1',
                '2026-01-01 12:00:00')])
    code = merge_tool.main([tmpdir])
    check('exits cleanly', code == 0, code)
    merged = [name for name in os.listdir(tmpdir) if name.startswith('merged_')]
    if not merged:
        check('a merged file was written', False)
        return
    _columns, rows = read_csv(os.path.join(tmpdir, merged[0]))
    check('one row for the one switch, not two', len(rows) == 1, rows)
    if rows:
        check('the newer, successful row is the one that survives',
              rows[0][4] == 'checklisted' and rows[0][0] == 'SW01', rows[0])


def test_stack_members_are_not_collapsed(tmpdir):
    """switch_number joins session in the dedupe key, so a rerun of a stack
    keeps one row per chassis rather than folding three members into one."""
    print("\na stack's members stay separate across a rerun")
    first_pass = [
        ('STACK1', '10.0.2.1', '1', 'Active', 'C9300-48P', 'FOC1', '17.12.4', '',
         'node-c\\stack', '2026-01-01 09:00:00'),
        ('STACK1', '10.0.2.1', '2', 'Standby', 'C9300-24P', 'FOC2', '17.12.4', '',
         'node-c\\stack', '2026-01-01 09:00:00'),
    ]
    write_csv(os.path.join(tmpdir, 'inventory_20260101_090000.csv'), INVENTORY_COLUMNS,
              first_pass)
    rerun = [
        ('STACK1', '10.0.2.1', '1', 'Active', 'C9300-48P', 'FOC1', '17.12.5', '',
         'node-c\\stack', '2026-01-02 09:00:00'),
        ('STACK1', '10.0.2.1', '2', 'Standby', 'C9300-24P', 'FOC2', '17.12.5', '',
         'node-c\\stack', '2026-01-02 09:00:00'),
        ('STACK1', '10.0.2.1', '3', 'Member', 'C9300-24P', 'FOC3', '17.12.5', '',
         'node-c\\stack', '2026-01-02 09:00:00'),
    ]
    write_csv(os.path.join(tmpdir, 'inventory_20260102_090000.csv'), INVENTORY_COLUMNS, rerun)
    code = merge_tool.main([tmpdir])
    check('exits cleanly', code == 0, code)
    merged = [name for name in os.listdir(tmpdir) if name.startswith('merged_')]
    if not merged:
        check('a merged file was written', False)
        return
    _columns, rows = read_csv(os.path.join(tmpdir, merged[0]))
    check('three members, three rows - not five and not one', len(rows) == 3, rows)
    releases = sorted(row[6] for row in rows)
    check('every member carries the rerun\'s release, not the first pass\'s',
          releases == ['17.12.5', '17.12.5', '17.12.5'], releases)


def test_mismatched_columns_are_refused(tmpdir):
    print('\nan inventory file and a run log are never merged together')
    write_csv(os.path.join(tmpdir, 'weird_a.csv'), INVENTORY_COLUMNS, [])
    write_csv(os.path.join(tmpdir, 'weird_b.csv'), RUN_LOG_COLUMNS, [])
    try:
        merge_tool.merge([os.path.join(tmpdir, 'weird_a.csv'),
                          os.path.join(tmpdir, 'weird_b.csv')])
        check('a header mismatch raises rather than merging silently', False)
    except ValueError as error:
        check('a header mismatch raises rather than merging silently', True)
        check('and says which file disagreed', 'weird_b.csv' in str(error), str(error))


def test_ambiguous_folder_requires_a_prefix(tmpdir):
    print('\na folder holding both kinds refuses to guess')
    write_csv(os.path.join(tmpdir, 'inventory_20260101_100000.csv'), INVENTORY_COLUMNS, [])
    write_csv(os.path.join(tmpdir, 'run_log_20260101_100000.csv'), RUN_LOG_COLUMNS, [])
    try:
        merge_tool.find_source_files(tmpdir)
        check('raises rather than picking one kind silently', False)
    except SystemExit as error:
        check('raises rather than picking one kind silently', True)
        check('and names both kinds found',
              'inventory_' in str(error) and 'run_log_' in str(error), str(error))

    only_inventory = merge_tool.find_source_files(tmpdir, prefix='inventory_')
    check('--prefix picks out just the one kind asked for',
          len(only_inventory) == 1 and 'inventory_' in only_inventory[0], only_inventory)


def test_no_files_found(tmpdir):
    print('\nan empty folder is reported, not a crash')
    code = merge_tool.main([tmpdir])
    check('a non-zero exit', code != 0, code)
    check('nothing written', not os.listdir(tmpdir), os.listdir(tmpdir))


def test_no_dedupe_keeps_every_row(tmpdir):
    print('\n--no-dedupe keeps every row, including older duplicates')
    write_csv(os.path.join(tmpdir, 'run_log_20260101_100000.csv'), RUN_LOG_COLUMNS,
              [('sw-a', '10.0.3.1', '', 'Connection timed out', 'unreachable', 'sw-a',
                '2026-01-01 10:00:00')])
    write_csv(os.path.join(tmpdir, 'run_log_20260101_120000.csv'), RUN_LOG_COLUMNS,
              [('SW01', '10.0.3.1', 'C9300-48P', '', 'checklisted', 'sw-a',
                '2026-01-01 12:00:00')])
    code = merge_tool.main([tmpdir, '--no-dedupe'])
    check('exits cleanly', code == 0, code)
    merged = [name for name in os.listdir(tmpdir) if name.startswith('merged_')]
    if not merged:
        check('a merged file was written', False)
        return
    _columns, rows = read_csv(os.path.join(tmpdir, merged[0]))
    check('both rows kept, deduped or not', len(rows) == 2, rows)


def test_a_previous_merge_is_never_folded_back_in(tmpdir):
    print('\nre-running the merge does not eat its own output')
    write_csv(os.path.join(tmpdir, 'run_log_20260101_100000.csv'), RUN_LOG_COLUMNS,
              [('sw-a', '10.0.4.1', 'C9300', '', 'checklisted', 'sw-a',
                '2026-01-01 10:00:00')])
    first_code = merge_tool.main([tmpdir])
    check('first merge exits cleanly', first_code == 0, first_code)
    second_code = merge_tool.main([tmpdir])
    check('second merge exits cleanly', second_code == 0, second_code)
    merged = sorted(name for name in os.listdir(tmpdir) if name.startswith('merged_'))
    check('two merges, two merged files - neither treated as a source',
          len(merged) == 2, os.listdir(tmpdir))
    if len(merged) == 2:
        _columns, rows = read_csv(os.path.join(tmpdir, merged[-1]))
        check('the second merge still has exactly the one real row', len(rows) == 1, rows)


if __name__ == '__main__':
    for test in (test_merges_disjoint_files,
                 test_dedupes_to_the_newest_row_per_switch,
                 test_stack_members_are_not_collapsed,
                 test_mismatched_columns_are_refused,
                 test_ambiguous_folder_requires_a_prefix,
                 test_no_files_found,
                 test_no_dedupe_keeps_every_row,
                 test_a_previous_merge_is_never_folded_back_in):
        with tempfile.TemporaryDirectory() as tmpdir:
            test(tmpdir)
    print('\n' + ('ALL CHECKS PASSED' if not failures
                  else f'{len(failures)} FAILED: {", ".join(failures)}'))
    sys.exit(1 if failures else 0)
