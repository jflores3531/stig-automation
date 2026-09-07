#!/usr/bin/env python
"""Merge the per-run CSVs the SecureCRT walkers leave behind into one file.

securecrt/inventory_l2s.py and securecrt/capture_l2s_bulk.py each write one
CSV per run - inventory_<stamp>.csv or run_log_<stamp>.csv - by design: a run
scoped to the whole fleet is one snapshot, and there is deliberately no
resume logic tying separate runs together (inventory_l2s.py's own docstring
says so). Scoping runs by distribution node instead of the whole fleet turns
that into one CSV per node, which is the right unit for running the walk but
not for reading the result - a spreadsheet wants the fleet in one file.

This reads every matching CSV in a folder and writes one merged file:

    python3 scripts/merge_walk_csvs.py <folder>

Only files sharing one exact header are ever merged together -
inventory_*.csv and run_log_*.csv answer different questions and are never
folded into each other. If a folder holds both, pass --prefix to say which.

Rows are deduplicated to the newest by the row's own timestamp column: a
switch a node's second run finally reached should not also appear as the
blank, unreachable row its first run produced. A stack keeps one row per
member - switch_number joins session in the dedupe key wherever the header
carries it, so member 2 is never collapsed into member 1 of the same
session appearing in an earlier run. Pass --no-dedupe to keep every row from
every file instead, e.g. to see how many attempts a switch took across
reruns.

A file this script itself wrote (merged_*.csv) is never picked up as a
source, so re-running the merge against its own output folder does not fold
a previous merge back into the next one.
"""

import argparse
import csv
import os
import sys
import time


PREFIXES = ('inventory_', 'run_log_')


def find_source_files(directory, prefix=None):
    """CSVs in `directory` to merge, sorted so same-run files stay in the
    order they were produced. Only the two known walker prefixes are ever
    picked up; `prefix` narrows to one, and without it exactly one kind must
    be present in the folder, or which files belong together is not this
    script's guess to make."""
    if not os.path.isdir(directory):
        return []
    names = sorted(name for name in os.listdir(directory)
                   if name.endswith('.csv') and not name.startswith('merged_'))
    if prefix:
        return [os.path.join(directory, name) for name in names if name.startswith(prefix)]

    by_kind = {kind: [name for name in names if name.startswith(kind)] for kind in PREFIXES}
    kinds_present = [kind for kind, matched in by_kind.items() if matched]
    if len(kinds_present) > 1:
        raise SystemExit(
            "Both {0} are in {1} - pass --prefix to say which to merge:\n  {2}".format(
                ' and '.join(f"'{kind}'" for kind in PREFIXES), directory,
                '\n  '.join(f'{kind} ({len(by_kind[kind])} file(s))' for kind in kinds_present)))
    if not kinds_present:
        return []
    return [os.path.join(directory, name) for name in by_kind[kinds_present[0]]]


def read_rows(path):
    """(header, rows) from one CSV. ([], []) for a file with nothing in it."""
    with open(path, encoding='utf-8', newline='') as handle:
        all_rows = list(csv.reader(handle))
    if not all_rows:
        return [], []
    return all_rows[0], all_rows[1:]


def merge(paths, dedupe=True):
    """(columns, rows, rows_read) from every file in `paths`.

    Raises ValueError if the files do not all share one header - merging
    columns that do not mean the same thing would produce a file that looks
    complete and is not, which is worse than refusing outright."""
    columns = None
    all_rows = []
    for path in paths:
        header, rows = read_rows(path)
        if not header:
            continue
        if columns is None:
            columns = header
        elif header != columns:
            raise ValueError(
                f'{path} has different columns than the files before it:\n'
                f'  expected: {columns}\n  found:    {header}')
        all_rows.extend(rows)
    if columns is None:
        return [], [], 0
    if not dedupe:
        return columns, all_rows, len(all_rows)

    session_idx = columns.index('session')
    timestamp_idx = columns.index('timestamp')
    switch_idx = columns.index('switch_number') if 'switch_number' in columns else None

    latest = {}
    order = []
    for row in all_rows:
        key = (row[session_idx], row[switch_idx] if switch_idx is not None else '')
        # Filenames are timestamp-ordered, so `all_rows` is already oldest
        # first - >= lets the later file win a same-second tie the same way
        # the walk itself would if it re-collected a switch that fast.
        if key not in latest or row[timestamp_idx] >= latest[key][timestamp_idx]:
            if key not in latest:
                order.append(key)
            latest[key] = row
    return columns, [latest[key] for key in order], len(all_rows)


def write_merged(path, columns, rows):
    # newline='' is required of csv on Windows; without it every row is
    # followed by a blank one, which Excel shows and a diff does not.
    with open(path, 'w', encoding='utf-8', newline='') as handle:
        writer = csv.writer(handle, quoting=csv.QUOTE_ALL)
        writer.writerow(columns)
        writer.writerows(rows)


def unused_path(directory, stem, extension):
    """A path in `directory` that does not exist yet, suffixing _2, _3 ... if
    needed - so two merges run inside the same second do not overwrite each
    other's output."""
    path = os.path.join(directory, stem + extension)
    counter = 2
    while os.path.exists(path):
        path = os.path.join(directory, f'{stem}_{counter}{extension}')
        counter += 1
    return path


def default_output_path(directory, paths):
    kind = 'inventory' if os.path.basename(paths[0]).startswith('inventory_') else 'run_log'
    stem = f'merged_{kind}_{time.strftime("%Y%m%d_%H%M%S")}'
    return unused_path(directory, stem, '.csv')


def main(argv=None):
    parser = argparse.ArgumentParser(
        description='Merge per-run inventory_*.csv or run_log_*.csv files into one.')
    parser.add_argument('directory', help='Folder holding the per-run CSVs')
    parser.add_argument('--prefix', choices=PREFIXES,
                        help="Merge only 'inventory_' or 'run_log_' files. Required if the "
                             'folder has both kinds.')
    parser.add_argument('-o', '--out', metavar='PATH',
                        help='Output path (default: merged_<kind>_<stamp>.csv in the same '
                             'folder)')
    parser.add_argument('--no-dedupe', action='store_true',
                        help='Keep every row from every file, instead of the newest row per '
                             'switch')
    args = parser.parse_args(argv)

    paths = find_source_files(args.directory, args.prefix)
    if not paths:
        print(f'No inventory_*.csv or run_log_*.csv files found in {args.directory}',
              file=sys.stderr)
        return 1

    try:
        columns, rows, rows_read = merge(paths, dedupe=not args.no_dedupe)
    except ValueError as error:
        print(error, file=sys.stderr)
        return 1

    if not rows:
        print('Nothing to merge - every input file was empty.', file=sys.stderr)
        return 1

    out_path = args.out or default_output_path(args.directory, paths)
    write_merged(out_path, columns, rows)

    dropped = rows_read - len(rows)
    print(f'{len(paths)} file(s), {rows_read} row(s) read'
          + (f', {dropped} collapsed as older duplicates' if dropped else '')
          + f' -> {len(rows)} row(s)\n{out_path}', file=sys.stderr)
    return 0


if __name__ == '__main__':
    sys.exit(main())
