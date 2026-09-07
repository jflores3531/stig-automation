#!/usr/bin/env python
"""pdf_ips.py: reading a diagram nobody will hand over as text.

Run directly: `python3 tests/test_pdf_ips.py`. No framework, no sample file.

The PDFs are built here rather than committed, for two reasons: a real diagram
from work cannot go in a repo, and a generated one can be made to carry exactly
the shapes that break extraction - an address split across a TJ array by
kerning, a compressed content stream, a page whose only content is an image.

The image-only page is the important one. A diagram that was flattened to a
picture looks identical to a person and contains no text at all, and the
failure that matters is reporting that as "no addresses on this diagram"
rather than as "this file has no text in it".
"""

import os
import subprocess
import sys
import tempfile
import zlib

PROJECT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(PROJECT, 'scripts'))

import pdf_ips

failures = []


def check(name, condition, detail=''):
    print(f'  {"ok  " if condition else "FAIL"} {name}')
    if not condition:
        if detail:
            print(f'       {detail}')
        failures.append(name)


def build_pdf(pages, compress=False):
    """A minimal multi-page PDF. `pages` is a list of content-stream bodies.

    Deliberately hand-built: it exercises the parser against the structure of
    the format rather than against one library's idea of it, and it needs no
    dependency to produce."""
    objects = {}
    page_numbers = []
    next_number = 3
    for body in pages:
        content = body.encode('latin-1')
        if compress:
            content = zlib.compress(content)
        stream_number = next_number + 1
        objects[next_number] = (
            f'<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] '
            f'/Contents {stream_number} 0 R >>').encode('latin-1')
        filters = b'/Filter /FlateDecode ' if compress else b''
        objects[stream_number] = (b'<< ' + filters + f'/Length {len(content)} >>'.encode('latin-1')
                                  + b'\nstream\n' + content + b'\nendstream')
        page_numbers.append(next_number)
        next_number += 2

    kids = ' '.join(f'{number} 0 R' for number in page_numbers)
    objects[1] = b'<< /Type /Catalog /Pages 2 0 R >>'
    objects[2] = (f'<< /Type /Pages /Kids [{kids}] /Count {len(pages)} >>').encode('latin-1')

    out = bytearray(b'%PDF-1.4\n')
    for number in sorted(objects):
        out += f'{number} 0 obj\n'.encode('latin-1') + objects[number] + b'\nendobj\n'
    out += b'trailer\n<< /Root 1 0 R /Size 99 >>\n%%EOF\n'
    return bytes(out)


def text(x, y, string):
    return f'BT /F1 12 Tf {x} {y} Td ({string}) Tj ET\n'


# An address broken across an array the way a PDF writer kerns one, plus the
# label drawn beside it - the two shapes that decide whether extraction works
# at all.
KERNED = 'BT /F1 12 Tf 72 640 Td [(10.44) -12 (.9) 3 (.20)] TJ ET\n'

PAGE_ONE = (text(72, 700, 'CORE-SW1') + text(72, 680, '10.44.9.3 / 24')
            + text(72, 660, 'Uplink to MDF') + KERNED)
PAGE_TWO = (text(72, 700, 'EDGE-RTR') + text(72, 680, '198.51.100.1')
            + text(72, 660, 'not an address: 999.1.1.1') + text(72, 640, '10.44.9.3'))

IMAGE_ONLY = ('q 612 0 0 792 0 0 cm /Im0 Do Q\n')


def test_extracts_addresses(tmpdir):
    print('addresses come out of a two-page drawing, with their page and label')
    path = os.path.join(tmpdir, 'diagram.pdf')
    with open(path, 'wb') as pdf_file:
        pdf_file.write(build_pdf([PAGE_ONE, PAGE_TWO]))
    rows = pdf_ips.addresses_in(pdf_ips.read_pdf(path), source='diagram.pdf')
    found = {(row['page'], row['ip_address']): row for row in rows}

    check('the address on page 1 is found', (1, '10.44.9.3') in found, sorted(found))
    check('with its prefix length', found.get((1, '10.44.9.3'), {}).get('prefix_length') == '24',
          found.get((1, '10.44.9.3')))
    check('and the label drawn beside it, as context',
          'CORE-SW1' in found.get((1, '10.44.9.3'), {}).get('context', ''),
          found.get((1, '10.44.9.3')))
    check('an address kerned across a TJ array is still one address',
          (1, '10.44.9.20') in found, sorted(found))
    check('page 2 is page 2, not more of page 1', (2, '198.51.100.1') in found, sorted(found))
    check('the same address on another page is its own row',
          (2, '10.44.9.3') in found, sorted(found))
    check('999.1.1.1 is not an address', not any(row['ip_address'] == '999.1.1.1' for row in rows),
          [row['ip_address'] for row in rows])


def test_compressed_streams(tmpdir):
    print('\nand out of the compressed streams a real exporter writes')
    path = os.path.join(tmpdir, 'compressed.pdf')
    with open(path, 'wb') as pdf_file:
        pdf_file.write(build_pdf([PAGE_ONE, PAGE_TWO], compress=True))
    rows = pdf_ips.addresses_in(pdf_ips.read_pdf(path))
    check('FlateDecode content is read', {row['ip_address'] for row in rows} >=
          {'10.44.9.3', '10.44.9.20', '198.51.100.1'},
          sorted({row['ip_address'] for row in rows}))


def test_repeats_are_counted_not_repeated(tmpdir):
    print('\nan address drawn twice on a page is one row and a count')
    path = os.path.join(tmpdir, 'repeats.pdf')
    with open(path, 'wb') as pdf_file:
        pdf_file.write(build_pdf([text(72, 700, '10.1.1.1') + text(72, 680, 'link to R2')
                                  + text(72, 660, '10.1.1.1')]))
    rows = pdf_ips.addresses_in(pdf_ips.read_pdf(path))
    check('one row', len(rows) == 1, rows)
    check('counted twice', rows and rows[0]['occurrences'] == 2, rows)


def run_cli(*args):
    result = subprocess.run([sys.executable, os.path.join(PROJECT, 'scripts', 'pdf_ips.py'), *args],
                            capture_output=True, text=True, cwd=PROJECT, timeout=60)
    return result


def test_image_only_pdf_says_so(tmpdir):
    print('\na diagram flattened to an image is said to have no text, not no addresses')
    path = os.path.join(tmpdir, 'scanned.pdf')
    with open(path, 'wb') as pdf_file:
        pdf_file.write(build_pdf([IMAGE_ONLY]))
    result = run_cli(path)
    check('it exits non-zero', result.returncode == 1, result.stdout + result.stderr)
    check('and says there is no extractable text', 'no extractable text' in result.stderr,
          result.stderr)
    check('and says what to do about it', 'Visio' in result.stderr, result.stderr)
    check('rather than writing an empty CSV that reads like an answer',
          'ip_address' not in result.stdout, result.stdout)


def test_not_a_pdf(tmpdir):
    print('\nand a file that is not a PDF is refused before anything else')
    path = os.path.join(tmpdir, 'notes.txt')
    with open(path, 'w', encoding='utf-8') as text_file:
        text_file.write('10.1.1.1 is the gateway\n')
    result = run_cli(path)
    check('refused', result.returncode == 2, result.stderr)
    check('and told why', 'not a PDF' in result.stderr, result.stderr)

    encrypted = os.path.join(tmpdir, 'locked.pdf')
    with open(encrypted, 'wb') as pdf_file:
        pdf_file.write(build_pdf([PAGE_ONE]).replace(
            b'trailer\n<< /Root 1 0 R', b'trailer\n<< /Encrypt 98 0 R /Root 1 0 R'))
    result = run_cli(encrypted)
    check('an encrypted PDF is refused rather than half-read', result.returncode == 2,
          result.stderr)
    check('and says to re-save it', 'without\nprotection' in result.stderr
          or 'without protection' in result.stderr, result.stderr)


def test_csv_output(tmpdir):
    print('\nthe CSV is the deliverable')
    path = os.path.join(tmpdir, 'diagram.pdf')
    out = os.path.join(tmpdir, 'addressing.csv')
    result = run_cli(path, '-o', out)
    check('written', result.returncode == 0 and os.path.exists(out), result.stderr)
    if os.path.exists(out):
        content = open(out, encoding='utf-8').read()
        check('with a header row', content.startswith('source,page,ip_address'), content[:80])
        check('and the source file named in every row', content.count('diagram.pdf') >= 3,
              content)
    check('the summary says how much text it saw, not just how many addresses',
          'text runs' in result.stderr, result.stderr)


def test_all_text(tmpdir):
    print('\n--all-text is how a page that extracted as noise is told from an empty one')
    result = run_cli(os.path.join(tmpdir, 'diagram.pdf'), '--all-text')
    check('it prints the runs', 'CORE-SW1' in result.stdout, result.stdout[:300])
    check('page by page', '--- page 2' in result.stdout, result.stdout[:300])


if __name__ == '__main__':
    with tempfile.TemporaryDirectory() as tmp:
        test_extracts_addresses(tmp)
        test_compressed_streams(tmp)
        test_repeats_are_counted_not_repeated(tmp)
        test_image_only_pdf_says_so(tmp)
        test_not_a_pdf(tmp)
        test_csv_output(tmp)
        test_all_text(tmp)
    print('\n' + ('ALL CHECKS PASSED' if not failures
                  else f'{len(failures)} FAILED: {", ".join(failures)}'))
    sys.exit(1 if failures else 0)
