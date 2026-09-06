#!/usr/bin/env python
"""Pull the IP addresses out of a PDF network diagram into a CSV.

A Visio drawing exported to PDF is how addressing usually arrives from someone
else, and reading fifty of them off a diagram into a spreadsheet is both slow
and the kind of work that produces a transposed octet nobody finds until it is
in a firewall rule.

Stdlib only, which is a constraint rather than a preference: the host this runs
on has no PyPDF2 and no pdfplumber, and the point of this repo is that it runs
where it is needed. So the PDF is parsed here - objects, page tree, content
streams, text-showing operators - which sounds worse than it is, because the
only thing being asked of the file is "what text does it contain".

**It reads text, and a diagram does not always have any.** A PDF exported from
Visio carries real text and this works. A PDF that is a scan, a photograph, or
a drawing flattened to an image carries pixels that look like text to a person
and are nothing to a parser: there is no text layer to find, no addresses come
out, and the answer is not a better regex but a different source file. That
case is reported as itself rather than as an empty result, because an empty
CSV reads like "the diagram has no addresses on it".

Two more limits worth knowing before trusting the output:

  * Text in a PDF has no reading order beyond the order it was drawn in, and a
    diagram is drawn shape by shape. The `context` column is the text drawn
    around each address, which is usually its label - and sometimes the label
    of the box next to it. Treat it as a hint for finding the address on the
    page, not as an assertion about what it belongs to.
  * A subset font with a custom encoding can map glyphs to codes that mean
    nothing outside the file. Text then extracts as mojibake; addresses in it
    will not match. The tool says how much text it found so a page that came
    out as noise is visible rather than silently empty.

Usage:
    python3 pdf_ips.py diagram.pdf
    python3 pdf_ips.py diagram.pdf -o addressing.csv
    python3 pdf_ips.py diagram.pdf --all-text        # what it saw, to debug a miss
"""

import argparse
import csv
import os
import re
import sys
import zlib

# `N 0 obj ... endobj`. Object numbers can repeat across incremental updates;
# later definitions win, which is what a PDF reader does with the newest xref.
OBJECT = re.compile(rb'(\d+)\s+(\d+)\s+obj\b(.*?)\bendobj', re.S)
STREAM = re.compile(rb'stream\r?\n(.*?)\r?\nendstream', re.S)

# Text-showing operators. `Tj` and `'` and `"` take one string; `TJ` takes an
# array of strings and kerning numbers, which is how a word processor writes a
# line and why an address can arrive split across several strings.
TEXT_OPERATORS = re.compile(rb"(\((?:[^()\\]|\\.|\((?:[^()\\]|\\.)*\))*\)|<[0-9A-Fa-f\s]*>)"
                            rb"\s*(?:Tj|TJ|'|\")|"
                            rb"\[((?:[^\[\]\\]|\\.)*)\]\s*TJ", re.S)
ARRAY_STRING = re.compile(rb"(\((?:[^()\\]|\\.)*\)|<[0-9A-Fa-f\s]*>)", re.S)

IP_ADDRESS = re.compile(r'(?<![\w.])(\d{1,3}(?:\.\d{1,3}){3})(?:\s*/\s*(\d{1,2}))?(?![\w.])')

FIELDS = ('source', 'page', 'ip_address', 'prefix_length', 'occurrences', 'context')

# PDF string escapes, per the spec's table of them.
STRING_ESCAPES = {
    b'n': b'\n', b'r': b'\r', b't': b'\t', b'b': b'\b', b'f': b'\f',
    b'(': b'(', b')': b')', b'\\': b'\\',
}


class PdfError(Exception):
    """The PDF could not be read as text. Raised rather than returning an
    empty result: "no addresses in this diagram" and "this file has no text in
    it at all" are different answers, and only one of them is about the
    diagram."""


def _unescape(raw):
    """Decode a PDF literal string body: backslash escapes and \\ddd octal."""
    out = bytearray()
    i = 0
    while i < len(raw):
        char = raw[i:i + 1]
        if char != b'\\':
            out += char
            i += 1
            continue
        nxt = raw[i + 1:i + 2]
        if nxt in STRING_ESCAPES:
            out += STRING_ESCAPES[nxt]
            i += 2
        elif nxt.isdigit():
            octal = raw[i + 1:i + 4]
            while octal and not octal.isdigit():
                octal = octal[:-1]
            out += bytes([int(octal, 8) & 0xFF])
            i += 1 + len(octal)
        elif nxt == b'\n':
            i += 2                      # a line continuation inside a string
        else:
            out += nxt
            i += 2
    return bytes(out)


def _decode(raw):
    """Bytes from a PDF string to text.

    UTF-16 is marked by a byte order mark; everything else is treated as
    Latin-1, which is close enough to PDFDocEncoding and WinAnsi for the ASCII
    an address is written in, and never raises."""
    if raw[:2] in (b'\xfe\xff', b'\xff\xfe'):
        return raw.decode('utf-16', errors='replace')
    return raw.decode('latin-1', errors='replace')


def _string_value(token):
    if token.startswith(b'<'):
        hex_digits = re.sub(rb'\s', b'', token[1:-1])
        if len(hex_digits) % 2:
            hex_digits += b'0'          # the spec pads an odd final digit
        try:
            return _decode(bytes.fromhex(hex_digits.decode('ascii')))
        except ValueError:
            return ''
    return _decode(_unescape(token[1:-1]))


def text_of_stream(content):
    """The text drawn by a content stream, one string per text-showing
    operation.

    Kept as a list rather than joined, because a diagram's text has no reading
    order: what is useful downstream is each drawn run, and their sequence."""
    runs = []
    for match in TEXT_OPERATORS.finditer(content):
        if match.group(1):
            runs.append(_string_value(match.group(1)))
        else:
            parts = [_string_value(token) for token in ARRAY_STRING.findall(match.group(2))]
            # TJ's numbers are kerning, not spaces. Joining the parts with
            # nothing is right for `10.1` `.1.1`, which is how one address
            # commonly arrives; a real space is drawn as a space character.
            runs.append(''.join(parts))
    return [run for run in runs if run.strip()]


def _objects(data):
    """{object number: body} for every object in the file, later definitions
    winning over earlier ones."""
    objects = {}
    for match in OBJECT.finditer(data):
        objects[int(match.group(1))] = match.group(3)
    return objects


def _stream_data(body):
    """The decoded bytes of an object's stream, or None if it has none."""
    match = STREAM.search(body)
    if not match:
        return None
    raw = match.group(1)
    if b'/FlateDecode' in body.split(b'stream', 1)[0]:
        try:
            return zlib.decompress(raw)
        except zlib.error:
            try:
                # Some writers leave a stray byte before the deflate data.
                return zlib.decompressobj().decompress(raw)
            except zlib.error:
                return b''
    if any(filter_name in body.split(b'stream', 1)[0] for filter_name in
           (b'/DCTDecode', b'/JPXDecode', b'/CCITTFaxDecode', b'/JBIG2Decode')):
        return b''                      # an image, not text
    return raw


def _page_objects(objects):
    """Page object numbers in reading order.

    The page tree is followed where it can be - /Kids is the only thing in a
    PDF that states page order - and object order is the fallback, which is
    what generated files (a Visio export among them) come out in anyway."""
    order = []

    def walk(number, seen):
        if number in seen or number not in objects:
            return
        seen.add(number)
        body = objects[number]
        if re.search(rb'/Type\s*/Pages\b', body):
            kids = re.search(rb'/Kids\s*\[(.*?)\]', body, re.S)
            if kids:
                for kid in re.findall(rb'(\d+)\s+\d+\s+R', kids.group(1)):
                    walk(int(kid), seen)
        elif re.search(rb'/Type\s*/Page\b', body):
            order.append(number)

    roots = [number for number, body in objects.items()
             if re.search(rb'/Type\s*/Pages\b', body) and b'/Parent' not in body]
    for root in roots:
        walk(root, set())
    if not order:
        order = sorted(number for number, body in objects.items()
                       if re.search(rb'/Type\s*/Page\b', body))
    return order


def pages_text(data):
    """[[run, ...], ...] - the text runs of each page, in page order."""
    objects = _objects(data)
    pages = []
    for number in _page_objects(objects):
        body = objects[number]
        contents = re.search(rb'/Contents\s*(?:(\d+)\s+\d+\s+R|\[(.*?)\])', body, re.S)
        stream_numbers = []
        if contents and contents.group(1):
            stream_numbers = [int(contents.group(1))]
        elif contents and contents.group(2):
            stream_numbers = [int(n) for n in re.findall(rb'(\d+)\s+\d+\s+R', contents.group(2))]
        runs = []
        for stream_number in stream_numbers:
            if stream_number in objects:
                content = _stream_data(objects[stream_number])
                if content:
                    runs.extend(text_of_stream(content))
        pages.append(runs)
    if not pages:
        # No page tree recognised: read every stream in the file instead. A
        # partial answer beats refusing a file that plainly has text in it.
        runs = []
        for body in objects.values():
            content = _stream_data(body)
            if content and b'Tj' in content or (content and b'TJ' in content):
                runs.extend(text_of_stream(content))
        if runs:
            pages = [runs]
    return pages


def _context_for(runs, index, ip_text):
    """The text drawn around one address, as a hint for finding it on the page.

    A diagram is drawn shape by shape, so the runs on either side are usually
    the label of the same shape - and sometimes the label of the next one,
    which is why this is a hint and the docstring at the top says so."""
    neighbours = runs[max(0, index - 2):index] + runs[index + 1:index + 3]
    context = ' | '.join(run.strip() for run in neighbours if run.strip())
    own = runs[index].strip()
    if own != ip_text:
        context = f'{own} | {context}' if context else own
    return re.sub(r'\s+', ' ', context)[:200]


def addresses_in(data, source=''):
    """[(row dict)] for every IPv4 address in the PDF, in page order.

    An address that appears more than once on a page is one row with a count:
    a diagram repeats an address for the same device at both ends of a link,
    and fifty duplicate rows help nobody."""
    rows = {}
    for page_number, runs in enumerate(pages_text(data), 1):
        for index, run in enumerate(runs):
            for match in IP_ADDRESS.finditer(run):
                octets = match.group(1).split('.')
                if any(int(octet) > 255 for octet in octets):
                    continue
                prefix = match.group(2) or ''
                if prefix and not 0 <= int(prefix) <= 32:
                    prefix = ''
                key = (page_number, match.group(1), prefix)
                if key in rows:
                    rows[key]['occurrences'] += 1
                    continue
                rows[key] = {
                    'source': source,
                    'page': page_number,
                    'ip_address': match.group(1),
                    'prefix_length': prefix,
                    'occurrences': 1,
                    'context': _context_for(runs, index, match.group(1)),
                }
    return list(rows.values())


def read_pdf(path):
    if not os.path.exists(path):
        raise PdfError(f'No such file: {path}')
    with open(path, 'rb') as pdf_file:
        data = pdf_file.read()
    if not data.startswith(b'%PDF-'):
        raise PdfError(f'{path} does not start with %PDF- , so it is not a PDF.')
    if re.search(rb'/Encrypt\b', data):
        raise PdfError(
            f'{path} is encrypted. Even an empty-password PDF has its streams encrypted, and '
            'decrypting them is not something this does.\nRe-export or re-save it without '
            'protection and try again.')
    return data


def main(argv=None):
    parser = argparse.ArgumentParser(
        description='Extract IPv4 addresses from a PDF (a Visio diagram exported to PDF, '
                    'typically) into a CSV.')
    parser.add_argument('pdf', help='The PDF to read. Never modified.')
    parser.add_argument('-o', '--output', metavar='PATH',
                        help='Write the CSV here. Default: stdout, so it can be piped.')
    parser.add_argument('--all-text', action='store_true',
                        help='Print every text run the PDF yielded instead of the CSV. This is '
                             'how to tell "the diagram has no addresses" from "the text came '
                             'out as noise" when a page looks empty.')
    args = parser.parse_args(argv)

    try:
        data = read_pdf(args.pdf)
    except PdfError as error:
        print(error, file=sys.stderr)
        return 2

    pages = pages_text(data)
    total_runs = sum(len(runs) for runs in pages)
    source = os.path.basename(args.pdf)

    if args.all_text:
        for page_number, runs in enumerate(pages, 1):
            print(f'--- page {page_number} ({len(runs)} text runs)')
            for run in runs:
                print(f'  {run}')
        return 0

    if total_runs == 0:
        print(
            f'{args.pdf} has {len(pages)} page(s) and no extractable text.\n'
            'That is what a scan, a photograph, or a diagram flattened to an image looks like: '
            'the addresses\nare pixels, and no amount of parsing will find them. Re-export the '
            'drawing to PDF from Visio\n(File > Export > PDF, not a print-to-image), or read '
            'them from the .vsdx instead.', file=sys.stderr)
        return 1

    rows = addresses_in(data, source=source)
    if args.output:
        parent = os.path.dirname(os.path.abspath(args.output))
        if parent:
            os.makedirs(parent, exist_ok=True)
        handle = open(args.output, 'w', newline='', encoding='utf-8')
    else:
        handle = sys.stdout
    try:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    finally:
        if args.output:
            handle.close()

    print(f'{len(rows)} address(es) across {len(pages)} page(s), from {total_runs} text runs'
          + (f' -> {args.output}' if args.output else ''), file=sys.stderr)
    if not rows:
        print('The text came out; no address was in it. Run again with --all-text to see what '
              'the pages actually said - a subset font with a custom encoding extracts as '
              'noise, and that looks the same from here.', file=sys.stderr)
    return 0


if __name__ == '__main__':
    sys.exit(main())
