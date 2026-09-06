#!/usr/bin/env python
"""Verification for capture.py and l2_stig_audit.py's --from-capture path.

Run it directly - `python3 tests/test_capture.py` - from anywhere. No test
framework, matching the rest of this project's dependencies (netmiko, pyyaml,
nothing else), and no device: the whole point of the offline path is that it
needs neither.

What this is guarding. An offline audit is only worth having if it reaches the
same verdicts a live one would, so the central test renders known output into a
capture file, parses it back, and asserts a full audit driven by that file is
byte-identical to one driven by a live-shaped session. Everything else here
guards the ways a capture can be quietly wrong: truncated by a pager, missing a
command, or carrying output for a command the audit never asked for. Those all
have to raise, because a check handed empty text returns a verdict with exactly
the same confidence as one handed real config, and a false PASS nobody re-reads
is worse than a crash.

Device output comes from fixtures.py and is synthetic. Real captures are
gitignored and must never be committed - see capture.py.
"""

import codecs
import contextlib
import io
import os
import subprocess
import sys
import tempfile

PROJECT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import capture
import stig_common
from fixtures import OUTPUTS, VLAN_BRIEF, VTP_PASSWORD

CHECKLIST = os.path.join(PROJECT, 'checklists', 'New Layer 2 switch Checklist.cklb')

failures = []


def check(name, condition, detail=''):
    print(f'  {"ok  " if condition else "FAIL"} {name}')
    if not condition:
        if detail:
            print(f'       {detail}')
        failures.append(name)


def expect_error(name, call, needle):
    """Assert `call` raises CaptureError whose message names the real problem.
    The message matters as much as the raise - these fire on someone else's
    network, where the fix has to be obvious from the text alone."""
    try:
        call()
    except capture.CaptureError as error:
        check(name, needle.lower() in str(error).lower(), f'message was: {error}')
    else:
        check(name, False, 'no CaptureError raised')


class FakeLiveSession:
    """Shaped like the Netmiko connection run_stig_audit would otherwise open."""

    def __init__(self, outputs):
        self.outputs = outputs
        self.disconnected = False

    def send_command(self, command, *_args, **_kwargs):
        return self.outputs[command]

    def disconnect(self):
        self.disconnected = True


def report_from(session, checks):
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        stig_common.run_stig_audit('TESTSW01', None, CHECKLIST, checks, title='STIG audit',
                                   username=None, password=None, session=session)
    return buffer.getvalue()


def test_round_trip():
    print('round-trip: text -> capture file -> parsed text')
    parsed = capture.parse(capture.render(OUTPUTS))
    for command, original in OUTPUTS.items():
        check(f'{command!r} survives verbatim', parsed.get(command) == original.strip('\n'))
    check('no extra sections', set(parsed) == set(OUTPUTS), f'got {sorted(parsed)}')
    # Indentation delimits interface blocks; a plain .strip() would eat it.
    check('interface block indentation preserved',
          ' switchport mode access' in parsed['show running-config'])
    check('CRLF captures normalise',
          capture.parse(capture.render(OUTPUTS).replace('\n', '\r\n'))['show vtp password']
          == VTP_PASSWORD)
    check('whitespace-varied command names still match',
          capture.parse(capture.render({'show  vlan   brief': VLAN_BRIEF}))['show vlan brief']
          == VLAN_BRIEF)


def test_session_log():
    print('\nplain terminal session log, no delimiters')
    log = ''.join(f'TESTSW01#{command}\n{output}\nTESTSW01#\n'
                  for command, output in OUTPUTS.items())
    parsed = capture.parse(log, capture.AUDIT_COMMANDS_L2S + capture.OPTIONAL_COMMANDS_L2S)
    check('every command recovered', set(parsed) == set(OUTPUTS), f'got {sorted(parsed)}')
    for command, original in OUTPUTS.items():
        check(f'{command!r} matches the delimited form', parsed.get(command) == original.strip('\n'))
    check('trailing prompt stripped', not parsed['show vtp password'].endswith('#'))
    # running-config is full of lines that read like commands. If any of them
    # were treated as a separator, the section before it would be silently
    # truncated - which is why only the requested commands can split a capture.
    check('running-config not split on its own content',
          parsed['show running-config'].endswith('end')
          and 'hostname TESTSW01' in parsed['show running-config'])


def test_encodings(tmpdir):
    """A capture does not always arrive as the tooling wrote it. The work
    switches are reachable only through PowerShell or SecureCRT, and both of
    PowerShell's obvious ways to save output add a byte order mark: `>` and
    Out-File default to UTF-16LE on Windows PowerShell 5.1, and
    `Out-File -Encoding utf8` writes UTF-8 with a BOM. Neither failed loudly
    before - a UTF-8 BOM glued itself to the first delimiter line so only
    `show running-config` went missing, and UTF-16 matched nothing at all -
    and either one is a wasted trip to a switch."""
    print('\ncaptures re-saved by PowerShell still load')
    rendered = capture.render(OUTPUTS)
    # Written as bytes, because Python's 'utf-16-be'/'utf-16-le' codecs emit no
    # BOM of their own - the mark has to be prepended to get the real thing.
    variants = [
        ('no BOM', rendered.encode('utf-8')),
        ('UTF-8 BOM, Out-File -Encoding utf8', codecs.BOM_UTF8 + rendered.encode('utf-8')),
        ("UTF-16LE BOM, PowerShell 5.1 '>'", codecs.BOM_UTF16_LE + rendered.encode('utf-16-le')),
        ('UTF-16BE BOM, Out-File -Encoding bigendianunicode',
         codecs.BOM_UTF16_BE + rendered.encode('utf-16-be')),
        ('UTF-32LE BOM', codecs.BOM_UTF32_LE + rendered.encode('utf-32-le')),
    ]
    for index, (label, raw) in enumerate(variants):
        path = os.path.join(tmpdir, f'enc_{index}.capture')
        with open(path, 'wb') as handle:
            handle.write(raw)
        try:
            session = capture.load(path)
            ok = session.send_command('show running-config') == OUTPUTS['show running-config'].strip('\n')
            detail = ''
        except capture.CaptureError as error:
            ok, detail = False, str(error)
        check(f'{label} loads', ok, detail)

    # UTF-16 with the BOM stripped cannot be sniffed. It has to name its own
    # cause rather than surfacing as "no recognisable command output".
    headless = os.path.join(tmpdir, 'utf16_nobom.capture')
    with open(headless, 'wb') as handle:
        handle.write(rendered.encode('utf-16-le'))
    expect_error('UTF-16 without a BOM names the encoding',
                 lambda: capture.load(headless), 'utf-16')


def test_not_a_switch(tmpdir):
    """A session pointed at something that is not a Cisco switch yields a file
    with all six sections present and none of them config - bash answers every
    command with an error, so nothing is empty and nothing is truncated. The
    audit would then answer 64 rules against shell error text and report a
    switch that does not exist. Caught here, however the capture was collected."""
    print('\ncaptures from something that is not a switch are refused')
    bash = {command: 'bash: {0}: command not found'.format(command.split()[0])
            for command in capture.AUDIT_COMMANDS_L2S}
    path = capture.write(os.path.join(tmpdir, 'bash.capture'), bash)
    expect_error('a bash session is refused', lambda: capture.load(path),
                 'does not contain a Cisco configuration')

    # Loose on purpose: a capture trimmed of its "Building configuration..."
    # header is still a config and must still load.
    trimmed = dict(OUTPUTS)
    trimmed['show running-config'] = 'hostname TESTSW01\n!\ninterface Vlan10\n!\nend'
    path = capture.write(os.path.join(tmpdir, 'trimmed.capture'), trimmed)
    check('a header-less config still loads',
          capture.load(path).send_command('show running-config').startswith('hostname'))


def test_refusals(tmpdir):
    print('\nmalformed captures are refused, not audited')
    paged = capture.render(OUTPUTS).replace('vlan 10\n', 'vlan 10\n --More-- \n', 1)
    expect_error('paginated capture rejected', lambda: capture.parse(paged), 'terminal length 0')

    partial = capture.write(os.path.join(tmpdir, 'partial.capture'),
                            {k: v for k, v in OUTPUTS.items() if k != 'show snmp user'})
    expect_error('missing command rejected', lambda: capture.load(partial), 'show snmp user')

    blank = capture.write(os.path.join(tmpdir, 'blank.capture'),
                          {**OUTPUTS, 'show vtp password': ''})
    expect_error('empty command output rejected', lambda: capture.load(blank), 'empty output')

    # `show snmp user` is the exception: a switch with no SNMPv3 users prints
    # nothing, which is a legal state and the V-220604/605 finding itself.
    # Refusing it would block the audit on exactly what it was run to catch.
    no_users = capture.write(os.path.join(tmpdir, 'nosnmp.capture'),
                             {**OUTPUTS, 'show snmp user': ''})
    check('empty `show snmp user` accepted, and served as empty',
          capture.load(no_users).send_command('show snmp user') == '')

    expect_error('absent file rejected',
                 lambda: capture.load(os.path.join(tmpdir, 'nope.capture')), 'no such capture')

    good = capture.write(os.path.join(tmpdir, 'good.capture'), OUTPUTS)
    expect_error('unrequested command raises rather than returning empty',
                 lambda: capture.load(good).send_command('show crypto pki certificates'),
                 'no output for')

    # `show ip interface brief` answers no rule - it fills the exported
    # checklist's asset block - so a capture taken before it was collected is
    # audited without it rather than refused. Every capture in captures/ from
    # before this existed is one of those, and refusing them would make an
    # older capture unauditable over a field STIG Viewer shows as blank.
    older = capture.write(os.path.join(tmpdir, 'older.capture'),
                          {k: v for k, v in OUTPUTS.items() if k != 'show ip interface brief'})
    session = capture.load(older)
    check('a capture without the optional command still loads', session is not None)
    check('and asking for it yields nothing rather than raising',
          capture.optional_output(session, 'show ip interface brief') == '')


def test_equivalence(tmpdir):
    print('\ncapture session vs live-shaped session, same verdicts')
    checks = {
        'V-220596': lambda cfg: ('exec-timeout 5 0' in cfg, 'console exec-timeout'),
        'V-220599': lambda cfg: ('logging buffered 64000' in cfg, 'buffer size'),
        'V-220649': lambda cfg: (None, 'not applicable here'),
        'V-220642': lambda cfg: ('NOT AUTOMATED', 'needs live review'),
    }
    good = capture.write(os.path.join(tmpdir, 'equiv.capture'), OUTPUTS)
    live = FakeLiveSession(OUTPUTS)
    live_report = report_from(live, checks)
    check('reports byte-identical', live_report == report_from(capture.load(good), checks))
    check('live session was disconnected', live.disconnected)
    check('report is non-trivial', live_report.count('\n') > 100 and 'passed' in live_report)


def test_end_to_end(tmpdir):
    print('\nend-to-end: l2_stig_audit.py --from-capture, every rule in the checklist')
    good = capture.write(os.path.join(tmpdir, 'e2e.capture'), OUTPUTS)
    result = subprocess.run(
        [sys.executable, os.path.join(PROJECT, 'l2_stig_audit.py'), 'TESTSW01',
         '--checklist', 'ios',  # this test's expectations are IOS-keyed (65 rules)
         '--from-capture', good, '--non-user-vlans', '1,10,999,1000'],
        capture_output=True, text=True, cwd=PROJECT, timeout=120)
    check('script exits cleanly', result.returncode == 0, result.stderr[-1500:])
    check('no connection attempted', 'Connecting to device' not in result.stdout)
    check('capture source named in output', 'e2e.capture' in result.stdout)
    summary = [line for line in result.stdout.splitlines() if 'out of' in line]
    check('summary line present', bool(summary), result.stdout[:400])
    if summary:
        print(f'       {summary[0].strip()}')
    check('every checklist rule reported', '65 rules' in result.stdout)

    print('\nmutually exclusive flags')
    clash = subprocess.run(
        [sys.executable, os.path.join(PROJECT, 'l2_stig_audit.py'), 'S1',
         '--checklist', 'ios',
         '--from-capture', good, '--capture-to', os.path.join(tmpdir, 'x.capture')],
        capture_output=True, text=True, cwd=PROJECT, timeout=60)
    check('--from-capture with --capture-to is refused', clash.returncode == 2, clash.stdout)


if __name__ == '__main__':
    with tempfile.TemporaryDirectory() as tmpdir:
        test_round_trip()
        test_session_log()
        test_encodings(tmpdir)
        test_not_a_switch(tmpdir)
        test_refusals(tmpdir)
        test_equivalence(tmpdir)
        test_end_to_end(tmpdir)
    print('\n' + ('ALL CHECKS PASSED' if not failures
                  else f'{len(failures)} FAILED: {", ".join(failures)}'))
    sys.exit(1 if failures else 0)
