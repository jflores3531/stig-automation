#!/usr/bin/env python
"""Push only the logging/audit and access-control fixes from the Cisco L2S
STIG - the two areas that change no forwarding behaviour.

Why this exists beside l2_stig_harden_global.py, which already pushes all of
these: that script also pushes spanning-tree mode, UDLD, IGMP snooping, VLAN
database entries, `vtp mode transparent`, SNMPv3, NTP and fifteen `no <service>`
lines. Every one of those can change how a switch forwards, converges or
answers, and on a production fleet that is a change window and a rollback plan.
Nothing here touches the data plane at all: it writes log destinations, log
content, and - only when asked - the terms under which a session may be opened
to the switch.

WHAT IT PUSHES - rule numbers are IOS XE first, then the IOS book's

  Logging / audit
    V-220528/220580   timestamps on every log line
    V-220547/220599   64000-byte informational buffer
    V-220560/220612   log both failed and successful logins
    V-220526/220578   log administrator activity (`logging userinfo`)
    V-220548/220600   alert on audit failure (`logging trap critical`)
    V-220568/220620   syslog servers, from inventory.yaml (needs two per DISA)
    V-220531/532/533  `file privilege 15`, conditional on `logging persistent`
    V-220519/520/521/522/530/545/559/561 - one `archive / log config` block
                      answers all eight: DISA reuses the same evidence for
                      each, which is why this looks like a bargain and is not.

  Access control
    V-220524/220576   lock out after 3 failed attempts in 120s, for 900s
    V-220544/220596   exec-timeout on the console line
    V-220518/220570   limit concurrent management sessions, and the vty half
                      of V-220544/220596 - only with --with-vty, see below

WHAT IT DELIBERATELY LEAVES OUT
`service password-encryption`, the SSH cipher/MAC lines, and the vty management
ACL. The first two are credential and transport protection rather than either
of the areas asked for; the ACL is its own script on purpose, because an
access-class that omits the automation host locks this machine out of every
future run.

THE VTY LINES ARE OFF BY DEFAULT
Everything above is reversible from any session that can reach the switch.
The vty block is not: it decides how many sessions there can be, so a mistake
there is the one mistake this script could make that takes away the means of
fixing it. It is behind --with-vty, and V-220518/220570 stays a finding until
that is run - said in the output rather than left to the next audit. The
console exec-timeout is pushed either way; it can strand nobody, and an un-set
console line sits at IOS's 10-minute default forever.

THE SESSION LIMIT, AND WHY IT IS 5 RATHER THAN DISA'S 2
The rule is "an organization-defined number", and its finding sentence is only
"If the switch is not configured to limit the number of concurrent management
sessions, this is a finding" - so 2 is the number DISA's own example uses, not
a maximum the STIG imposes. The number here is 5, which is what
l2_stig_harden_global, ios_router_stig_harden_global and
nxos_stig_harden_global have always pushed; this script pushing 2 for the same
requirement was an inconsistency, not a stricter reading.

DISA gives three mechanisms and this pushes two of them:

  `ip http max-connections 2` is NOT pushed. It configures a limit on a server
  that hardening turns off - `no ip http server` - so on a hardened switch it
  is a number attached to nothing. The audit accepts it, which is how it ended
  up in the bulk script; that does not make it a control.

  `session-limit 5` under `line vty 0 4` is pushed, because the Fix Text shows
  it and an assessor will look for it. Worth knowing what it actually does:
  on IOS this limits the sessions a user *on that line* may open outward, not
  the number of inbound management sessions. It satisfies the rule as written.

  Reducing the usable vty lines is what actually caps concurrent inbound
  sessions, and it is the method DISA's Fix Text leads with. At a limit of 5
  that means vty 0-4 answer SSH and anything above them answers nothing: five
  lines, five sessions, enforced by the switch rather than by a per-line
  counter. On a switch whose only vty range is 0-4 there is nothing above them,
  and what gets pushed is DISA's first example verbatim.

With --with-vty both are pushed, in that order, so the switch is compliant by
the letter and limited in fact. The risk is worth stating plainly: after that,
the switch accepts 5 SSH sessions and refuses a sixth - including yours, if
five are already open. That is the intended behaviour of the rule, and the
reason it is not the default, though it is a far smaller trap at 5 than at the
2 this script pushed before.
"""

import argparse
import re

import netauto

# Every fix here is a single global line, idempotent, and safe to push whether
# or not it is already present.
LOGGING_FIXES = {
    'V-220528/220580 (log timestamps)': 'service timestamps log datetime localtime',
    'V-220547/220599 (logging buffer size)': 'logging buffered 64000 informational',
    'V-220560/220612a (log on-failure)': 'login on-failure log',
    'V-220560/220612b (log on-success)': 'login on-success log',
    'V-220526/220578 (admin activity logging)': 'logging userinfo',
    'V-220548/220600 (audit failure alert)': 'logging trap critical',
    # V-220531/532/533 protect persistent log files. They are NOT APPLICABLE
    # until `logging persistent` is configured, which nothing here pushes -
    # this only ensures that if it ever is, the files are already privileged
    # correctly rather than being written world-readable first.
    'V-220531/532/533 (file privilege 15)': 'file privilege 15',
}

ACCESS_CONTROL_FIXES = {
    # Two attempts is what the bulk walker allows itself, deliberately under
    # the three that trip this - see capture_l2s_bulk.LOGIN_ATTEMPTS.
    'V-220524/220576 (lockout after 3 failed attempts)':
        'login block-for 900 attempts 3 within 120',
}

# V-220555/220607 and V-220556/220608: SSH transport crypto. Global config
# lines, nothing per-interface, and nothing that changes how the switch
# forwards - but they do change how you log into it, so read the note below.
#
# The MAC line is DISA's V-220555 example verbatim. The encryption line is not:
# V-220556's example reads `aes256-ctr aes192-ctr aes128-ctr`. Its finding
# sentence asks for "a FIPS 140-2 approved algorithm", not for that list, and
# AES-GCM (SP 800-38D) and AES-CTR (SP 800-38A) are both approved - so
# `aes256-gcm aes256-ctr` satisfies the rule as written while offering less
# than the example does, not more. Kept identical to l2_stig_harden_global's
# SSH_ENCRYPTION_FIX, which is the same requirement pushed from the bulk pass.
#
# Both lines REPLACE the switch's algorithm list rather than adding to it:
#
#   * An image without `aes256-gcm` rejects the whole line and keeps the list
#     it had, so the rule stays a finding on a run that otherwise looks clean.
#     Netmiko does not treat a rejected command as fatal - check
#     `show running-config | include ip ssh` afterwards, or the SecureCRT
#     walk's rejected column.
#   * Where they are accepted, a client that cannot negotiate hmac-sha2-256 or
#     better, and aes256-ctr or better, no longer connects. Every current SSH
#     client can; anything that cannot is a client that should not be reaching
#     a DoD switch anyway.
SSH_CRYPTO_FIXES = {
    'V-220555/220556 (SSH version 2, which both rules require)': 'ip ssh version 2',
    'V-220555/220607 (FIPS-validated HMAC, session integrity)':
        'ip ssh server algorithm mac hmac-sha2-512 hmac-sha2-256',
    'V-220556/220608 (FIPS-approved encryption, session confidentiality)':
        'ip ssh server algorithm encryption aes256-gcm aes256-ctr',
}

# One block, eight rules - DISA reuses the same evidence for every one of them.
#
# The two trailing exits are not decoration. This descends two sub-modes -
# `archive`, then `log config` - and everything after it in the batch is a
# global-config command. IOS will usually fall back to a parent mode for a
# command the current one does not know, which is why a block written without
# them appears to work, but "usually" is doing real work in that sentence and
# the cost of being wrong is the vty and console fixes silently not landing.
# Netmiko sends this list flat and navigates nothing on its own.
ARCHIVE_LOGGING_FIX = [
    'archive',
    'log config',
    'logging enable',
    'logging size 1000',
    'notify syslog contenttype plaintext',
    'hidekeys',
    'exit',
    'exit',
]

# The organization-defined number, which is what the rule actually asks for:
# its finding sentence is only "if the switch is not configured to limit the
# number of concurrent management sessions". The 2 in DISA's example is an
# example. 5 is the number the rest of this project already pushes -
# l2_stig_harden_global, ios_router_stig_harden_global and
# nxos_stig_harden_global all use `line vty 0 4` / `session-limit 5` - and one
# project pushing two different limits for the same requirement is the kind of
# inconsistency an assessor asks about.
CONCURRENT_SESSIONS = 5

# exec-timeout must be nonzero and <= 5 minutes: `0 0` disables the timeout
# entirely, which is non-compliant rather than exempt. The console line needs
# it as much as vty - DISA's Fix Text configures both, and an un-set console
# sits at IOS's 10-minute default forever.
EXEC_TIMEOUT = 'exec-timeout 5 0'


def _line_range(first, last):
    """`line vty 0 4`, or `line vty 4` where the range is a single line."""
    return f'line vty {first} {last}' if last > first else f'line vty {first}'


def vty_fixes(highest_vty, sessions=CONCURRENT_SESSIONS):
    """The vty lines, in the order they must be sent. Off by default - see
    --with-vty.

    `highest_vty` is read off the switch rather than assumed, and that is the
    whole reason this takes an argument. What actually caps inbound management
    sessions is how many vty lines will answer, so a limit of 5 means five
    lines answering and the rest out of service. IOS XE ships `line vty 0 4`
    AND `line vty 5 15`: a script that configures 0-4 and stops leaves eleven
    more answering, and its claim of a five-session limit is false on a switch
    that will hold sixteen. Whatever the highest configured line is, everything
    above the allowed count is taken out of service.

    `session-limit` goes on the full range first, so it is on every line an
    assessor looks at, and the split follows - which means no line is ever left
    without one."""
    last_open = sessions - 1
    if last_open >= highest_vty:
        # Every line the switch has is inside the allowed count, so there is
        # nothing to take out of service and no second range to enter. On a
        # switch with only `line vty 0 4` and a limit of 5, this is DISA's
        # first example verbatim.
        return [_line_range(0, highest_vty), f'session-limit {sessions}', EXEC_TIMEOUT,
                'transport input ssh']
    return [
        _line_range(0, highest_vty),
        f'session-limit {sessions}',
        EXEC_TIMEOUT,
        _line_range(0, last_open),
        'transport input ssh',
        _line_range(last_open + 1, highest_vty),
        'transport input none',
    ]


def highest_vty_line(net_connect):
    """The highest vty line number the switch actually has configured.

    Falls back to 4 - DISA's own example range - if nothing can be read, which
    keeps the script working against a device that answers this oddly rather
    than having it push nothing. The fallback is reported, never silent: a
    wrong answer here is lines left answering that the run claims are closed."""
    try:
        output = net_connect.send_command('show running-config | include ^line vty')
    except Exception:
        return 4, False
    numbers = [int(n) for line in (output or '').splitlines()
               for n in re.findall(r'\d+', line)]
    return (max(numbers), True) if numbers else (4, False)



# The console line is not the vty lines and is not held back with them. An
# exec-timeout here can strand nobody: it ends an idle session at the physical
# console, which is the one place a locked-out switch is recovered from. Left
# un-set it sits at IOS's 10-minute default forever, which is the whole of
# V-220544's finding on that line.
CONSOLE_FIX = ['line con 0', EXEC_TIMEOUT]


parser = argparse.ArgumentParser(
    description='Push only the logging/audit and access-control L2S STIG fixes to a device')
parser.add_argument('device', help='Device name as it appears in inventory.yaml (e.g. S1)')
parser.add_argument('--sessions', type=int, default=CONCURRENT_SESSIONS, metavar='N',
                    help=f'Concurrent management sessions to allow (default {CONCURRENT_SESSIONS}, '
                         "DISA's own example). The rule is an organization-defined number, so "
                         'raise it if your organization defined a different one - but the switch '
                         'will refuse the N+1th SSH session, including yours.')
parser.add_argument('--with-vty', action='store_true', dest='with_vty',
                    help='Also push the vty session limit and vty exec-timeout (V-220518/220570 '
                         'and the vty half of V-220544/220596). OFF by default, because it is the '
                         'only part of this script that decides how many may log in afterwards: it '
                         f'leaves the switch answering on {CONCURRENT_SESSIONS} vty lines, so the '
                         'next SSH session is refused. Run it with console access to hand, or a '
                         'second known-good path '
                         'to the switch. Everything else here is reversible from any session.')
parser.add_argument('--dry-run', action='store_true',
                    help='Print the commands and exit without connecting to anything.')
args = parser.parse_args()

if not 1 <= args.sessions <= 5:
    raise SystemExit(f'--sessions must be between 1 and 5 (there are 5 vty lines, 0-4); '
                     f'got {args.sessions}')
if args.sessions != CONCURRENT_SESSIONS and not args.with_vty:
    raise SystemExit('--sessions only means anything with --with-vty, which is off by default; '
                     'without it no vty line is touched at all.')

services = netauto.load_services()
syslog_servers = services.get('syslog_servers') or []

applied_fixes = dict(LOGGING_FIXES)
applied_fixes.update(ACCESS_CONTROL_FIXES)
applied_fixes.update(SSH_CRYPTO_FIXES)
applied_fixes['V-220519/520/521/522/530/545/559/561 (archive logging)'] = \
    '; '.join(ARCHIVE_LOGGING_FIX)
applied_fixes['V-220544/220596 (console exec-timeout)'] = '; '.join(CONSOLE_FIX)

commands = list(LOGGING_FIXES.values()) + list(ACCESS_CONTROL_FIXES.values())
commands += list(SSH_CRYPTO_FIXES.values())
commands += ARCHIVE_LOGGING_FIX

# DISA asks for two syslog servers, so one configured server is reported rather
# than pushed as though it satisfied the rule.
if len(syslog_servers) >= 2:
    commands += [f'logging host {ip}' for ip in syslog_servers]
    applied_fixes['V-220568/220620 (dual syslog servers)'] = \
        '; '.join(f'logging host {ip}' for ip in syslog_servers)

commands += CONSOLE_FIX

# What is left undone by not pushing the vty lines, said here rather than
# discovered in the next audit. Both rules stay findings until they are run:
# V-220518 has nothing else that could satisfy it, and V-220544 asks for the
# timeout on vty as well as console.
UNADDRESSED_WITHOUT_VTY = (
    'V-220518/220570 (concurrent session limit) - nothing else satisfies it',
    'V-220544/220596 (exec-timeout) - console only; the vty half is still a finding',
)

if args.dry_run:
    print('Dry run - nothing was connected to and nothing was pushed.\n')
    print('Commands that would be sent:')
    for command in commands:
        print('  ' + command)
    if args.with_vty:
        # The real run reads the highest vty line off the switch first, so the
        # range shown here is DISA's example rather than a promise about yours.
        print('\nPlus the vty block, whose range is read off the switch at run time. '
              'Against a switch configured `line vty 0 4` it would be:')
        for command in vty_fixes(4, args.sessions):
            print('  ' + command)
        print(f'\nOn a switch that also has `line vty 5 15` - the IOS XE default - the closing '
              f'range covers those too, or the {args.sessions}-session limit would be untrue.')
    else:
        print('\nNo vty line is touched, so nothing here can change who may log in.')
        print('Still a finding afterwards, until --with-vty is run:')
        for rule in UNADDRESSED_WITHOUT_VTY:
            print('  ' + rule)
    raise SystemExit(0)

all_devices = netauto.load_inventory()
device_info = netauto.require_devices(all_devices, [device_name := args.device])[device_name]
username, password = netauto.get_credentials()

net_connect = netauto.connect(device_name, device_info, username, password)
if net_connect is None:
    raise SystemExit(1)

# Read before writing, and only for this: how many vty lines the switch has.
# Appended last, because everything above is reversible from any session that
# can reach the switch and this decides which sessions there can be.
highest_vty, read_ok = 4, True
if args.with_vty:
    highest_vty, read_ok = highest_vty_line(net_connect)
    if not read_ok:
        print('Could not read the vty ranges from the switch; assuming `line vty 0 4`, '
              "DISA's example. If this switch also has `line vty 5 15` those lines will be "
              'left answering and the session limit below will not be true - check by hand.')
    vty_commands = vty_fixes(highest_vty, args.sessions)
    commands += vty_commands
    applied_fixes['V-220518/220570 + V-220544/220596 (vty session limit + exec-timeout)'] = \
        '; '.join(vty_commands)

net_connect.send_config_set(commands)
netauto.log_push('l2_stig_harden_logging_access.py', device_name, username, commands)

print(f'Logging/audit and access-control fixes pushed to {device_name}:\n')
for label in sorted(applied_fixes):
    print(f'  {label}\n      {netauto.redact_secrets(applied_fixes[label])}')

if len(syslog_servers) < 2:
    print(f'\nSkipped V-220568/220620 (dual syslog servers) - {len(syslog_servers)} configured in '
          "inventory.yaml's services section, and the rule asks for two.")

if args.with_vty:
    closed = 'none' if args.sessions > highest_vty else f'{args.sessions}-{highest_vty}'
    print(f'\nThe switch now accepts {args.sessions} concurrent SSH session(s): vty '
          f'0-{args.sessions - 1} answer SSH, vty {closed} answer nothing '
          f'(read from the switch: its highest vty line is {highest_vty}). A further session is '
          'refused - verify you can still open a new one before closing this session.')
else:
    print('\nNo vty line was touched, so who may log in is exactly as it was.')
    print('Still a finding, until this is re-run with --with-vty:')
    for rule in UNADDRESSED_WITHOUT_VTY:
        print('  ' + rule)

print('\nNothing here was written to startup-config. Re-audit first, then run save_config.py.')

# Left open deliberately when the vty lines were touched: if the session limit
# locked something out, the way back is a session that already exists, and
# closing this one first would take that away.
if args.with_vty:
    print(f'\nThe connection to {device_name} is still open for that reason; close it yourself '
          'once a new session has been proved to work.')
net_connect.disconnect()
