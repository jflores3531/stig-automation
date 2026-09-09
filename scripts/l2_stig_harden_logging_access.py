#!/usr/bin/env python
"""Push only the logging/audit and access-control fixes from the Cisco L2S
STIG - the two areas that change no forwarding behaviour.

Why this exists beside l2_stig_harden_global.py, which already pushes all of
these: that script also pushes spanning-tree mode, UDLD, IGMP snooping, VLAN
database entries, `vtp mode transparent`, SNMPv3, NTP and fifteen `no <service>`
lines. Every one of those can change how a switch forwards, converges or
answers, and on a production fleet that is a change window and a rollback plan.
Nothing here touches the data plane at all: it writes log destinations, log
content, and the terms under which a session may be opened to the switch. The
worst case is a session limit set too tight, which is why the vty lines are
handled the way they are below.

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
    V-220518/220570   limit concurrent management sessions - see below
    V-220544/220596   exec-timeout on vty AND console

WHAT IT DELIBERATELY LEAVES OUT
`service password-encryption`, the SSH cipher/MAC lines, and the vty management
ACL. The first two are credential and transport protection rather than either
of the areas asked for; the ACL is its own script on purpose, because an
access-class that omits the automation host locks this machine out of every
future run.

THE SESSION LIMIT, AND WHY IT IS NOT JUST `session-limit 2`
The rule is "an organization-defined number", and its finding sentence is only
"If the switch is not configured to limit the number of concurrent management
sessions, this is a finding" - so 2 is the number DISA's own example uses, not
a maximum the STIG imposes. It is still the right number to push, because it is
what an assessor reads in the Fix Text.

DISA gives three mechanisms and this pushes two of them:

  `ip http max-connections 2` is NOT pushed. It configures a limit on a server
  that hardening turns off - `no ip http server` - so on a hardened switch it
  is a number attached to nothing. The audit accepts it, which is how it ended
  up in the bulk script; that does not make it a control.

  `session-limit 2` under `line vty 0 4` is pushed, because the Fix Text shows
  it and an assessor will look for it. Worth knowing what it actually does:
  on IOS this limits the sessions a user *on that line* may open outward, not
  the number of inbound management sessions. It satisfies the rule as written.

  Reducing the usable vty lines is what actually caps concurrent inbound
  sessions, and it is the method DISA's Fix Text leads with: vty 0-1 answer
  SSH, vty 2-4 answer nothing. Two lines, two sessions, enforced by the switch
  rather than by a per-line counter.

Both are pushed, in that order, so the switch is compliant by the letter and
limited in fact. The risk is real and worth stating plainly: after this, the
switch accepts two SSH sessions. A third is refused - including yours, if two
are already open. That is the intended behaviour of the rule.
"""

import argparse

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

# The number DISA's example uses. Not a maximum the STIG imposes - the rule
# says "organization-defined" - but the number an assessor reads in the Fix
# Text, so the one to push absent a local decision to the contrary.
CONCURRENT_SESSIONS = 2

# exec-timeout must be nonzero and <= 5 minutes: `0 0` disables the timeout
# entirely, which is non-compliant rather than exempt. The console line needs
# it as much as vty - DISA's Fix Text configures both, and an un-set console
# sits at IOS's 10-minute default forever.
EXEC_TIMEOUT = 'exec-timeout 5 0'


def vty_fixes(sessions=CONCURRENT_SESSIONS):
    """The vty and console lines, in the order they must be sent.

    `session-limit` first, on the full range, so it is on every line an
    assessor looks at. Then the range is split: the first `sessions` lines
    answer SSH, the rest answer nothing. Splitting after setting the limit
    means no line is ever left without one."""
    last_open = sessions - 1
    commands = [
        'line vty 0 4',
        f'session-limit {sessions}',
        EXEC_TIMEOUT,
        'transport input ssh',
        f'line vty 0 {last_open}' if last_open else 'line vty 0',
        'transport input ssh',
    ]
    if last_open < 4:
        commands += [
            f'line vty {last_open + 1} 4' if last_open + 1 < 4 else 'line vty 4',
            'transport input none',
        ]
    commands += ['line con 0', EXEC_TIMEOUT]
    return commands


parser = argparse.ArgumentParser(
    description='Push only the logging/audit and access-control L2S STIG fixes to a device')
parser.add_argument('device', help='Device name as it appears in inventory.yaml (e.g. S1)')
parser.add_argument('--sessions', type=int, default=CONCURRENT_SESSIONS, metavar='N',
                    help=f'Concurrent management sessions to allow (default {CONCURRENT_SESSIONS}, '
                         "DISA's own example). The rule is an organization-defined number, so "
                         'raise it if your organization defined a different one - but the switch '
                         'will refuse the N+1th SSH session, including yours.')
parser.add_argument('--dry-run', action='store_true',
                    help='Print the commands and exit without connecting to anything. Worth doing '
                         'first: the vty changes below decide who can log in afterwards.')
args = parser.parse_args()

if not 1 <= args.sessions <= 5:
    raise SystemExit(f'--sessions must be between 1 and 5 (there are 5 vty lines, 0-4); '
                     f'got {args.sessions}')

services = netauto.load_services()
syslog_servers = services.get('syslog_servers') or []

applied_fixes = dict(LOGGING_FIXES)
applied_fixes.update(ACCESS_CONTROL_FIXES)
applied_fixes['V-220519/520/521/522/530/545/559/561 (archive logging)'] = \
    '; '.join(ARCHIVE_LOGGING_FIX)
applied_fixes['V-220518/220570 + V-220544/220596 (session limit + exec-timeout)'] = \
    '; '.join(vty_fixes(args.sessions))

commands = list(LOGGING_FIXES.values()) + list(ACCESS_CONTROL_FIXES.values())
commands += ARCHIVE_LOGGING_FIX

# DISA asks for two syslog servers, so one configured server is reported rather
# than pushed as though it satisfied the rule.
if len(syslog_servers) >= 2:
    commands += [f'logging host {ip}' for ip in syslog_servers]
    applied_fixes['V-220568/220620 (dual syslog servers)'] = \
        '; '.join(f'logging host {ip}' for ip in syslog_servers)

# Last, because everything above is reversible from any session and this
# decides which sessions there can be.
commands += vty_fixes(args.sessions)

if args.dry_run:
    print('Dry run - nothing was connected to and nothing was pushed.\n')
    print('Commands that would be sent:')
    for command in commands:
        print('  ' + command)
    print(f'\nAfter this the switch would accept {args.sessions} concurrent SSH session(s) '
          f'on vty 0-{args.sessions - 1}; vty {args.sessions}-4 would answer nothing.')
    raise SystemExit(0)

all_devices = netauto.load_inventory()
device_info = netauto.require_devices(all_devices, [device_name := args.device])[device_name]
username, password = netauto.get_credentials()

net_connect = netauto.connect(device_name, device_info, username, password)
if net_connect is None:
    raise SystemExit(1)

net_connect.send_config_set(commands)
netauto.log_push('l2_stig_harden_logging_access.py', device_name, username, commands)

print(f'Logging/audit and access-control fixes pushed to {device_name}:\n')
for label in sorted(applied_fixes):
    print(f'  {label}\n      {netauto.redact_secrets(applied_fixes[label])}')

if len(syslog_servers) < 2:
    print(f'\nSkipped V-220568/220620 (dual syslog servers) - {len(syslog_servers)} configured in '
          "inventory.yaml's services section, and the rule asks for two.")

print(f'\nThe switch now accepts {args.sessions} concurrent SSH session(s): vty '
      f'0-{args.sessions - 1} answer SSH, vty {args.sessions}-4 answer nothing. A further '
      'session is refused - verify you can still open a new one before closing this session.')
print('\nNothing here was written to startup-config. Re-audit first, then run save_config.py.')

# Left open deliberately. If the session limit locked something out, the way
# back is a session that already exists - closing this one first would take
# that away.
print(f'\nThe connection to {device_name} is still open for that reason; close it yourself once '
      'a new session has been proved to work.')
net_connect.disconnect()
