#!/usr/bin/env python
"""Push the global (non-interface-scoped) hardening fixes from the DISA
Cisco NX-OS Switch L2S STIG to a device. Interface-scoped fixes (UUFB, IP
Source Guard, storm control, trunk conversion, native VLAN, trunk VLAN
pruning) live in the companion script nxos_stig_harden_interfaces.py -
run this script first, then reload the device (needed for the TCAM regions
staged below to take effect), then run nxos_stig_harden_interfaces.py.
V-220681 (BPDU Guard) also pushes 'spanning-tree port type edge default' -
without it, the global bpduguard-default command has no edge ports to
activate on and is a functional no-op (same false-pass shape as L2S's
V-220630/PortFast). V-220493 (exec-timeout) uses NX-OS's single-argument
syntax ('exec-timeout <minutes>'), not IOS's two-argument form. V-220676
(VTP) requires a 'vtp domain' be set before 'vtp password' takes effect at
all on NX-OS - confirmed live on NXCore1 ("Domain not set" otherwise).
V-220689 (UDLD) only pushes 'feature udld' - 'udld enable' isn't valid
NX-OS syntax (confirmed live: "% Invalid command"), an IOS-ism that doesn't
carry over; UDLD is on by default for fiber interfaces once the feature
itself is enabled.
V-220684 (DHCP snooping) and V-220686 (DAI) are pushed together, scoped to
the same discovered user VLANs. V-220685 (IP Source Guard, in the companion
script) depends on DHCP snooping already being active here - confirmed live
on NXCore1: pushing IPSG with no DHCP snooping enabled doesn't raise an
error, it just silently fails to take effect.
V-220685/686 also need dedicated TCAM regions carved out before they take
effect in hardware at all - staged here (see TCAM_FIX) but require a device
reload to actually apply, which this script deliberately does not perform.
VLAN 999 (the shared unused/native VLAN) is created here in the VLAN
database - needed before the companion script can assign it as a trunk's
native VLAN."""

import argparse
import netauto
import stig_common

# Global (non-interface-specific) fixes always pushed by this script
BASE_FIXES = {
    # 'spanning-tree port type edge bpduguard default' only activates BPDU
    # Guard on ports typed as "edge" (NX-OS's PortFast equivalent) - without
    # 'spanning-tree port type edge default' (the global equivalent of IOS's
    # 'spanning-tree portfast default'), the bpduguard-default command was
    # present in the config but functionally inert everywhere, since no port
    # was ever typed as edge (same false-pass shape as L2S's V-220630).
    'V-220681a (edge port type, required for BPDU Guard to activate)': 'spanning-tree port type edge default',
    'V-220681b (BPDU Guard)': 'spanning-tree port type edge bpduguard default',
    'V-220682 (Loop Guard)': 'spanning-tree loopguard default',
    'V-220688 (IGMP snooping)': 'ip igmp snooping',
    # Password complexity is on by default per the STIG's own Check Text -
    # 'password strength-check' is only needed to reverse a prior 'no
    # password strength-check', but pushing it unconditionally is a safe
    # no-op if complexity is already enforced. Single command covers all
    # four character-class rules (upper/lower/numeric/special) at once.
    'V-220489/490/491/492 (password complexity)': 'password strength-check',
    'V-220480 (SSH login attempts)': 'ssh login-attempts 3',
    # Check Text's example is 'logging logfile LOGFILE1 6 size nnnnn' -
    # 64000 bytes matches the buffer size l2_stig_harden_global.py already
    # uses for V-220599's 'logging buffered 64000 informational' (same
    # org-defined-size convention, level 6/informational too).
    'V-220496 (logfile size)': 'logging logfile STIG_LOGFILE 6 size 64000',
    # V-220486: Check Content only condemns telnet unconditionally ("should
    # never be enabled") - everything else in its example list "should only
    # be enabled if required for operations." 'feature dhcp' is deliberately
    # NOT included here even though Check Content lists it as an example -
    # this project requires it for DHCP snooping/V-220684 on NXCore1's
    # server-facing ports, a genuine operational need per the rule's own
    # carve-out. nxapi has no operational use anywhere in this project, so
    # it's disabled unconditionally alongside telnet - idempotent no-ops if
    # already absent, same as L2S's V-220586 pattern. 'no feature wccp' is
    # NOT pushed - confirmed live on NXCore1 that it's rejected outright
    # ("% Invalid command"), wccp isn't a supported feature on this
    # platform/image at all (telnet/nxapi both worked fine). Since it can
    # never be enabled here either, _no_unnecessary_features_check in
    # nxos_stig_audit.py still passes trivially without this push.
    'V-220486a (unnecessary services - telnet)': 'no feature telnet',
    'V-220486c (unnecessary services - nxapi)': 'no feature nxapi',
    # V-220510: admin session start/end logging - a plain presence check
    # (_dot1x_mab_check-style shared-evidence pattern doesn't apply here,
    # this is its own separate rule from the aaa-accounting-group cluster
    # nxos_stig_harden_aaa.py covers), verbatim from Check Text's example.
    'V-220510 (admin session logging)': 'logging level authpriv 6',
}

# V-220474: session-limit only applies under 'line vty' per the Check Text's
# own example (not 'line console') - kept separate from EXEC_TIMEOUT_FIX's
# console+vty pair rather than merged into it, since this one's scope is
# narrower.
#
# 5, not the Check Text example's 2 - the rule asks for an organization-defined
# limit and the audit only verifies that some limit is present, so the example
# value isn't binding. Same change L2S already made in bd210e1, and it matters
# more here: nxos_stig_harden_acl.py and nxos_stig_harden_aaa.py both hold a
# primary session open while opening a second one to verify new logins still
# work. A limit of 2 leaves no headroom for that, and the second session gets
# torn down right after authenticating - which surfaces as Netmiko's
# "Pattern not detected: '[>#]'" rather than a connection failure, and reads
# like a lockout the verification was designed to catch.
SESSION_LIMIT_FIX = ['line vty', 'session-limit 5']

# V-220488/503 (SSH MACs - both rules share the identical Fix Text example,
# filed under two different CCI categories). The Fix Text's own example
# ('ssh macs hmac-sha2-256 hmac-sha2-512') is an IOS-router-oriented example
# (prompt literally shows 'R1(config)#') that doesn't carry over: confirmed
# live on NXCore1 that 'ssh macs' takes exactly one algorithm name per
# invocation ('ssh macs hmac-sha2-256 ?' shows only <CR>), and both
# hmac-sha2-256/hmac-sha2-512 are already in NX-OS's default allow-list
# ("Config is already present" pushing either) - confirmed via
# `show running-config all | include macs`, since defaults never appear in
# plain `show running-config`. The rest of the default allow-list needs to
# be explicitly disabled to match: hmac-sha1/hmac-sha1-etm@openssh.com are
# genuinely weak (SHA-1, known collision attacks), while
# hmac-sha2-256-etm@openssh.com/hmac-sha2-512-etm@openssh.com are still
# SHA-2-based (not weak the same way) but outside the two algorithms DISA's
# Fix Text example names - disabled anyway so the allow-list matches that
# example exactly rather than leaving it to interpretation. Unlike the
# defaults, these 'no ssh macs ...' overrides DO show up in plain
# running-config, same as 'no password strength-check' does.
SSH_MACS_FIX = [
    'no ssh macs hmac-sha1',
    'no ssh macs hmac-sha1-etm@openssh.com',
    'no ssh macs hmac-sha2-256-etm@openssh.com',
    'no ssh macs hmac-sha2-512-etm@openssh.com',
]

# V-220504: same shape as SSH_MACS_FIX above - 'ssh ciphers aes128-ctr
# aes256-ctr' (Fix Text's example) doesn't work as a space-separated list
# on NX-OS either. Confirmed live on NXCore1 via `show ssh ciphers`:
# aes128-ctr/aes256-ctr are already permitted by default, alongside three
# others not named by DISA - aes256-gcm@openssh.com/aes128-gcm@openssh.com
# (still FIPS-validated per the platform's own table, just not the exact
# pair DISA names - disabled anyway, same treatment as the MACs sha2-etm
# variants) and chacha20-poly1305@openssh.com (confirmed FIPS=no on this
# platform). aes192-ctr/aes128-cbc/aes192-cbc/aes256-cbc are already denied
# by default (also confirmed live), so no push needed for those.
SSH_CIPHERS_FIX = [
    'no ssh ciphers aes256-gcm@openssh.com',
    'no ssh ciphers aes128-gcm@openssh.com',
    'no ssh ciphers chacha20-poly1305@openssh.com',
]

# V-220481: DoD-mandated banner text verbatim from the checklist's Fix/Check
# Text (identical wording in both - this is the one rule where DISA's text
# itself is the compliance requirement, not just an example). Delimited with
# '#' per the Fix Text's own example - safe since the banner text contains
# no '#' character itself, so it can't collide with the delimiter.
# Long paragraphs are wrapped across multiple lines matching the Fix Text's
# own '>' continuation breaks - confirmed live on NXCore1 that this isn't
# just document formatting: NX-OS rejects any single banner-entry line over
# ~256 chars with "input string too long" (silently dropping just that
# paragraph, not aborting the whole banner), so joining a wrapped paragraph
# back into one long line loses it entirely.
BANNER_TEXT = [
    'You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.',
    '',
    'By using this IS (which includes any device attached to this IS), you consent to the following conditions:',
    '',
    '-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to,',
    'penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law',
    'enforcement (LE), and counterintelligence (CI) investigations.',
    '',
    '-At any time, the USG may inspect and seize data stored on this IS.',
    '',
    '-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and',
    'search, and may be disclosed or used for any USG-authorized purpose.',
    '',
    '-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your',
    'personal benefit or privacy.',
    '',
    '-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or',
    'monitoring of the content of privileged communications, or work product, related to personal representation or services',
    'by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and',
    'confidential. See User Agreement for details.',
]
BANNER_FIX = ['banner motd #'] + BANNER_TEXT + ['#']

# V-220493: exec-timeout on both console and vty (DISA's Check Text configures
# both). NX-OS's exec-timeout takes a single argument (minutes only), unlike
# IOS's two-argument 'exec-timeout <min> <sec>' form - stig_common.exec_timeout_ok()
# assumes the IOS syntax and would never match real NX-OS config.
EXEC_TIMEOUT_FIX = ['line console', 'exec-timeout 5', 'line vty', 'exec-timeout 5']

# V-220689 (UDLD): 'udld enable' is not a valid NX-OS global command at all -
# confirmed live on NXCore1 ("% Invalid command"), an IOS-ism that doesn't
# carry over. Per the STIG's own Fix Text, 'feature udld' alone is sufficient -
# UDLD is enabled by default on every fiber interface once the feature itself
# is turned on, no separate enable command needed.
UDLD_FIX = ['feature udld']

# V-220685 (IP Source Guard) / V-220686 (DAI) need dedicated TCAM regions
# carved out before either feature actually takes effect on this platform -
# confirmed live on NXCore1 by the device's own error text ("IPSG tcam
# region is not configured. Please configure IPSG TCAM region and retry" /
# "arp-ether region is not configured. Please configure arp-ether region and
# retry"), which also names the exact region tokens NX-OS expects. Pushed
# unconditionally every run - carving is safe/idempotent even before there's
# a VLAN to apply IPSG/DAI to yet, and doing it proactively avoids needing a
# second future reload once one is added.
# IMPORTANT: TCAM carving changes don't take effect until the next device
# reload. This script stages the carving commands but deliberately does NOT
# reload the device - that's disruptive and needs to be a manual/scheduled
# step, not an automatic side effect of a hardening pass. Until that reload
# happens, V-220685/686 will keep failing even with vlan_ids non-empty and
# the carving already staged - expected, not a bug in this script.
TCAM_FIX = [
    'hardware access-list tcam region ipsg 256',        # V-220685 (IP Source Guard)
    'hardware access-list tcam region arp-ether 256',   # V-220686 (DAI)
]

# Parse the target device from the command line
parser = argparse.ArgumentParser(description='Push global L2S STIG hardening fixes to an NX-OS device from inventory.yaml')
parser.add_argument('device', help='Device name as it appears in inventory.yaml (e.g. NXCore1)')
args = parser.parse_args()

device_name = args.device

# Load the target device from the YAML inventory
all_devices = netauto.load_inventory()
device_info = netauto.require_devices(all_devices, [device_name])[device_name]

# Prompt for credentials
username, password = netauto.get_credentials()

# VTP password (V-220676) comes from secrets.yaml instead of a prompt (gitignored,
# never committed - see secrets.yaml.example). VTP domain comes from
# inventory.yaml - required on NX-OS before a password takes effect at all
# (confirmed live on NXCore1: 'vtp password ...' silently fails with "Domain
# not set" otherwise, and Netmiko doesn't treat that as fatal). Not needed on
# IOS L2S switches, which accept the password with no domain set.
secrets = netauto.load_secrets()
vtp_password = str(secrets.get('vtp_password') or '').strip()
vtp_domain = netauto.load_vtp_domain()

# SNMPv3 auth/priv passwords (V-220500/501) come from secrets.yaml - same
# snmpv3.auth_password/priv_password keys l2_stig_harden_global.py uses.
# Config-only push - no SNMP monitoring station in this lab to actually poll
# it, same as the L2S side. NX-OS's own syntax needs no separate
# 'snmp-server group ... v3 priv' step unlike IOS - the Check Text's own
# example creates just the user, defaulting to NX-OS's built-in
# 'network-operator' group when none is given.
SNMPV3_USER = 'SNMPV3_USER'
snmpv3 = secrets.get('snmpv3') or {}
snmp_auth_password = str(snmpv3.get('auth_password') or '').strip()
snmp_priv_password = str(snmpv3.get('priv_password') or '').strip()

# Connect, bailing out if it fails
net_connect = netauto.connect(device_name, device_info, username, password)
if net_connect is None:
    raise SystemExit(1)

unused_vlan = netauto.load_unused_vlan()
native_vlan_id = netauto.load_native_vlan()

# Discover the switch's user VLANs (V-220684: DHCP snooping, V-220686: DAI -
# same VLAN set for both), excluding management/servers/unused VLANs from
# inventory.yaml's non_user_vlans, plus unused_vlan/native_vlan (1000/999,
# deliberately different VLANs - see inventory.yaml) - not just
# non_user_vlans. Confirmed live on NXCore1: with no other VLANs in the
# database yet, a designated black-hole/native VLAN just created below was
# the only candidate and got misclassified as a genuine user VLAN, scoping
# DHCP snooping/DAI/IPSG to the wrong VLAN entirely.
# Passes device_name so NXCore1's non_user_vlans_by_device override
# (inventory.yaml) applies here - VLAN 100 is real server traffic on this
# device (Ethernet1/3-4), not infrastructure like on the L2S switches, so
# it's left out of that override and picked up here as a genuine user VLAN.
non_user_vlan_exclude = list(netauto.load_non_user_vlans(device_name=device_name))
if unused_vlan:
    non_user_vlan_exclude.append(unused_vlan)
if native_vlan_id:
    non_user_vlan_exclude.append(native_vlan_id)
vlan_ids = stig_common.discover_user_vlans(net_connect, exclude=non_user_vlan_exclude,
                                           exclude_names=netauto.load_non_user_vlan_names(),
                                           include_names=netauto.load_user_vlan_names())

# V-220695 (native VLAN): created in the VLAN database here so the companion
# script (nxos_stig_harden_interfaces.py) can assign it as a trunk's native
# VLAN. Same native_vlan value l2_stig_harden_global.py uses, currently 999.
native_vlan_commands = [f'vlan {native_vlan_id}', 'name NATIVE', 'exit'] if native_vlan_id else []

# V-220690: unused_vlan's own database entry - a deliberately different VLAN
# than native_vlan_id (see inventory.yaml for why) so the companion script's
# disabled-port assignment doesn't collide with V-220696's "no access port
# on the native VLAN" requirement.
unused_vlan_commands = [f'vlan {unused_vlan}', 'name UNUSED', 'exit'] if unused_vlan else []

# V-220516: syslog server IPs come from inventory.yaml's services section -
# same syslog_servers list l2_stig_harden_global.py uses (V-220620), already two
# entries so "at least two central log servers" is satisfied as-is. '6'
# is the informational severity level, matching the Fix Text's own example.
syslog_servers = netauto.load_services().get('syslog_servers', [])
syslog_commands = [f'logging server {ip} 6' for ip in syslog_servers]

# NTP server IPs (V-220498) come from inventory.yaml's services section. NTP
# authentication key (V-220502) comes from secrets.yaml.
ntp_servers = netauto.load_services().get('ntp_servers', [])
ntp_auth_key = secrets.get('ntp_auth_key') or {}
ntp_key_id = ntp_auth_key.get('id')
ntp_key_value = ntp_auth_key.get('value')
if not ntp_key_value:
    ntp_key_id = None

ntp_commands = []
if ntp_servers or ntp_key_id:
    ntp_commands.append('feature ntp')
if ntp_key_id:
    ntp_commands += [
        f'ntp authentication-key {ntp_key_id} md5 {ntp_key_value}',
        'ntp authenticate',
        f'ntp trusted-key {ntp_key_id}',
    ]
if ntp_servers:
    key_suffix = f' key {ntp_key_id}' if ntp_key_id else ''
    ntp_commands += [f'ntp server {ip}{key_suffix}' for ip in ntp_servers]

applied_fixes = dict(BASE_FIXES)
applied_fixes['V-220481 (DoD banner)'] = 'banner motd # <DoD-mandated notice text> #'
applied_fixes['V-220493 (exec-timeout)'] = '; '.join(EXEC_TIMEOUT_FIX)
applied_fixes['V-220474 (session limit)'] = '; '.join(SESSION_LIMIT_FIX)
applied_fixes['V-220488/503 (SSH MACs - FIPS-validated HMAC)'] = (
    '; '.join(SSH_MACS_FIX) + ' (hmac-sha2-256/512 already allowed by default; this disables the non-FIPS ones alongside them)'
)
applied_fixes['V-220504 (SSH ciphers - confidentiality)'] = (
    '; '.join(SSH_CIPHERS_FIX) + ' (aes128-ctr/aes256-ctr already allowed by default; this disables the rest alongside them)'
)
applied_fixes['V-220689 (UDLD)'] = '; '.join(UDLD_FIX)
applied_fixes['V-220685/686 (TCAM regions for IPSG/DAI) - STAGED, NEEDS RELOAD'] = (
    '; '.join(TCAM_FIX) + ' - takes effect only after the next device reload (not performed by this script)'
)
if vlan_ids:
    applied_fixes['V-220684 (DHCP snooping)'] = f'feature dhcp; ip dhcp snooping; ip dhcp snooping vlan {",".join(vlan_ids)}'
    applied_fixes['V-220686 (DAI)'] = f'ip arp inspection vlan {",".join(vlan_ids)}'
if vtp_password and vtp_domain:
    applied_fixes['V-220676 (VTP authentication)'] = (
        f'feature vtp; vtp domain {vtp_domain}; vtp password {vtp_password} '
        f'(no mode command - 9000v only supports VTP transparent mode)'
    )
if ntp_servers:
    applied_fixes['V-220498 (NTP time sync)'] = '; '.join(
        f'ntp server {ip}' + (f' key {ntp_key_id}' if ntp_key_id else '') for ip in ntp_servers)
if ntp_key_id:
    applied_fixes['V-220502 (NTP authentication)'] = '; '.join([
        f'ntp authentication-key {ntp_key_id} md5 {ntp_key_value}', 'ntp authenticate', f'ntp trusted-key {ntp_key_id}'])
if syslog_servers:
    applied_fixes['V-220516 (syslog servers)'] = '; '.join(syslog_commands)
if snmp_auth_password and snmp_priv_password:
    applied_fixes['V-220500/501 (SNMPv3 auth/priv)'] = (
        f'snmp-server user {SNMPV3_USER} auth sha ... priv aes-128 ... (defaults to the built-in network-operator group)'
    )

commands = list(BASE_FIXES.values()) + EXEC_TIMEOUT_FIX + SESSION_LIMIT_FIX + SSH_MACS_FIX + SSH_CIPHERS_FIX + UDLD_FIX + TCAM_FIX + BANNER_FIX + syslog_commands
if snmp_auth_password and snmp_priv_password:
    commands.append(f'snmp-server user {SNMPV3_USER} auth sha {snmp_auth_password} priv aes-128 {snmp_priv_password}')
if vlan_ids:
    commands += [
        'feature dhcp', 'ip dhcp snooping', f'ip dhcp snooping vlan {",".join(vlan_ids)}',
        f'ip arp inspection vlan {",".join(vlan_ids)}',  # V-220686 (DAI) - same VLAN set as DHCP snooping
    ]
commands += native_vlan_commands + unused_vlan_commands
if vtp_password and vtp_domain:
    # Domain must be set before the password takes effect - confirmed live
    # on NXCore1 ('vtp password ...' fails with "Domain not set" otherwise).
    # No 'vtp mode transparent' here: the Nexus 9000 series (including the
    # 9000v virtual platform this lab runs) supports VTP exclusively in
    # transparent mode - it's not a settable option, and pushing it is
    # rejected outright ("% Invalid command", confirmed live on NXCore1).
    # Transparent is already the only state, so the security property
    # l2_stig_harden_global.py's own 'vtp mode transparent' line achieves on IOS
    # (switch won't originate/relay VLAN database changes to peers) holds
    # here unconditionally, with nothing to push for it.
    commands += ['feature vtp', f'vtp domain {vtp_domain}', f'vtp password {vtp_password}']
commands += ntp_commands

# Push the hardening commands and close the session. read_timeout raised
# well above Netmiko's default - the multi-line banner push alone is slow
# enough on this device to trip the default before this script's global
# batch (no per-port loop here anymore, see nxos_stig_harden_interfaces.py)
# finishes.
output = net_connect.send_config_set(commands, read_timeout=180)
net_connect.disconnect()
netauto.log_push('nxos_stig_harden_global.py', device_name, username, commands)

print(f'Hardening commands pushed to {device_name}:')
for command in commands:
    print('  ' + netauto.redact_secrets(command))
print()
print(netauto.redact_output(output))

print(f'\nRules addressed by this pass:')
for rule in applied_fixes:
    print('  - ' + rule)

if vlan_ids:
    print(
        '\nV-220685 (IP Source Guard) and V-220686 (DAI) will keep failing an audit until '
        f'{device_name} is reloaded - the TCAM regions staged this run only take effect after '
        'the next reload. Schedule that separately; this script will not do it for you.'
    )

if not (vtp_password and vtp_domain):
    missing = []
    if not vtp_password:
        missing.append('vtp_password to secrets.yaml')
    if not vtp_domain:
        missing.append('vtp_domain to inventory.yaml')
    print(f'\nSkipped V-220676 (VTP authentication) - add {" and ".join(missing)} to include it.')
if not ntp_servers:
    print('\nSkipped V-220498 (NTP time sync) - add ntp_servers to inventory.yaml\'s services section to include it.')
if not ntp_key_id:
    print('\nSkipped V-220502 (NTP authentication) - add ntp_auth_key to secrets.yaml to include it.')
if not syslog_servers:
    print('\nSkipped V-220516 (syslog servers) - add syslog_servers to inventory.yaml\'s services section to include it.')
if not (snmp_auth_password and snmp_priv_password):
    print('\nSkipped V-220500/501 (SNMPv3 auth/priv) - add snmpv3.auth_password and snmpv3.priv_password to secrets.yaml to include it.')

print(
    '\nNext: reload the device, then run nxos_stig_harden_interfaces.py to push the interface-scoped '
    'fixes (V-220683/685/687/692/695).'
)
