#!/usr/bin/env python
"""Push the global (non-interface-scoped) hardening fixes from the DISA
Cisco IOS Switch L2S STIG to a device. Interface-scoped fixes (UUFB, storm
control, PortFast/BPDU Guard, 802.1x/MAB, trunk trust/allowed-vlan/native
VLAN, Root Guard, disabled-port unused-VLAN reassignment) live in the
companion script l2_stig_harden_interfaces.py - run this script first
(it creates the native/unused/default-access VLANs in the database and
enables DHCP snooping globally), then run l2_stig_harden_interfaces.py.
V-220634 (IP Source Guard) is pushed separately by l2_stig_harden_ipsg.py,
and V-220635 (DAI) separately by l2_stig_harden_dai.py - both split out
because they only trust the DHCP snooping binding table, so a statically-
addressed host with no DHCP lease gets its traffic dropped once either is
pushed (see the static-host-binding gap tracked in project memory).
V-220623 (802.1x/MAB): the global prerequisites ('dot1x system-auth-control',
'aaa authentication dot1x default group radius') are pushed by
l2_stig_harden_aaa.py instead, not here - the latter needs aaa new-model
already active, which this script doesn't push (see that script's own
docstring for why).

IOS XE: every command below was compared against the IOS XE Switch STIG's own
Fix Text, and 15 of the 16 labelled fixes are configured identically in both
books - the scripts were written from the IOS book but are not IOS-specific.
The one real divergence is `mls qos` (V-220625), which does not exist on IOS
XE; it is commented at the line and rejected harmlessly there. `ip device
tracking` in OPTIONAL_FIXES is IOS-era too, but optional and unrelated to any
rule. Per-interface commands in the companion scripts (UUFB, storm control,
IPSG, DAI, DHCP snooping, 802.1x) were checked the same way and match the IOS
XE Fix Text verbatim."""

import argparse
import netauto
import stig_common

# Global (non-interface-specific) fixes always pushed by this script
BASE_FIXES = {
    'V-220630 (BPDU Guard)': 'spanning-tree portfast bpduguard default',
    'V-220631 (Loop Guard)': 'spanning-tree loopguard default',
    'V-220638 (Rapid-PVST)': 'spanning-tree mode rapid-pvst',
    'V-220639 (UDLD)': 'udld enable',
    'V-220637 (IGMP snooping)': 'ip igmp snooping',
    'V-220580 (log timestamps)': 'service timestamps log datetime localtime',
    'V-220599 (logging buffer size)': 'logging buffered 64000 informational',
    'V-220612a (log on-failure)': 'login on-failure log',
    'V-220612b (log on-success)': 'login on-success log',
    'V-220576 (lockout after 3 failed attempts)': 'login block-for 900 attempts 3 within 120',
    'V-220578 (admin activity logging)': 'logging userinfo',
    'V-220570a (HTTP session limit)': 'ip http max-connections 2',
    # IOS ONLY - `mls qos` does not exist on IOS XE, which uses MQC instead
    # (its V-220651 Fix Text configures DSCP class-maps, a bandwidth-reserving
    # policy-map, and service-policy on interfaces). Expect this one line to be
    # rejected on an IOS XE switch; Netmiko does not treat a rejected command
    # as fatal, so the rest of the batch still lands. Kept because it is
    # correct for classic IOS. IOS XE's V-220651 is deliberately NOT AUTOMATED
    # in the audit rather than answered by this - see ios_xe_rule_map.EXCLUDED.
    'V-220625 (QoS enabled, IOS only - rejected on IOS XE)': 'mls qos',
    'V-220595a (password encryption)': 'service password-encryption',
    'V-220600 (audit failure alert)': 'logging trap critical',
    # Confirmed live that this lab's vios_l2 rejects 'file privilege 15'
    # ("% Invalid input") - same category as UUFB/storm-control/mls
    # qos/security passwords min-length, kept for real hardware. Doesn't
    # affect the audit result here since V-220583/584/585 are conditional on
    # `logging persistent` (not pushed anywhere), which isn't configured.
    'V-220583/584/585 (file privilege 15)': 'file privilege 15',
}

# Not a STIG requirement - pushed for host visibility only. ARP-probes every
# L2 port and populates 'show ip device tracking all' with each host's
# IP/MAC/VLAN/interface, static or DHCP-assigned alike (unlike IP Source Guard,
# it doesn't rely on the DHCP snooping binding table).
#
# Also IOS-era: IOS XE replaced this with SISF (`device-tracking policy` /
# `device-tracking attach-policy`). Expect the legacy command to be rejected
# or deprecated on IOS XE - it is optional and nothing in the audit depends
# on it either way.
OPTIONAL_FIXES = {
    'IP Device Tracking (host visibility, not a STIG requirement; IOS-era, SISF on IOS XE)': 'ip device tracking',
}

# V-220570: session-limit needs its own "line vty 0 4" context. DISA's rule is
# "organization-defined number," not a fixed value - 5 concurrent sessions.
# V-220596: exec-timeout must be nonzero and <=5 min (stig_common.exec_timeout_ok) -
# "0 0" disables the timeout entirely, which is non-compliant, not exempt from it.
VTY_SESSION_LIMIT_FIX = ['line vty 0 4', 'session-limit 5', 'exec-timeout 5 0']

# V-220596 also requires the console line, not just vty (DISA's Fix Text
# configures both) - previously only vty was ever set, so the console line
# sat at IOS's un-set default (10 min, non-compliant) indefinitely.
CONSOLE_EXEC_TIMEOUT_FIX = ['line con 0', 'exec-timeout 5 0']

# V-220607/608: SSH MAC (integrity) and encryption (confidentiality) algorithms.
# Both need "ip ssh version 2" - previously only the encryption line was pushed
# on the mistaken assumption it would satisfy V-220607 too, but V-220607's audit
# check looks at the separate `algorithm mac` line specifically, so it always
# failed live until this was added.
SSH_ENCRYPTION_FIX = [
    'ip ssh version 2',
    'ip ssh server algorithm mac hmac-sha2-256',
    'ip ssh server algorithm encryption aes256-ctr aes192-ctr aes128-ctr',
]

# V-220586: disable unnecessary/nonsecure services - idempotent, safe to push
# unconditionally even when a service is already disabled
UNNECESSARY_SERVICES_FIX = [
    'no boot network',
    'no ip boot server',
    'no ip bootp server',
    'no ip dns server',
    'no ip identd',
    'no ip finger',
    'no ip http server',
    'no ip rcmd rcp-enable',
    'no ip rcmd rsh-enable',
    'no service config',
    'no service finger',
    'no service tcp-small-servers',
    'no service udp-small-servers',
    'no service pad',
    'no service call-home',
]

# V-220571/572/573/574/582/597/611/613: config-change archive logging satisfies
# all 8 rules at once (DISA reuses the exact same evidence for each)
ARCHIVE_LOGGING_FIX = [
    'archive',
    'log config',
    'logging enable',
    'logging size 1000',
    'notify syslog contenttype plaintext',
    'hidekeys',
]

# Parse the target device from the command line
parser = argparse.ArgumentParser(description='Push global L2S STIG hardening fixes to a device from inventory.yaml')
parser.add_argument('device', help='Device name as it appears in inventory.yaml (e.g. S1)')
args = parser.parse_args()

device_name = args.device

# Load the target device from the YAML inventory
all_devices = netauto.load_inventory()
device_info = netauto.require_devices(all_devices, [device_name])[device_name]

# Prompt for credentials
username, password = netauto.get_credentials()

# VTP password (V-220624) comes from secrets.yaml instead of a prompt (gitignored,
# never committed - see secrets.yaml.example)
secrets = netauto.load_secrets()
vtp_password = str(secrets.get('vtp_password') or '').strip()

# SNMPv3 auth/priv passwords (V-220604/605) come from secrets.yaml. Config-only
# push - no SNMP monitoring station in this lab to actually poll it, this is
# purely to satisfy the audit. SHA for auth (FIPS-validated HMAC, V-220604) and
# AES for priv (FIPS 140-2 approved, V-220605) - "v3 priv" implies auth too, so
# one group/user satisfies both rules.
SNMPV3_GROUP = 'SNMPV3_GROUP'
SNMPV3_USER = 'SNMPV3_USER'
snmpv3 = secrets.get('snmpv3') or {}
snmp_auth_password = str(snmpv3.get('auth_password') or '').strip()
snmp_priv_password = str(snmpv3.get('priv_password') or '').strip()

# Connect, bailing out if it fails
net_connect = netauto.connect(device_name, device_info, username, password)
if net_connect is None:
    raise SystemExit(1)

# Discover the switch's user VLANs (V-220633: DHCP snooping, V-220635: DAI),
# excluding management/servers/unused VLANs from inventory.yaml's non_user_vlans
vlan_ids = stig_common.discover_user_vlans(net_connect, exclude=netauto.load_non_user_vlans(),
                                           exclude_names=netauto.load_non_user_vlan_names(),
                                           include_names=netauto.load_user_vlan_names())

# V-220641's unused VLAN and V-220646's native VLAN come from inventory.yaml -
# only their VLAN-database entries are created here, the per-port
# assignment/trust is pushed by the companion l2_stig_harden_interfaces.py.
unused_vlan = netauto.load_unused_vlan()
native_vlan_id = netauto.load_native_vlan()

# Create the native/unused VLAN in the VLAN database itself, named NATIVE.
# Referencing it on interfaces (switchport trunk native vlan / switchport
# access vlan) doesn't create a VLAN database entry by itself, so without
# this it never shows up in `show vlan brief`. Must explicitly 'exit' the
# 'vlan <id>' sub-mode, not just leave it hanging - the remaining commands
# in this script assume global config context, and Netmiko sends this whole
# list as one flat sequence.
#
# Not a STIG requirement, but pushed first: in VTP server mode (the Cisco
# default), VLAN database entries live in a separate vlan.dat file on flash,
# not in the running-config/startup-config text - confirmed live that VLAN
# 999/NATIVE never once appeared in `show running-config` even right after
# being pushed, and was lost entirely on a reload of S3 despite `copy
# running-config startup-config` (which never saves vlan.dat). 'vtp mode
# transparent' makes VLAN config part of the regular running-config instead,
# so it saves/persists the normal way - also has the effect of disabling
# VTP's own database-synchronization behavior between switches.
native_vlan_commands = ['vtp mode transparent', f'vlan {native_vlan_id}', 'name NATIVE', 'exit'] if native_vlan_id else []

# Default VLAN for host-facing/access ports (comes from inventory.yaml instead
# of a prompt). A freshly built port has no explicit switchport mode/VLAN at
# all, which silently breaks other access-port fixes that require the port to
# already be in access mode first - confirmed live on a fresh S3 in GNS3.
# Every non-trunk port gets 'switchport mode access' + this VLAN explicitly;
# the VLAN itself is created in the database the same way as native_vlan_id
# above (needs 'vtp mode transparent' too, already pushed by native_vlan_commands
# if that ran - if native_vlan_id isn't set this pushes its own copy).
default_access_vlan = netauto.load_default_access_vlan()
access_vlan_commands = []
if default_access_vlan:
    if not native_vlan_commands:
        access_vlan_commands.append('vtp mode transparent')
    access_vlan_commands += [f'vlan {default_access_vlan}', 'name USER', 'exit']

# unused_vlan's own database entry - needed now that it's a deliberately
# different VLAN from native_vlan_id (previously the same ID by convention,
# so native_vlan_commands covered both implicitly). Split apart because
# NX-OS's counterpart hit a literal conflict: DISA's "no switchport on the
# native VLAN" rule is worded as a finding for ANY access port sharing the
# native VLAN's ID, with no carve-out for administratively-shutdown ports -
# and V-220641 assigns disabled ports to unused_vlan, so it can no longer
# share native_vlan_id's number.
unused_vlan_commands = []
if unused_vlan:
    if not native_vlan_commands and not access_vlan_commands:
        unused_vlan_commands.append('vtp mode transparent')
    unused_vlan_commands += [f'vlan {unused_vlan}', 'name UNUSED', 'exit']

snmpv3_commands = []
if snmp_auth_password and snmp_priv_password:
    snmpv3_commands = [
        f'snmp-server group {SNMPV3_GROUP} v3 priv',
        f'snmp-server user {SNMPV3_USER} {SNMPV3_GROUP} v3 auth sha {snmp_auth_password} priv aes 128 {snmp_priv_password}',
    ]

# NTP/syslog server IPs (V-220601, V-220620) come from inventory.yaml's services
# section. NTP authentication key (V-220606) comes from secrets.yaml.
services = netauto.load_services()
ntp_servers = services.get('ntp_servers', [])
syslog_servers = services.get('syslog_servers', [])
ntp_auth_key = secrets.get('ntp_auth_key') or {}
ntp_key_id = ntp_auth_key.get('id')
ntp_key_value = ntp_auth_key.get('value')
if not ntp_key_value:
    ntp_key_id = None

ntp_commands = []
if ntp_key_id:
    ntp_commands += [
        f'ntp authentication-key {ntp_key_id} md5 {ntp_key_value}',
        'ntp authenticate',
        f'ntp trusted-key {ntp_key_id}',
    ]
if ntp_servers:
    key_suffix = f' key {ntp_key_id}' if ntp_key_id else ''
    ntp_commands += [f'ntp server {ip}{key_suffix}' for ip in ntp_servers]

# AAA/RADIUS (V-220587/617) is pushed by the separate l2_stig_harden_aaa.py
# script, not here - bundling aaa new-model in with this script's ~60-command
# batch caused a live session to drop on S2 right after aaa new-model took
# effect, before the rest of the block could send, leaving the device
# half-configured and SSH-inaccessible (recovered via console + 'no aaa
# new-model'). Keeping it isolated makes it safer to push and easier to
# diagnose if it ever fails again.

applied_fixes = dict(BASE_FIXES)
applied_fixes.update(OPTIONAL_FIXES)
applied_fixes['V-220586 (unnecessary services)'] = '; '.join(UNNECESSARY_SERVICES_FIX)
applied_fixes['V-220607/608 (SSH MAC + encryption)'] = '; '.join(SSH_ENCRYPTION_FIX)
applied_fixes['V-220571/572/573/574/582/597/611/613 (archive logging)'] = '; '.join(ARCHIVE_LOGGING_FIX)
applied_fixes['V-220570b/596 (VTY session limit + exec-timeout)'] = '; '.join(VTY_SESSION_LIMIT_FIX)
applied_fixes['V-220596b (console exec-timeout)'] = '; '.join(CONSOLE_EXEC_TIMEOUT_FIX)
if vlan_ids:
    applied_fixes['V-220633 (DHCP snooping)'] = (
        f'ip dhcp snooping; ip dhcp snooping vlan {",".join(vlan_ids)}; no ip dhcp snooping information option'
    )
if vtp_password:
    applied_fixes['V-220624 (VTP authentication)'] = f'vtp password {vtp_password}'
if native_vlan_commands:
    applied_fixes['Native VLAN database entry'] = '; '.join(native_vlan_commands)
if access_vlan_commands:
    applied_fixes['Default access VLAN database entry'] = '; '.join(access_vlan_commands)
if unused_vlan_commands:
    applied_fixes['Unused VLAN database entry'] = '; '.join(unused_vlan_commands)
if snmpv3_commands:
    applied_fixes['V-220604/605 (SNMPv3 auth/priv)'] = f'snmp-server group {SNMPV3_GROUP} v3 priv; snmp-server user {SNMPV3_USER} ... v3 auth sha ... priv aes 128 ...'
if ntp_servers:
    applied_fixes['V-220601 (NTP time sync)'] = '; '.join(
        f'ntp server {ip}' + (f' key {ntp_key_id}' if ntp_key_id else '') for ip in ntp_servers)
if ntp_key_id:
    applied_fixes['V-220606 (NTP authentication)'] = '; '.join([
        f'ntp authentication-key {ntp_key_id} md5 {ntp_key_value}', 'ntp authenticate', f'ntp trusted-key {ntp_key_id}'])
if syslog_servers:
    applied_fixes['V-220620 (dual syslog servers)'] = '; '.join(f'logging host {ip}' for ip in syslog_servers)

commands = list(BASE_FIXES.values()) + list(OPTIONAL_FIXES.values()) + UNNECESSARY_SERVICES_FIX + SSH_ENCRYPTION_FIX + ARCHIVE_LOGGING_FIX + VTY_SESSION_LIMIT_FIX + CONSOLE_EXEC_TIMEOUT_FIX
if vlan_ids:
    # `information option` (Option 82 relay-agent info insertion) is on by
    # default once DHCP snooping is enabled - turned off here since some DHCP
    # servers/relays reject or mishandle it, and V-220633 doesn't require it.
    commands += [
        'ip dhcp snooping',
        f'ip dhcp snooping vlan {",".join(vlan_ids)}',
        'no ip dhcp snooping information option',
    ]
# Order here doesn't functionally matter for vtp password - turned out V-220624
# was a false FAIL all along (VTP passwords are deliberately excluded from
# `show running-config` on Cisco IOS, confirmed live via `show vtp password`
# showing it set correctly regardless of push order - see l2_stig_audit.py's
# _vtp_password_check). Keeping native_vlan_commands first anyway since it's
# still the more sensible order (mode/VLAN setup before other global config).
commands += native_vlan_commands
if vtp_password:
    commands.append(f'vtp password {vtp_password}')
commands += access_vlan_commands
commands += unused_vlan_commands
commands += snmpv3_commands
commands += ntp_commands
commands += [f'logging host {ip}' for ip in syslog_servers]

# Push the hardening commands and close the session
output = net_connect.send_config_set(commands)
net_connect.disconnect()
netauto.log_push('l2_stig_harden_global.py', device_name, username, commands)

print(f'Hardening commands pushed to {device_name}:')
for command in commands:
    print('  ' + netauto.redact_secrets(command))
print()
print(netauto.redact_output(output))

print(f'\nRules addressed by this pass:')
for rule in applied_fixes:
    print('  - ' + rule)
print('\nIP Device Tracking pushed - view results with `show ip device tracking all` on the device.')

if not default_access_vlan:
    print('\nSkipped default access VLAN database entry - add default_access_vlan to inventory.yaml to include it.')
if not (snmp_auth_password and snmp_priv_password):
    print('\nSkipped V-220604/605 (SNMPv3 auth/priv) - add snmpv3.auth_password and snmpv3.priv_password to secrets.yaml to include it.')
if not unused_vlan:
    print('\nSkipped unused VLAN database entry - add unused_vlan to inventory.yaml to include it.')
if not native_vlan_id:
    print('\nSkipped native VLAN database entry - add native_vlan to inventory.yaml to include it.')
if not vtp_password:
    print('\nSkipped V-220624 (VTP authentication) - add vtp_password to secrets.yaml to include it.')
if not ntp_servers:
    print('\nSkipped V-220601 (NTP time sync) - add ntp_servers to inventory.yaml\'s services section to include it.')
if not syslog_servers:
    print('\nSkipped V-220620 (dual syslog servers) - add syslog_servers to inventory.yaml\'s services section to include it.')
if not ntp_key_id:
    print('\nSkipped V-220606 (NTP authentication) - add ntp_auth_key to secrets.yaml to include it.')

print('\nV-220634 (IP Source Guard) is pushed separately by l2_stig_harden_ipsg.py.')
print('V-220635 (DAI) is pushed separately by l2_stig_harden_dai.py.')
print('V-220587/617 (AAA new-model + RADIUS auth) is pushed separately by l2_stig_harden_aaa.py.')
print('V-220623a/b (dot1x system-auth-control + AAA method) is pushed separately by l2_stig_harden_aaa.py.')

print(
    '\nNext: run l2_stig_harden_interfaces.py to push the interface-scoped fixes '
    '(V-220629/630/632/633b/635b/636/640/641a/643/646/623b, plus V-220642/645 as a side effect).'
)
