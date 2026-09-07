#!/usr/bin/env python
"""Push the global (non-interface-specific) hardening fixes from the DISA Cisco
IOS Router RTR STIG to a device. Interface-scoped rules (directed broadcast,
ICMP redirects/unreachables/mask-reply, proxy ARP, LLDP transmit) need to be
applied per-interface and are intentionally left out of this pass.

AAA/RADIUS + password complexity (V-215681-686/709) and the vty management
ACL (V-215667) are pushed by separate scripts (ios_router_stig_harden_aaa.py,
ios_router_stig_harden_acl.py) - kept isolated the same way L2S splits
l2_stig_harden_aaa.py/l2_stig_harden_acl.py out of l2_stig_harden_global.py."""

import argparse
import netauto

# Global (non-interface-specific) fixes always pushed by this script
BASE_FIXES = {
    'V-216563 (Gratuitous ARPs)': 'no ip gratuitous-arps',
    'V-216585 (CDP)': 'no cdp run',
    'V-229030 (CEF)': 'ip cef',
    # Retroactively re-encodes any existing type-0 (cleartext) passwords
    # already in the config - including the local admin account's - to type 7
    # (weak, reversible, but that's the literal Check Content requirement for
    # this rule). Doesn't change the password value itself, just its stored
    # representation - zero login/lockout risk.
    'V-215687 (password encryption)': 'service password-encryption',
    'V-215672 (log timestamps)': 'service timestamps log datetime localtime',
    'V-215691 (logging buffer size)': 'logging buffered 64000 informational',
    'V-215692 (audit failure alert)': 'logging trap critical',
    'V-215670a (admin activity logging: privilege escalation)': 'logging userinfo',
    'V-215704a (log on-failure)': 'login on-failure log',
    'V-215704b (log on-success)': 'login on-success log',
    'V-215668 (lockout after 3 failed attempts)': 'login block-for 900 attempts 3 within 120',
    # Not confirmed to be valid syntax on this lab's IOSv image without a base
    # MPLS feature-set active - included per the check text's literal presence
    # requirement (no "not applicable if MPLS unused" language, unlike the
    # BGP/OSPF/MPLS-TE-gated rules ios_router_audit.py reports NOT APPLICABLE
    # for). If rejected live, harmless - doesn't touch AAA/access.
    'V-216610 (MPLS TTL propagation)': 'no mpls ip propagate-ttl',
    'V-216993 (drop IP options)': 'ip options drop',
}

# V-216571 (AUX port disabled) needs two lines under "line aux 0", so it's
# handled separately from the single-command BASE_FIXES
AUX_PORT_FIX = ['line aux 0', 'no exec']

# V-215688: exec-timeout on console and vty, plus the HTTP timeout-policy the
# check text's own example lists alongside them. Pushed unconditionally like
# CONSOLE_EXEC_TIMEOUT_FIX/VTY_SESSION_LIMIT_FIX are in the L2S/NX-OS harden
# scripts - `ip http timeout-policy` is a no-op if the HTTP server is never
# enabled.
CONSOLE_EXEC_TIMEOUT_FIX = ['line con 0', 'exec-timeout 5 0']
VTY_EXEC_TIMEOUT_FIX = ['line vty 0 4', 'exec-timeout 5 0']
HTTP_TIMEOUT_FIX = ['ip http timeout-policy idle 300 life 180 requests 1']

# V-215662: concurrent session limit, same "line vty 0 4" context and value
# (5) as L2S's VTY_SESSION_LIMIT_FIX for consistency across the project -
# DISA's own check/fix text example uses 2, but leaves the actual number
# organization-defined.
VTY_SESSION_LIMIT_FIX = ['line vty 0 4', 'session-limit 5']

# V-215670b: the second half of V-215670's evidence requirement (checked by
# ios_router_audit.py's _admin_activity_logged as one combined rule with
# 'logging userinfo' above - both must be present together). Same archive
# block as L2S's ARCHIVE_LOGGING_FIX.
ARCHIVE_LOGGING_FIX = [
    'archive',
    'log config',
    'logging enable',
    'logging size 1000',
    'notify syslog contenttype plaintext',
    'hidekeys',
]

# V-215699/700: FIPS-validated HMAC (MAC/integrity) and encryption
# (confidentiality) algorithms for SSH, both gated on 'ip ssh version 2'
# being active - same shape as L2S's SSH_ENCRYPTION_FIX. Classic IOS accepts
# a space-separated algorithm list in one command (confirmed already working
# via L2S), unlike NX-OS's 'ssh macs'/'ssh ciphers', which needed one
# algorithm per invocation (see project memory) - R2 is cisco_ios, same
# platform family as the switches, not NX-OS.
SSH_ENCRYPTION_FIX = [
    'ip ssh version 2',
    'ip ssh server algorithm mac hmac-sha2-256',
    'ip ssh server algorithm encryption aes256-ctr aes192-ctr aes128-ctr',
]

# Rules that need per-interface targeting and are intentionally not pushed by
# this global-only pass
SKIPPED_RULES = [
    'V-216564 (directed broadcast)',
    'V-216565 (ICMP unreachables)',
    'V-216566 (ICMP mask reply)',
    'V-216567 (ICMP redirects)',
    'V-216584 (LLDP transmit)',
    'V-216586 (proxy ARP)',
]

# Parse the target device from the command line
parser = argparse.ArgumentParser(description='Push global RTR STIG hardening fixes to a device from inventory.yaml')
parser.add_argument('device', help='Device name as it appears in inventory.yaml (e.g. R1)')
args = parser.parse_args()

device_name = args.device

# Load the target device from the YAML inventory
all_devices = netauto.load_inventory()
device_info = netauto.require_devices(all_devices, [device_name])[device_name]

# Prompt for credentials
username, password = netauto.get_credentials()

# Connect, bailing out if it fails
net_connect = netauto.connect(device_name, device_info, username, password)
if net_connect is None:
    raise SystemExit(1)

# NTP server IPs (V-215693) and syslog server IPs (V-220136) come from
# inventory.yaml's services section. NTP authentication key (V-215698) and
# SNMPv3 auth/priv passwords (V-215696/697) come from secrets.yaml (gitignored,
# never committed - see secrets.yaml.example).
services = netauto.load_services()
ntp_servers = services.get('ntp_servers', [])
syslog_servers = services.get('syslog_servers', [])
secrets = netauto.load_secrets()
ntp_auth_key = secrets.get('ntp_auth_key') or {}
ntp_key_id = ntp_auth_key.get('id')
ntp_key_value = ntp_auth_key.get('value')
if not ntp_key_value:
    ntp_key_id = None

# V-215696/697: FIPS-validated HMAC (SHA) auth + FIPS 140-2 approved (AES)
# privacy for SNMPv3. Same shared secrets.yaml fields as L2S's identical
# push (l2_stig_harden_global.py) - config-only, no NMS in this lab actually
# polls it yet. Skips the view/host lines from V-215696's own Fix Text
# example (SNMP access scoping + trap destination) since
# ios_router_audit.py's check only verifies `show snmp user` output (auth/
# privacy protocol), not those - same simplification L2S already made.
# AES 256 matches V-215697's own Fix Text example specifically (unlike
# L2S's AES 128 choice) - either satisfies the audit's `'aes' in ...` check.
SNMPV3_GROUP = 'SNMPV3_GROUP'
SNMPV3_USER = 'SNMPV3_USER'
snmpv3 = secrets.get('snmpv3') or {}
snmp_auth_password = str(snmpv3.get('auth_password') or '').strip()
snmp_priv_password = str(snmpv3.get('priv_password') or '').strip()

snmpv3_commands = []
if snmp_auth_password and snmp_priv_password:
    snmpv3_commands = [
        f'snmp-server group {SNMPV3_GROUP} v3 priv',
        f'snmp-server user {SNMPV3_USER} {SNMPV3_GROUP} v3 auth sha {snmp_auth_password} priv aes 256 {snmp_priv_password}',
    ]

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

applied_fixes = dict(BASE_FIXES)
applied_fixes['V-216571 (AUX port disabled)'] = '; '.join(AUX_PORT_FIX)
applied_fixes['V-215688 (exec-timeout)'] = '; '.join(CONSOLE_EXEC_TIMEOUT_FIX + VTY_EXEC_TIMEOUT_FIX + HTTP_TIMEOUT_FIX)
applied_fixes['V-215662 (session limit)'] = '; '.join(VTY_SESSION_LIMIT_FIX)
applied_fixes['V-215670b (admin activity logging: archive)'] = '; '.join(ARCHIVE_LOGGING_FIX)
applied_fixes['V-215699/700 (SSH MAC + encryption)'] = '; '.join(SSH_ENCRYPTION_FIX)
if ntp_servers:
    applied_fixes['V-215693 (NTP time sync)'] = '; '.join(
        f'ntp server {ip}' + (f' key {ntp_key_id}' if ntp_key_id else '') for ip in ntp_servers)
if ntp_key_id:
    applied_fixes['V-215698 (NTP authentication)'] = '; '.join([
        f'ntp authentication-key {ntp_key_id} md5 {ntp_key_value}', 'ntp authenticate', f'ntp trusted-key {ntp_key_id}'])
if syslog_servers:
    applied_fixes['V-220136 (dual syslog servers)'] = '; '.join(f'logging host {ip}' for ip in syslog_servers)
if snmpv3_commands:
    applied_fixes['V-215696/697 (SNMPv3 auth/priv)'] = f'snmp-server group {SNMPV3_GROUP} v3 priv; snmp-server user {SNMPV3_USER} ... v3 auth sha ... priv aes 256 ...'

commands = (
    list(BASE_FIXES.values()) + AUX_PORT_FIX + CONSOLE_EXEC_TIMEOUT_FIX + VTY_EXEC_TIMEOUT_FIX
    + HTTP_TIMEOUT_FIX + VTY_SESSION_LIMIT_FIX + ARCHIVE_LOGGING_FIX + SSH_ENCRYPTION_FIX
    + ntp_commands + [f'logging host {ip}' for ip in syslog_servers] + snmpv3_commands
)

# Push the hardening commands and close the session
output = net_connect.send_config_set(commands)
net_connect.disconnect()
netauto.log_push('ios_router_stig_harden_global.py', device_name, username, commands)

print(f'Hardening commands pushed to {device_name}:')
for command in commands:
    print('  ' + netauto.redact_secrets(command))
print()
print(netauto.redact_output(output))

print(f'\nRules addressed by this pass:')
for rule in applied_fixes:
    print('  - ' + rule)

if not ntp_servers:
    print('\nSkipped V-215693 (NTP time sync) - add ntp_servers to inventory.yaml\'s services section to include it.')
if not ntp_key_id:
    print('\nSkipped V-215698 (NTP authentication) - add ntp_auth_key to secrets.yaml to include it.')
if not syslog_servers:
    print('\nSkipped V-220136 (dual syslog servers) - add syslog_servers to inventory.yaml\'s services section to include it.')
if not (snmp_auth_password and snmp_priv_password):
    print('\nSkipped V-215696/697 (SNMPv3 auth/priv) - add snmpv3.auth_password and snmpv3.priv_password to secrets.yaml to include it.')

print('\nRules requiring interface targeting (not pushed by this script):')
for rule in SKIPPED_RULES:
    print('  - ' + rule)

print('\nV-215667 (vty management ACL) is pushed separately by ios_router_stig_harden_acl.py.')
print('V-215681-686/709 (AAA new-model + RADIUS auth + password complexity) is pushed separately by ios_router_stig_harden_aaa.py.')
