#!/usr/bin/env python
"""Push RADIUS authentication (V-220513: two authentication servers) and the
AAA accounting cluster it enables (V-220475/476/477/478/482/485/494/495/
506/507/509, all sharing nxos_stig_audit.py's _aaa_accounting_check - see
that function's docstring for why one 'aaa accounting default group <name>'
line covers all eleven CCI categories) plus the 802.1x global prerequisites
(feature dot1x + aaa authentication dot1x default group - the per-port
V-220675/679 commands are pushed by nxos_stig_harden_interfaces.py and stay
inert until this script runs, same split L2S uses) to a device. Kept
separate from nxos_stig_harden_global.py's batch on purpose, same reasoning
as l2_stig_harden_aaa.py: this is the one script in this pass that changes
how SSH login itself is authenticated.

The 802.1x globals are skipped entirely (not just left inert) when IP
Source Guard is active - confirmed live on NXCore1 that Nexus 9000 rejects
'feature dot1x' outright ("802.1X can't be enabled, IPSG is enabled in
system") whenever IPSG is configured, a platform-level mutual exclusion per
Cisco's own documentation. nxos_stig_audit.py's _dot1x_mab_check reports
V-220675/679 NOT APPLICABLE under the same condition.

Why this is lower-risk on NX-OS than the L2S incident that motivated
l2_stig_harden_aaa.py's enable-secret verification: DISA's own V-220513 Fix
Text pushes 'aaa authentication login default group RADIUS_SERVERS' with no
'local' keyword in the method list at all (unlike IOS's 'group radius
local') - NX-OS instead has a separate 'fallback error local' mechanism
that Check Content confirms is ON BY DEFAULT ("should not be seen in the
configuration" when compliant). This script never pushes the 'no ...
fallback error local' line that would disable it: if RADIUS is reachable,
login authenticates via RADIUS; if it's not, NX-OS falls back to the same
local account automatically. NX-OS also doesn't tie a local account's role
to AAA authentication the way IOS ties privilege 15 to 'aaa new-model', so
the IOS "local account stops being privileged on login" behaviour does not
apply here.

Safety net for the actual push (step 2 below): same two-connection
verify+revert pattern nxos_stig_harden_acl.py/l2_stig_harden_acl.py use for
their riskiest moment - push, then open a *second* independent SSH
connection to prove login still works before going any further. This is a
more direct test of the real risk here (can the automation host still log
in at all) than an enable-secret round-trip would be.

V-220487 (dedicated local last-resort account) is deliberately NOT pushed
here - stays NOT AUTOMATED on the audit side (two prior heuristics tried
and reverted, see project_nxos_snmpv3_linked_username in Claude's memory
system), relying on the existing admin account + NX-OS's default fallback
above instead, per explicit decision when this script was planned.

'feature dot1x' isn't mentioned anywhere in V-220675/679's Check Content or
Fix Text - inferred from NX-OS's feature-gate model (same pattern as
'feature dhcp'/'feature udld'/'feature vtp' elsewhere in this codebase).
Confirm the exact feature name live (`feature ?` on the target device)
before trusting this - same class of undocumented-prerequisite gap already
found and fixed for V-220681's edge port type."""

import argparse
import re
import netauto

GROUP_NAME = 'RADIUS_SERVERS'

# Parse the target device from the command line
parser = argparse.ArgumentParser(
    description='Push RADIUS auth + AAA accounting + 802.1x globals to a device from inventory.yaml/secrets.yaml (V-220513/475-509/675/679)'
)
parser.add_argument('device', help='Device name as it appears in inventory.yaml (e.g. NXCore1)')
args = parser.parse_args()

device_name = args.device

# Load the target device from the YAML inventory
all_devices = netauto.load_inventory()
device_info = netauto.require_devices(all_devices, [device_name])[device_name]

# Prompt for credentials (reused for the verification connection later too)
username, password = netauto.get_credentials()

# RADIUS server IPs come from inventory.yaml's services section (shared
# with L2S, not platform-specific), the shared secret from secrets.yaml.
# Required up front - no safe partial version of this push.
secrets = netauto.load_secrets()
services = netauto.load_services()
radius_key = str(secrets.get('radius_key') or '').strip()
radius_servers = services.get('radius_servers', [])

if not radius_servers or not radius_key:
    print('Aborting: radius_servers (inventory.yaml services section) and radius_key (secrets.yaml) are both required.')
    raise SystemExit(1)
if len(radius_servers) < 2:
    print(f'Warning: only {len(radius_servers)} RADIUS server(s) configured - V-220513 wants 2+. Continuing anyway.')

# Connect (primary session - stays open as the safety net until verified)
net_connect = netauto.connect(device_name, device_info, username, password)
if net_connect is None:
    raise SystemExit(1)

# Step 1: RADIUS server definitions + the AAA group referencing them. Zero
# risk - doesn't touch how login is authenticated yet. Classic 'radius-server
# host <ip> key <key>' syntax, per V-220513's own Fix Text example (confirmed
# NX-OS syntax, unlike L2S's vios_l2 image which rejects this classic form
# and needs the modern 'radius server <name>' block instead - verify this
# still holds on NXCore1 before trusting it blindly).
radius_commands = []
for ip in radius_servers:
    radius_commands.append(f'radius-server host {ip} key {radius_key}')
# Global timeout/retransmit tuning - same motivation as l2_stig_harden_aaa.py's
# per-server tuning (IOS/NX-OS defaults can add ~15-30s of login delay per
# unreachable server before falling back) - confirm 'radius-server timeout ?'
# / 'radius-server retransmit ?' live on NXCore1 before trusting this exact
# syntax; these are the classic-syntax global equivalents, not per-host
# keywords.
radius_commands += ['radius-server timeout 2', 'radius-server retransmit 1']
radius_commands += [f'aaa group server radius {GROUP_NAME}']
radius_commands += [f'server {ip}' for ip in radius_servers]
radius_commands.append('exit')

net_connect.send_config_set(radius_commands)
netauto.log_push('nxos_stig_harden_aaa.py', device_name, username, radius_commands)
print(f'RADIUS servers + `aaa group server radius {GROUP_NAME}` pushed to {device_name}.')

# Step 2: the actual risky moment - everything before this point was fully
# reversible with zero exposure window. 'console' is physically separate
# from this SSH session, so it can't lock out the connection being used
# right now - safe to include in the same push as 'default'.
auth_commands = [
    f'aaa authentication login default group {GROUP_NAME}',
    f'aaa authentication login console group {GROUP_NAME}',
]
net_connect.send_config_set(auth_commands)
netauto.log_push('nxos_stig_harden_aaa.py', device_name, username, auth_commands)
print(f'Applied `aaa authentication login default/console group {GROUP_NAME}` on {device_name}.')

# Step 3: verify with a *second*, independent connection - the primary
# session was established before the AAA change took effect, so it can't
# prove new connections still work. Covers both live states: if RADIUS is
# reachable, this proves login via RADIUS works; if not, it proves NX-OS's
# default-on fallback-error-local path works instead. Either way is a pass.
print('Opening a second, independent connection to verify new logins still work...')
verify_connect = netauto.connect(device_name, device_info, username, password)
if verify_connect is None:
    print(f'\nABORT: verification connection failed - the automation host may have been locked out. '
          f'Reverting `aaa authentication login ...` via the still-open primary session now.')
    revert_commands = [
        f'no aaa authentication login default group {GROUP_NAME}',
        f'no aaa authentication login console group {GROUP_NAME}',
    ]
    net_connect.send_config_set(revert_commands)
    netauto.log_push('nxos_stig_harden_aaa.py', device_name, username, revert_commands)
    net_connect.disconnect()
    print('Reverted. RADIUS servers/group are still defined but not referenced by login - investigate before retrying.')
    raise SystemExit(1)

print(f'Verification connection succeeded - login still works after the AAA change.')
verify_connect.disconnect()

# Step 4 (only reached after verification succeeds): AAA accounting (11 of
# the 12 harden-side gap rules) - reuses the same GROUP_NAME already proven
# to have live servers. Doesn't touch admin CLI login, safe regardless.
followup_commands = [f'aaa accounting default group {GROUP_NAME}']

# 802.1x globals - NOT pushed when IP Source Guard is active: confirmed
# live on NXCore1 that Nexus 9000 rejects 'feature dot1x' outright ("802.1X
# can't be enabled, IPSG is enabled in system") whenever IPSG is
# configured, platform-level mutually exclusive per Cisco's own
# documentation - matches nxos_stig_audit.py's _dot1x_mab_check, which
# reports V-220675/679 NOT APPLICABLE under the same condition.
running_config = str(net_connect.send_command('show running-config'))
ipsg_active = bool(re.search(r'^\s*ip verify source dhcp-snooping-vlan\s*$', running_config, re.M))
if ipsg_active:
    print(f'\nSkipping V-220675a/679a (802.1x globals) - IP Source Guard is active on {device_name}, '
          f'and Nexus 9000 rejects `feature dot1x` while IPSG is enabled. See nxos_stig_audit.py\'s '
          f'_dot1x_mab_check, which now reports V-220675/679 NOT APPLICABLE for the same reason.')
else:
    followup_commands += ['feature dot1x', f'aaa authentication dot1x default group {GROUP_NAME}']

output = net_connect.send_config_set(followup_commands)
net_connect.disconnect()
netauto.log_push('nxos_stig_harden_aaa.py', device_name, username, followup_commands)

print(f'\nFollow-up commands pushed to {device_name}:')
for command in followup_commands:
    print('  ' + netauto.redact_secrets(command))
print()
print(netauto.redact_output(output))

print('\nRules addressed by this pass:')
print(f'  - V-220513 (RADIUS as primary auth source, {len(radius_servers)} server(s))')
print('  - V-220475/476/477/478/482/485/494/495/506/507/509 (AAA accounting, 11 of the 12 harden-side gap rules '
      'via one `aaa accounting default group` line - V-220510 is pushed separately by nxos_stig_harden_global.py, '
      'it\'s a plain `logging level authpriv 6` presence check, not part of this accounting-group mechanism)')
if not ipsg_active:
    print('  - V-220675a/679a (802.1x AAA method + feature dot1x) - per-port V-220675/679 commands are pushed by nxos_stig_harden_interfaces.py')
else:
    print('  - V-220675/679 (802.1x/MAB) - NOT APPLICABLE, IP Source Guard is active (see skip note above)')
print(f'\nNot addressed (deliberately): V-220487 (dedicated local last-resort account) - relying on the existing '
      f'admin account + NX-OS\'s default `fallback error local` instead. Still NOT AUTOMATED on the audit side.')
