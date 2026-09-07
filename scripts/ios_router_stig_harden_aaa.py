#!/usr/bin/env python
"""Push aaa new-model + RADIUS auth (V-215709: at least two authentication
servers used as the primary source for administrative access) to a device,
kept separate on purpose - port of l2_stig_harden_aaa.py's exact safety
pattern, after L2S/S2 had a live session drop right after 'aaa new-model'
took effect (recovered via console + 'no aaa new-model'). This project's
routers (R1/R2) don't have console access from the automation host the way
the switches do - see project memory on R1 being the sole connectivity path
- so getting this right matters even more here.

Before touching aaa new-model at all, this script pushes the enable secret
on its own and verifies it actually works: drop to user EXEC with 'disable',
then escalate back with Netmiko's enable() (which uses the same secret), and
confirm privileged EXEC was reached. If that round-trip fails for any
reason, it aborts without pushing anything AAA-related.

Uses the modern block-style 'radius server <name>' / 'address ipv4 ...' /
'key ...' form, not the classic single-line 'radius-server host <ip> ...'
from V-215709's own check/fix text example - confirmed live on R2 that this
IOSv image rejects the classic form outright (no 'host' keyword under
'radius-server ?' at all), same platform quirk L2S's vios_l2 image hit.

V-215681/682-686 (password length + complexity via 'aaa common-criteria
policy') are NOT pushed here - confirmed live that this IOSv image doesn't
support the command at all ('common-criteria' isn't listed under 'aaa ?').
Same category as vios_l2's missing UUFB/mls qos: a permanent lab-image
ceiling, not something this script can work around. ios_router_audit.py's
V-215681-686 checks will correctly keep reporting FAIL on this platform.

'local' stays last in the login authentication method lists as a fallback,
same account (admin) this script is already connected with - if RADIUS is
entirely unreachable, SSH login still succeeds via the local account. Only
privilege escalation (enable) is gated behind the round-trip check below,
same as L2S/NX-OS's equivalent scripts."""

import argparse
import netauto

# Parse the target device from the command line
parser = argparse.ArgumentParser(
    description='Push aaa new-model + RADIUS auth to a device from inventory.yaml/secrets.yaml (V-215709)'
)
parser.add_argument('device', help='Device name as it appears in inventory.yaml (e.g. R2)')
args = parser.parse_args()

device_name = args.device

# Load the target device from the YAML inventory
all_devices = netauto.load_inventory()
device_info = netauto.require_devices(all_devices, [device_name])[device_name]

# Prompt for credentials
username, password = netauto.get_credentials()

# RADIUS server IPs come from inventory.yaml's services section, the shared
# secret and enable secret from secrets.yaml (never hardcoded/prompted via
# CLI flag). This script requires all three up front and refuses to do
# anything if they're missing - unlike ios_router_stig_harden_global.py's
# "skip and continue" pattern, there's no safe partial version of this push.
secrets = netauto.load_secrets()
services = netauto.load_services()
enable_secret = str(secrets.get('enable_secret') or '').strip()
radius_key = str(secrets.get('radius_key') or '').strip()
radius_servers = services.get('radius_servers', [])

if not enable_secret:
    print('Aborting: no enable_secret in secrets.yaml. Set one first - it is the only way back into '
          'privileged EXEC once aaa new-model is active, and this script verifies it works before using it.')
    raise SystemExit(1)
if not radius_servers or not radius_key:
    print('Aborting: radius_servers (inventory.yaml services section) and radius_key (secrets.yaml) are both required.')
    raise SystemExit(1)
if len(radius_servers) < 2:
    print(f'Warning: only {len(radius_servers)} RADIUS server(s) configured - V-215709 wants 2+. Continuing anyway.')

# Connect, bailing out if it fails
net_connect = netauto.connect(device_name, device_info, username, password)
if net_connect is None:
    raise SystemExit(1)

# Push the enable secret on its own first (idempotent if already set).
enable_secret_command = [f'enable secret {enable_secret}']
net_connect.send_config_set(enable_secret_command)
netauto.log_push('ios_router_stig_harden_aaa.py', device_name, username, enable_secret_command)

# Verify it actually works before going anywhere near aaa new-model: drop to
# user EXEC, then escalate back using the same secret Netmiko already has
# from netauto.connect(). check_enable_mode() reflects the real prompt, not
# just whether enable() raised - IOS can accept 'enable' and still leave you
# at user EXEC in some failure modes.
#
# exit_enable_mode() (not a raw send_command('disable')) - send_command()
# waits for Netmiko's already-cached '#'-style prompt to reappear, which
# never happens once 'disable' changes it to '>', causing a hang and a
# ReadTimeout crash. exit_enable_mode() knows to expect the new prompt.
net_connect.exit_enable_mode()
net_connect.enable()
if not net_connect.check_enable_mode():
    print(f'ABORT: enable secret verification failed on {device_name} - not back at privileged EXEC after '
          'disable -> enable. Not touching aaa new-model. Investigate before retrying.')
    net_connect.disconnect()
    raise SystemExit(1)

print(f'Enable secret verified working on {device_name} (disable -> enable round-trip succeeded).')

# Verified - now safe to push aaa new-model + RADIUS. 'local' stays last in
# both method lists as a fallback, same as the account this script is
# connected with.
aaa_commands = ['aaa new-model']

# Modern block-style form, confirmed live as the only one this platform
# accepts (see module docstring) - matches l2_stig_harden_aaa.py's identical
# per-server timeout/retransmit sub-commands.
for i, ip in enumerate(radius_servers, start=1):
    aaa_commands += [
        f'radius server RADIUS{i}',
        f'address ipv4 {ip} auth-port 1812 acct-port 1813',
        f'key {radius_key}',
        'timeout 2',
        'retransmit 1',
        'exit',
    ]

# V-215709's own fix text example uses two named method lists - CONSOLE for
# the console line, LOGIN_AUTHENTICATION for vty - rather than one shared
# 'default' list, so each line type can be governed independently. Each
# 'line ...' block needs its own 'exit' back to global config before the
# next global-level command - confirmed live as a real bug the first time
# this script ran (every command after 'line vty 0 4' silently stayed in
# line-config context and failed).
aaa_commands += [
    'aaa authentication login CONSOLE group radius local',
    'aaa authentication login LOGIN_AUTHENTICATION group radius local',
    'line con 0',
    'login authentication CONSOLE',
    'exit',
    'line vty 0 4',
    'login authentication LOGIN_AUTHENTICATION',
    'exit',
]

output = net_connect.send_config_set(aaa_commands)
net_connect.disconnect()
netauto.log_push('ios_router_stig_harden_aaa.py', device_name, username, aaa_commands)

print(f'\nAAA/RADIUS commands pushed to {device_name}:')
for command in aaa_commands:
    print('  ' + netauto.redact_secrets(command))
print()
print(netauto.redact_output(output))

print('\nRules addressed by this pass:')
print('  - V-215709 (RADIUS as primary auth source, local fallback)')
print('\nV-215681/682-686 (password length + complexity via `aaa common-criteria policy`) NOT pushed - '
      'confirmed live this IOSv image does not support the command at all (permanent lab-image ceiling, '
      'see module docstring). ios_router_audit.py will keep correctly reporting these as FAIL.')
