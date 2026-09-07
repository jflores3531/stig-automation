#!/usr/bin/env python
"""Push a vty management ACL (V-215667: enforce approved authorizations for
controlling the flow of management information) to a device, kept as its own
script on purpose - a vty access-class that excludes the automation host's
own source IP blocks every future SSH connection from it, so this is run and
reviewed independently of the bulk hardening pass.
Port of l2_stig_harden_acl.py's V-220575 script - identical pattern.

Scoped to just the automation host (inventory.yaml's automation_host), not
the whole management_subnet - least privilege, and simpler to reason about.

The ACL is created first, separate from applying it - creating an ip
access-list on its own has no effect until something references it. Only
once that is committed does this script apply 'access-class ... in' to line
vty 0 4, then confirm the automation host can still connect, reverting
automatically if it cannot."""

import argparse
import netauto

ACL_NAME = 'VTY_MGMT'

# Parse the target device from the command line
parser = argparse.ArgumentParser(description='Push a vty management ACL scoped to the automation host (V-215667)')
parser.add_argument('device', help='Device name as it appears in inventory.yaml (e.g. R2)')
args = parser.parse_args()

device_name = args.device

# Load the target device from the YAML inventory
all_devices = netauto.load_inventory()
device_info = netauto.require_devices(all_devices, [device_name])[device_name]

# Prompt for credentials (reused for the verification connection later too)
username, password = netauto.get_credentials()

automation_host = netauto.load_automation_host()
if not automation_host:
    print('Aborting: no automation_host in inventory.yaml. This is the sole permitted source for the ACL - required.')
    raise SystemExit(1)

# Connect (primary session - stays open as the safety net until verified)
net_connect = netauto.connect(device_name, device_info, username, password)
if net_connect is None:
    raise SystemExit(1)

# Step 1: create the ACL on its own. Has no effect on anything until it's
# actually referenced by an access-class - completely safe on its own.
acl_commands = [
    f'ip access-list extended {ACL_NAME}',
    f'permit ip host {automation_host} any',
    'deny ip any any log-input',
    'exit',
]
net_connect.send_config_set(acl_commands)
netauto.log_push('ios_router_stig_harden_acl.py', device_name, username, acl_commands)
print(f'ACL {ACL_NAME} created on {device_name}, scoped to {automation_host} only.')
print('Trailing `deny ip any any log-input` added - logs rejected vty access attempts with '
      'source/interface info. Matches the implicit deny already in effect, so no access change.')

# Step 2: apply it. This is the actual risky moment - everything before this
# point was fully reversible with zero exposure window.
apply_commands = ['line vty 0 4', f'access-class {ACL_NAME} in']
net_connect.send_config_set(apply_commands)
netauto.log_push('ios_router_stig_harden_acl.py', device_name, username, apply_commands)
print(f'Applied `access-class {ACL_NAME} in` to line vty 0 4 on {device_name}.')

# Step 3: verify with a *second*, independent connection - the primary
# session is unaffected by the ACL (already established before it took
# effect), so it can't prove new connections still work. Only a fresh
# connection attempt can.
print('Opening a second, independent connection to verify new logins still work...')
verify_connect = netauto.connect(device_name, device_info, username, password)
if verify_connect is None:
    print(f'\nABORT: verification connection failed - the automation host may have been locked out. '
          f'Reverting `access-class {ACL_NAME} in` via the still-open primary session now.')
    revert_commands = ['line vty 0 4', f'no access-class {ACL_NAME} in']
    net_connect.send_config_set(revert_commands)
    netauto.log_push('ios_router_stig_harden_acl.py', device_name, username, revert_commands)
    net_connect.disconnect()
    print('Reverted. The ACL itself is still defined but no longer applied to line vty 0 4 - investigate before retrying.')
    raise SystemExit(1)

print(f'Verification connection succeeded - {automation_host} still has access after the ACL was applied.')
verify_connect.disconnect()
net_connect.disconnect()

print(f'\nRules addressed by this pass:')
print(f'  - V-215667 (vty management ACL, scoped to {automation_host} only)')
