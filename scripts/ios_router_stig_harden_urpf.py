#!/usr/bin/env python
"""Push uRPF (V-216989: restrict outbound IP packets containing an
illegitimate source address, via Unicast Reverse Path Forwarding) to every
internal interface on a router - the complement of the external role
declared in inventory.yaml's external_interfaces_by_device, same
classification ios_router_audit.py's _urpf_egress_check uses.

LIVE INCIDENT, 2026-08-01: the first version of this script pushed
'ip verify unicast source reachable-via rx' without the 'allow-default'
keyword and locked R2 out completely, requiring out-of-band console
recovery. Root cause: Cisco's uRPF strict mode does NOT accept a packet
whose only matching route is a default route (0.0.0.0/0) unless
'allow-default' is also configured - R2's only route is a single default
route out Gi0/0, so the filter started dropping essentially all inbound
traffic on that interface the instant it applied, including the SSH
session that pushed it. 'allow-default' is the documented Cisco fix for
exactly this topology (a stub/single-uplink router with no specific
routes) and is now always included below.

Second lesson from that incident: the create-verify-revert pattern that
works for ios_router_stig_harden_acl.py/l2_stig_harden_acl.py does NOT
transfer cleanly to uRPF. Those scripts' safety net relies on the primary
session being unaffected by the change (an access-class/authentication
check only applies to NEW connections, so an already-established session
keeps working while a second connection proves new ones do too). uRPF is
fundamentally different: it filters every INCOMING packet on the
interface it's applied to, including packets belonging to the
already-established primary session itself. When the bad push happened,
the primary session's own send_config_set() call hung mid-command (return
traffic from the device was already being dropped) and raised an
uncaught exception - never reaching the revert logic below the original
version had, which only guarded against the *verification* connection
failing, not the initial push itself failing. The primary connection is
now wrapped in a try/except so a failure there is at least caught and
reported clearly, and a same-session revert is still attempted as a
best-effort measure - but if uRPF is actively dropping inbound traffic on
that same session, the revert commands may never arrive either. Console
access (via whatever hypervisor/emulator hosts these routers, not SSH) is
the only guaranteed recovery path if this happens again."""

import argparse
import re
import netauto

# Parse the target device from the command line
parser = argparse.ArgumentParser(description='Push uRPF to every internal interface on a router (V-216989)')
parser.add_argument('device', help='Device name as it appears in inventory.yaml (e.g. R2)')
args = parser.parse_args()

device_name = args.device

# Load the target device from the YAML inventory
all_devices = netauto.load_inventory()
device_info = netauto.require_devices(all_devices, [device_name])[device_name]

# Prompt for credentials (reused for the verification connection later too)
username, password = netauto.get_credentials()

# Connect (primary session - stays open as the safety net until verified)
net_connect = netauto.connect(device_name, device_info, username, password)
if net_connect is None:
    raise SystemExit(1)

# Discover internal interfaces live - addressed, not declared external
# (inventory.yaml), and not a loopback (not a traffic-forwarding boundary).
# Same classification as ios_router_audit.py's _urpf_egress_check.
running_config = str(net_connect.send_command('show running-config'))
external_interfaces = netauto.load_external_interfaces(device_name)
internal_interfaces = []
for chunk in re.split(r'^(?=interface \S+)', running_config, flags=re.M):
    m = re.match(r'interface (\S+)', chunk)
    if not m:
        continue
    name = m.group(1)
    if name in external_interfaces or name.lower().startswith('loopback'):
        continue
    if re.search(r'^\s*ip address \S+', chunk, re.M):
        internal_interfaces.append(name)

if not internal_interfaces:
    print(f'No internal interfaces found on {device_name} - nothing to push.')
    net_connect.disconnect()
    raise SystemExit(0)

# 'allow-default' lets the reverse-path check succeed against a default
# route, not just a specific one - required on any router (like R2) whose
# only route out an interface is a default route. See module docstring.
urpf_commands = []
for name in internal_interfaces:
    urpf_commands += [f'interface {name}', 'ip verify unicast source reachable-via rx allow-default']

revert_commands = []
for name in internal_interfaces:
    revert_commands += [f'interface {name}', 'no ip verify unicast source reachable-via rx allow-default']

try:
    net_connect.send_config_set(urpf_commands)
    netauto.log_push('ios_router_stig_harden_urpf.py', device_name, username, urpf_commands)
    print(f'uRPF (allow-default) pushed to {device_name} on internal interface(s): {", ".join(internal_interfaces)}')
except Exception as e:
    print(f'\nABORT: the push itself failed or hung ({type(e).__name__}: {e}). Attempting a best-effort revert '
          f'on the same session now - if uRPF is actively dropping inbound traffic on this connection, this may '
          f'not succeed. Console access (not SSH) will be the only guaranteed recovery path in that case.')
    try:
        net_connect.send_config_set(revert_commands)
        netauto.log_push('ios_router_stig_harden_urpf.py', device_name, username, revert_commands)
        print('Best-effort revert command sent - verify manually with a fresh connection before trusting it.')
    except Exception as revert_e:
        print(f'Revert attempt also failed ({type(revert_e).__name__}: {revert_e}). Console access required.')
    net_connect.disconnect()
    raise SystemExit(1)

# Verify with a *second*, independent connection - same pattern as
# ios_router_stig_harden_acl.py, though see module docstring for why this
# is weaker protection for uRPF than it is for an ACL/AAA change.
print('Opening a second, independent connection to verify new logins still work...')
verify_connect = netauto.connect(device_name, device_info, username, password)
if verify_connect is None:
    print(f'\nABORT: verification connection failed - the automation host may have been affected. '
          f'Reverting uRPF via the still-open primary session now.')
    try:
        net_connect.send_config_set(revert_commands)
        netauto.log_push('ios_router_stig_harden_urpf.py', device_name, username, revert_commands)
        print('Reverted. Investigate before retrying.')
    except Exception as revert_e:
        print(f'Revert attempt also failed ({type(revert_e).__name__}: {revert_e}). Console access required.')
    net_connect.disconnect()
    raise SystemExit(1)

print(f'Verification connection succeeded - {device_name} still reachable after uRPF was applied.')
verify_connect.disconnect()
net_connect.disconnect()

print(f'\nRules addressed by this pass:')
print(f'  - V-216989 (uRPF on internal interface(s): {", ".join(internal_interfaces)})')
