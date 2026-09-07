#!/usr/bin/env python
"""Push 'ip verify source' (V-220634, IP Source Guard) to every host-facing/
access port on a device, split out of l2_stig_harden_global.py's bulk batch on
purpose - IP Source Guard only trusts the DHCP snooping binding table, so a
statically-addressed host (no DHCP lease) has its traffic dropped once this
is pushed (confirmed live on S3: %SW_DAI-4-DHCP_SNOOPING_DENY-style
drops - see the static-host-binding gap tracked in project memory). Keeping
this isolated makes it easy to push/pull independently of the rest of the
STIG batch while that gap is unresolved.

Run l2_stig_harden_global.py first - this assumes DHCP snooping is already enabled
and access ports are already in 'switchport mode access' (both handled
there), neither of which this script sets up itself."""

import argparse
import re
import netauto

# Interface types that take switchport commands - VLAN SVIs, loopbacks, etc. are
# excluded since "switchport mode trunk" can never appear in their blocks and they'd
# otherwise be misclassified as host-facing/access. The multigigabit and 25G-and-up
# names are IOS-XE (Catalyst 9000) forms with no equivalent on the lab's vios_l2
# image; leaving them out doesn't error, it silently skips those ports, which reads
# exactly like a clean run. AppGigabitEthernet is deliberately excluded: it's the
# internal port to the switch's app-hosting container, not an external attack
# surface, and access-port hardening there would disrupt app hosting rather than
# protect anything.
SWITCHPORT_PREFIXES = (
    'GigabitEthernet', 'FastEthernet', 'TenGigabitEthernet', 'TwoGigabitEthernet',
    'FiveGigabitEthernet', 'TwentyFiveGigE', 'FortyGigabitEthernet', 'HundredGigE',
    'TwoHundredGigE', 'FourHundredGigE', 'Ethernet', 'Port-channel',
)


def parse_switchports(cfg):
    """Classify every switchport-capable interface as trunk or host-facing/access:
    an interface counts as trunk only if its block has 'switchport mode trunk';
    anything else (access mode, unset mode, dynamic negotiation) is host-facing.
    Returns (access_names, trunk_names)."""
    access, trunk = [], []
    for chunk in re.split(r'^(?=interface \S+)', cfg, flags=re.M):
        m = re.match(r'interface (\S+)', chunk)
        if not m or not m.group(1).startswith(SWITCHPORT_PREFIXES):
            continue
        name = m.group(1)
        if re.search(r'^\s*switchport mode trunk\s*$', chunk, re.M):
            trunk.append(name)
        else:
            access.append(name)
    return access, trunk


# Parse the target device from the command line
parser = argparse.ArgumentParser(description="Push IP Source Guard ('ip verify source') to a device's access ports (V-220634)")
parser.add_argument('device', help='Device name as it appears in inventory.yaml (e.g. S1)')
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

# Classify switchports so the fix is only pushed to host-facing/access ports
running_config = str(net_connect.send_command('show running-config'))
access_ports, _ = parse_switchports(running_config)

interface_commands = []
for name in access_ports:
    interface_commands.append(f'interface {name}')
    interface_commands.append('ip verify source')

# Push the commands and close the session
output = net_connect.send_config_set(interface_commands)
net_connect.disconnect()
netauto.log_push('l2_stig_harden_ipsg.py', device_name, username, interface_commands)

print(f'IP Source Guard commands pushed to {device_name}:')
for command in interface_commands:
    print('  ' + netauto.redact_secrets(command))
print()
print(netauto.redact_output(output))

if access_ports:
    print(f'\nV-220634 (IP Source Guard) addressed on {len(access_ports)} access port(s): {", ".join(access_ports)}')
else:
    print('\nNo access/host-facing switchports found - nothing to push.')

print(
    '\nReminder: IP Source Guard only trusts the DHCP snooping binding table. '
    'Statically-addressed hosts with no DHCP lease will have their traffic dropped.'
)
