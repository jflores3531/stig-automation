#!/usr/bin/env python
"""Push 'ip arp inspection vlan <ids>' (V-220635, Dynamic ARP Inspection) to
a device, split out of l2_stig_harden_global.py's bulk batch on purpose - DAI only
trusts the DHCP snooping binding table, so a statically-addressed host (no
DHCP lease) is invisible to it and can have its ARP traffic dropped once
this is pushed (same static-host-binding gap as l2_stig_harden_ipsg.py - see
project memory). Keeping this isolated makes it easy to push/pull
independently of the rest of the STIG batch while that gap is unresolved.

Run l2_stig_harden_global.py first - this assumes DHCP snooping is already enabled
and trunk/uplink ports are already 'ip arp inspection trust'ed (both handled
there), neither of which this script sets up itself. Without trunk trust,
DAI also drops legitimate transit ARP traffic from hosts behind other
switches - DHCP snooping bindings are learned per-switch only, never
synced, so a switch's own binding table is incomplete for anything not
directly connected to it (confirmed live: S1 dropped ARP for a host bound
only on S3's local table)."""

import argparse
import netauto
import stig_common

# Parse the target device from the command line
parser = argparse.ArgumentParser(description="Push Dynamic ARP Inspection ('ip arp inspection vlan <ids>') to a device (V-220635)")
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

# Discover the switch's user VLANs, excluding management/servers/unused VLANs
# from inventory.yaml's non_user_vlans - same discovery l2_stig_harden_global.py uses
# for V-220633 (DHCP snooping), since DAI must cover the same VLAN set.
vlan_ids = stig_common.discover_user_vlans(net_connect, exclude=netauto.load_non_user_vlans(),
                                           exclude_names=netauto.load_non_user_vlan_names(),
                                           include_names=netauto.load_user_vlan_names())

commands = [f'ip arp inspection vlan {",".join(vlan_ids)}'] if vlan_ids else []

# Push the commands and close the session
output = net_connect.send_config_set(commands) if commands else ''
net_connect.disconnect()
netauto.log_push('l2_stig_harden_dai.py', device_name, username, commands)

if commands:
    print(f'DAI commands pushed to {device_name}:')
    for command in commands:
        print('  ' + netauto.redact_secrets(command))
    print()
    print(netauto.redact_output(output))
    print(f'\nV-220635 (DAI) addressed on {device_name}, covering user VLAN(s): {", ".join(vlan_ids)}')
else:
    print(f'\nNo user VLANs discovered on {device_name} - nothing to push for V-220635.')

print(
    '\nReminder: DAI only trusts the DHCP snooping binding table. '
    'Statically-addressed hosts with no DHCP lease will have their ARP traffic dropped.'
)
