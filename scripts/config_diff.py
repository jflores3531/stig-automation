#!/usr/bin/env python
"""Compare a device's current running-config (plus VLANs) against its last backup_config.py backup."""

import argparse
import difflib
import os
import netauto

# Parse the target device from the command line
parser = argparse.ArgumentParser(description='Diff a device\'s current running-config and VLANs against its last backup_config.py backup')
parser.add_argument('device', help='Device name as it appears in inventory.yaml (e.g. R1)')
args = parser.parse_args()

device_name = args.device

# Load the target device from the YAML inventory
all_devices = netauto.load_inventory()
device_info = netauto.require_devices(all_devices, [device_name])[device_name]
ip_address_of_device = device_info['host']

# Find the last backup taken for this device (written by backup_config.py)
backup_path = os.path.join(netauto.BACKUP_DIR, f'{device_name}_{ip_address_of_device}.cfg')
if not os.path.exists(backup_path):
    print(f'No existing backup found at {backup_path} - run backup_config.py first.')
    raise SystemExit(1)

with open(backup_path) as f:
    # Drop the 3-line header backup_config.py adds (hostname/IP/timestamp) so it
    # doesn't show up as noise in every diff. Rebuilt the same way current_lines
    # is below, so a missing trailing newline on the last line of the file
    # doesn't show up as a false diff.
    backup_lines = [line + '\n' for line in f.read().splitlines()[3:]]

# Prompt for credentials
username, password = netauto.get_credentials()

# Connect, bailing out if it fails
net_connect = netauto.connect(device_name, device_info, username, password)
if net_connect is None:
    raise SystemExit(1)

# Pull the current running config and VLANs, then close the session
running_config = str(net_connect.send_command('show running-config'))
vlan_brief = str(net_connect.send_command('show vlan brief'))
net_connect.disconnect()

current_output = running_config + '\n! --- show vlan brief ---\n' + vlan_brief
current_lines = [line + '\n' for line in current_output.splitlines()]

diff = list(difflib.unified_diff(
    backup_lines,
    current_lines,
    fromfile=backup_path,
    tofile=f'{device_name} current running-config',
    lineterm=''
))

if diff:
    print('\n'.join(diff))
else:
    print(f'No differences - {device_name} matches its last backup ({backup_path}).')
