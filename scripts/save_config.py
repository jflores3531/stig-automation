#!/usr/bin/env python
"""Save running-config to startup-config on one device (or all devices) in
inventory.yaml, so pushed configuration survives a reload.

Deliberately a separate script rather than something the *_stig_harden*.py
scripts do themselves. Until a config is saved, reloading the device reverts
it - which is the escape hatch when a push turns out to lock the automation
host out, and the only recovery that doesn't need console access. Saving
automatically at the end of every push would make a bad push permanent.

So the intended order is: push, audit, confirm the result is what you wanted,
then run this. The cost of getting that order wrong in the other direction is
mild by comparison - NXCore1 lost a full session of AAA/ACL/Root Guard work to
an unsaved reload, and re-running the harden scripts restored it in minutes.

NX-OS in particular stages some configuration (the TCAM regions for IPSG/DAI
in nxos_stig_harden_global.py) that only takes effect after a reload, so
saving before that reload is what makes those fixes persist."""

import argparse
import netauto

# Optional device name to save just one device; omit to save all of them
parser = argparse.ArgumentParser(
    description='Save running-config to startup-config on devices in inventory.yaml'
)
parser.add_argument(
    'device', nargs='?', default=None,
    help='Device name as it appears in inventory.yaml (e.g. NXCore1). Omit to save all devices.'
)
args = parser.parse_args()

# Prompt for credentials used against every device being saved
username, password = netauto.get_credentials()

# Load target devices from the YAML inventory (name -> {host, device_type})
all_devices = netauto.load_inventory()
if args.device:
    devices_list = netauto.require_devices(all_devices, [args.device])
else:
    devices_list = all_devices

saved, failed = [], []

for device_name, device_info in devices_list.items():
    net_connect = netauto.connect(device_name, device_info, username, password)
    if net_connect is None:
        failed.append(device_name)
        continue

    # Netmiko picks the right command per platform - 'copy running-config
    # startup-config' on both cisco_ios and cisco_nxos, but leaving the choice
    # to the driver keeps this working if another device_type is added.
    try:
        output = net_connect.save_config()
    except Exception as error:
        print(f'{device_name}: save failed - {error}')
        failed.append(device_name)
        net_connect.disconnect()
        continue

    net_connect.disconnect()
    netauto.log_push('save_config.py', device_name, username, ['copy running-config startup-config'])
    saved.append(device_name)
    print(f'{device_name}: running-config saved to startup-config.')
    print(netauto.redact_output(output))

print()
if saved:
    print(f'Saved on {len(saved)} device(s): {", ".join(saved)}')
    print('These devices will now come back with this configuration after a reload.')
if failed:
    print(f'FAILED on {len(failed)} device(s): {", ".join(failed)} - their running-config is '
          f'still unsaved and will be lost on reload.')
    raise SystemExit(1)
