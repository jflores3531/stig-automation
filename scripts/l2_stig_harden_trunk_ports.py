#!/usr/bin/env python
"""Push the trunk/uplink port fixes from the DISA Cisco IOS Switch L2S STIG to
a device.

READ THIS BEFORE RUNNING IT ON A SWITCH YOU REACH THROUGH A TRUNK
This is the half of the old l2_stig_harden_interfaces.py that can take the
switch away from you. A trunk port is an uplink; the session pushing these
commands is usually riding one. Two of the fixes below decide what that uplink
carries and whether it forwards at all:

  * `switchport trunk allowed vlan <list>` replaces the allowed list outright.
    The list is discovered from the switch's own VLAN database, so a management
    VLAN that exists there is in it - but a management VLAN that does not exist
    locally, or is excluded, is pruned off the uplink the moment this lands,
    and the session goes with it.
  * `switchport trunk native vlan <id>` changes what untagged frames land in on
    both ends of the link. A trunk whose neighbour still has the old native
    VLAN is a native VLAN mismatch: STP complains, and untagged traffic - which
    can include the management path on a badly built link - stops arriving.

Root Guard is the third one, and is handled rather than warned about:
V-220629 must never be pushed to this switch's own root port, because it forces
that port into root-inconsistent (blocking) state and takes out the path to the
root bridge. The root port is discovered live before anything is sent, and
excluded.

Give this its own change window, with console access or a second known-good
path to the switch. The access-port half - l2_stig_harden_access_ports.py -
carries none of this risk and can go out on a working day; that is why the two
are separate scripts.

Run l2_stig_harden_global.py first: it creates the native/unused VLANs in the
database (referenced here, not created here) and enables DHCP snooping globally
(V-220633), without which the trust commands below are inert.

WHAT IT PUSHES, per trunk port
  switchport nonegotiate          V-220640 (static trunk, no DTP)
  ip dhcp snooping trust          V-220633b
  ip arp inspection trust         V-220635b
  switchport trunk allowed vlan   V-220643/641b, list discovered live
  switchport trunk native vlan    V-220646, from inventory.yaml
  spanning-tree guard root        V-220629, on every trunk EXCEPT the root port
"""

import argparse

import netauto
import stig_common

# Pushed to every trunk/uplink-classified interface. The allowed-VLAN list and
# the native VLAN line are added separately below, once the device's actual
# VLAN database is known.
TRUNK_PORT_FIXES = [
    'switchport nonegotiate',  # V-220640 (static trunk, no DTP negotiation)
    # DHCP snooping (V-220633) makes every port untrusted by default - an
    # untrusted port drops any DHCPOFFER/DHCPACK outright, so without this the
    # trunk port(s) toward wherever the real DHCP server lives would silently
    # break DHCP for every client behind this switch. Every trunk-classified
    # port gets trusted, consistent with this repo's existing trunk =
    # switch-to-switch uplink model (not a mix of trusted-upstream/
    # untrusted-peer trunks).
    'ip dhcp snooping trust',
    # DAI (V-220635) trust is a separate setting from DHCP snooping trust above
    # - it defaults to untrusted even on a DHCP-snooping-trusted port. DHCP
    # snooping bindings are learned per-switch only, from DORA exchanges seen
    # locally, never synced between switches. Without this, DAI on a trunk port
    # validates transit ARP traffic from hosts behind other switches against
    # this switch's own (often empty) binding table and drops it - confirmed
    # live: S1 dropped ARP traffic for a host bound only on S3's local table
    # (%SW_DAI-4-DHCP_SNOOPING_DENY on a trunk port, 0 local bindings on S1).
    # Trusting trunk/uplink ports for DAI too keeps inspection scoped to actual
    # access ports, where the local binding table is authoritative.
    'ip arp inspection trust',
]

parser = argparse.ArgumentParser(
    description='Push trunk/uplink port L2S STIG fixes to a device from inventory.yaml. '
                'These are uplink commands - see this script\'s docstring before running it '
                'through a trunk. Access ports are handled by l2_stig_harden_access_ports.py '
                'and are never touched here.')
parser.add_argument('device', help='Device name as it appears in inventory.yaml (e.g. S1)')
args = parser.parse_args()

device_name = args.device

all_devices = netauto.load_inventory()
device_info = netauto.require_devices(all_devices, [device_name])[device_name]
username, password = netauto.get_credentials()

net_connect = netauto.connect(device_name, device_info, username, password)
if net_connect is None:
    raise SystemExit(1)

# V-220629: this switch's STP root port(s), read live. Root Guard must never be
# pushed there - see stig_common.discover_root_port_interfaces for why: it
# forces the port into root-inconsistent/blocking state, a real outage.
root_ports = stig_common.discover_root_port_interfaces(net_connect)

running_config = str(net_connect.send_command('show running-config'))
access_ports, trunk_ports = stig_common.switchport_names(running_config)
root_guard_ports = [name for name in trunk_ports if name not in root_ports]

# Both exclusions below are read even though this script pushes neither VLAN:
# they are what the allowed-list must leave out.
unused_vlan = netauto.load_unused_vlan()

# Native VLAN for trunk ports (V-220646) comes from inventory.yaml rather than
# a prompt. Its own database entry is created by l2_stig_harden_global.py.
native_vlan_id = netauto.load_native_vlan()

# V-220643/641: trunks should carry only VLANs that actually exist in the
# switch's VLAN database, minus the default VLAN (1), the designated unused
# VLAN, and the native VLAN - not just "everything except 1/999", which would
# still leave every undefined VLAN ID allowed too. An explicit list also
# sidesteps the except/remove semantics entirely (no risk of clobbering a
# pre-existing restriction on first run). native_vlan_id is a genuinely
# separate exclusion from unused_vlan - they used to be the same ID by
# convention, so excluding unused_vlan implicitly excluded native_vlan too; now
# that they are deliberately different VLANs (see inventory.yaml), both need
# naming explicitly or native_vlan_id would get swept into the discovered
# allowed-list once it exists in the VLAN database.
trunk_vlan_exclude = [1] + ([unused_vlan] if unused_vlan else []) \
    + ([native_vlan_id] if native_vlan_id else [])
allowed_trunk_vlans = stig_common.discover_user_vlans(net_connect, exclude=trunk_vlan_exclude)

trunk_fixes = list(TRUNK_PORT_FIXES)
if allowed_trunk_vlans:
    trunk_fixes.append(f'switchport trunk allowed vlan {",".join(allowed_trunk_vlans)}')
if native_vlan_id:
    trunk_fixes.append(f'switchport trunk native vlan {native_vlan_id}')

commands = []
for name in trunk_ports:
    commands.append(f'interface {name}')
    commands += trunk_fixes
    if name in root_guard_ports:
        commands.append('spanning-tree guard root')

applied_fixes = {}
if trunk_ports:
    applied_fixes['V-220640 (static trunk)'] = \
        f'switchport nonegotiate (on {len(trunk_ports)} trunk port(s))'
    applied_fixes['V-220633b/635b (DHCP snooping + DAI trust)'] = (
        f'ip dhcp snooping trust; ip arp inspection trust (on {len(trunk_ports)} trunk port(s))')
    if root_guard_ports:
        applied_fixes['V-220629 (Root Guard)'] = (
            f'spanning-tree guard root (on {len(root_guard_ports)} trunk port(s) not leading '
            f'to the STP root: {", ".join(root_guard_ports)})')
    if allowed_trunk_vlans:
        applied_fixes['V-220643/641b (trunks scoped to real VLANs only)'] = (
            f'switchport trunk allowed vlan {",".join(allowed_trunk_vlans)} '
            f'(on {len(trunk_ports)} trunk port(s))')
    if native_vlan_id:
        applied_fixes['V-220646 (native VLAN)'] = (
            f'switchport trunk native vlan {native_vlan_id} (on {len(trunk_ports)} trunk port(s))')

output = net_connect.send_config_set(commands) if commands else ''
net_connect.disconnect()
netauto.log_push('l2_stig_harden_trunk_ports.py', device_name, username, commands)

if commands:
    print(f'Trunk-port hardening commands pushed to {device_name}:')
    for command in commands:
        print('  ' + netauto.redact_secrets(command))
    print()
    print(netauto.redact_output(output))

print('\nRules addressed by this pass:')
for rule in applied_fixes:
    print('  - ' + rule)

if not trunk_ports:
    print('\nNo trunk switchports found - nothing to push for V-220629/633b/635b/640/643/646.')
elif not root_guard_ports:
    print("\nSkipped V-220629 (Root Guard) - every trunk port is this switch's STP root port "
          'toward the root bridge; Root Guard must not be applied there.')
if trunk_ports and not allowed_trunk_vlans:
    print('\nSkipped V-220643/641b (trunk VLAN scoping) - no VLANs discovered in the VLAN '
          'database besides VLAN 1/unused_vlan/native_vlan.')
if trunk_ports and not native_vlan_id:
    print('\nSkipped V-220646 (native VLAN) - add native_vlan to inventory.yaml to include it.')

print(f'\n{len(access_ports)} access port(s) were classified and deliberately left alone. '
      'Run l2_stig_harden_access_ports.py for V-220630b/632/636/641 and the access mode/VLAN.')
