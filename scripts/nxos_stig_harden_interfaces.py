#!/usr/bin/env python
"""Push the interface-scoped hardening fixes from the DISA Cisco NX-OS
Switch L2S STIG to a device - split out of nxos_stig_harden_global.py so global
fixes and per-port fixes can be run/reviewed independently, same pattern as
l2_stig_harden_dai.py. Classifies each switchport by whether it has an
explicit 'switchport access vlan <n>' line - present means access/host-facing
(gets UUFB/storm control/IPSG), absent means trunk (gets converted to trunk
with the shared allowed-VLAN list and native VLAN). See classify_switchports()
for why the VLAN-assignment line is used as the signal instead of 'switchport
mode access' (unreliable in NX-OS running-config).

Run nxos_stig_harden_global.py first, then reload the device, before running this:
V-220685 (IP Source Guard) needs the 'ipsg' TCAM region carved and live
(nxos_stig_harden_global.py stages the carve but doesn't reload), and V-220684
(DHCP snooping) needs to already be enabled for the same VLANs, since IPSG
silently no-ops without it (confirmed live on NXCore1). VLAN 999
(unused/native VLAN) also needs to already exist in the VLAN database -
created by nxos_stig_harden_global.py, not here.

V-220683 (UUFB) and V-220687 (storm control) are pushed to every
access-classified port unconditionally. V-220687's threshold is a percentage
(NX-OS), not bps (IOS) - 40% matches DISA's own Fix Text example; per the
STIG's own note, network engineers are responsible for the actual value,
this is a reasonable default, not a mandated one. Only broadcast is pushed -
Check Text's compliance floor is broadcast alone, same as L2S's V-220636.
V-220685 (IP Source Guard) uses NX-OS's own syntax ('ip verify source
dhcp-snooping-vlan', confirmed different from IOS's 'ip verify source'),
pushed only when vlan_ids is non-empty - same condition nxos_stig_harden_global.py
gates DHCP snooping on, since IPSG has no prerequisite to depend on
otherwise.
V-220695 (native VLAN): unless a switchport already has an explicit
'switchport access vlan <n>' line, it's pushed to trunk mode with the
shared native_vlan - the inverse default from l2_stig_harden_global.py's
access-layer switches. Appropriate here since NXCore1/NXCore2 are core
switches where most ports interconnect other switches, not end hosts.
V-220692 (trunk VLAN pruning): trunks carry only VLANs that actually exist
in the switch's VLAN database, minus the default VLAN (1) and the
designated unused VLAN - same explicit-list pattern l2_stig_harden_global.py uses.
V-220691/694 (default VLAN on host ports / user-facing ports as access)
aren't pushed by anything here either - they're satisfied by construction
(access ports are never touched, only ports without an explicit access VLAN
get converted to trunk). nxos_stig_audit.py independently verifies both via
its own parse_switchports().

V-220690 (disabled ports assigned to unused VLAN): of the non-access ports
classify_switchports() finds, the ones NX-OS's own 'show interface status'
reports as 'disabled' (administratively shutdown, confirmed live on
NXCore1 - distinct from 'suspended'/'notconnect', which are genuine
interconnects just not currently up) are pulled out of the trunk-conversion
loop and get 'switchport access vlan <unused_vlan>' instead - trunking a
port nobody's using contradicts the whole point of parking it on the
black-hole VLAN. V-220692's trunk pruning already excludes unused_vlan from
every trunk's allowed-VLAN list, satisfying the Fix Text's Step 2 with no
extra work. These reclassified ports deliberately don't get
UUFB/IPSG/storm control (ACCESS_PORT_FIXES) - they're not host-facing, just
parked, and nxos_stig_audit.py's _all_access_ports_have() excludes
unused_vlan-assigned ports from that requirement for the same reason.

V-220680 (Root Guard): pushed to every trunk-classified port except this
switch's own live-detected STP root port(s), via the shared
stig_common.discover_root_port_interfaces() (same function L2S's
l2_stig_harden_interfaces.py uses) - guarding the root port would force it
into root-inconsistent (blocking) state, a real outage risk. Reuses the
connection this script already keeps open rather than opening a second one.

V-220675/679 (802.1x): pushed to every access-classified port not already
parked on unused_vlan (V-220690's black-hole ports don't need endpoint
authentication - nothing is plugged in), per Check Content's full documented
form: 'dot1x pae authenticator' + 'dot1x port-control auto' + 'dot1x
host-mode single-host'. These commands are valid to configure even before
nxos_stig_harden_aaa.py's global prerequisites ('feature dot1x' + 'aaa
authentication dot1x default group ...') are active - they're just inert
until that script runs, same as L2S's equivalent split. MAB isn't pushed
here - its NX-OS command syntax isn't documented in this rule's own Check
Content/Fix Text at all, only inferred in nxos_stig_audit.py's own comment,
so it needs a live `dot1x mac-auth-bypass ?` confirmation first before this
script should push it too."""

import argparse
import re
import netauto
import stig_common

# Interface types that take switchport commands on NX-OS - mgmt0
# (management), Vlan<n> (SVIs), and loopback<n> aren't physical/logical
# switchports and can't take 'switchport mode' commands at all.
NXOS_SWITCHPORT_PREFIXES = ('Ethernet', 'port-channel')


def classify_switchports(cfg):
    """Classify every switchport-capable interface as access (has an
    explicit 'switchport access vlan <n>' line) or not (everything else -
    trunk-classified already, or left in NX-OS's default negotiated mode).
    Checks for the VLAN assignment, not 'switchport mode access' -
    confirmed live that 'switchport mode access' alone doesn't reliably
    show up in NX-OS running-config (default mode, same omission pattern
    IOS uses for VLAN 1), so it isn't a trustworthy signal on its own. The
    policy for these core switches: unless a port is already configured as
    access, it should be trunk - these are the switch's interconnect/uplink
    ports, or ports left in NX-OS's default negotiated mode.
    Returns (access_names, non_access_names)."""
    access, non_access = [], []
    for chunk in re.split(r'^(?=interface \S+)', cfg, flags=re.M):
        m = re.match(r'interface (\S+)', chunk)
        if not m or not m.group(1).startswith(NXOS_SWITCHPORT_PREFIXES):
            continue
        name = m.group(1)
        if re.search(r'^\s*switchport access vlan \d+\s*$', chunk, re.M):
            access.append(name)
        else:
            non_access.append(name)
    return access, non_access


# 'show interface status' uses abbreviated interface names ('Eth1/5',
# 'Po10') - running-config and classify_switchports() use the full form
# ('Ethernet1/5', 'port-channel10'). Only the two prefixes this script
# cares about need mapping.
_SHORT_TO_FULL_PREFIX = (('Eth', 'Ethernet'), ('Po', 'port-channel'))

# Every status value 'show interface status' actually prints in the Status
# column, per NX-OS's own vocabulary - used as an anchor to pull the status
# out of a fixed-width table whose Name field is free text that can't be
# reliably column-sliced.
_INTERFACE_STATUSES = (
    'connected', 'disabled', 'suspended', 'notconnect', 'noOperMem',
    'inactive', 'xcvrAbsent', 'sfpAbsent', 'err-disabled',
)


def parse_interface_status(output):
    """Maps every interface name (expanded to running-config form) found in
    'show interface status' output to its Status column value. Confirmed
    live on NXCore1: 'disabled' specifically means administratively
    shutdown - distinct from 'suspended' (a port-channel member with no
    active peer) or 'notconnect' (up, but no link partner), neither of
    which mean unused the way 'disabled' does."""
    statuses = {}
    for line in output.splitlines():
        m = re.match(r'^(\S+)\s+.*?\b(' + '|'.join(_INTERFACE_STATUSES) + r')\b', line)
        if not m:
            continue
        short_name, status = m.group(1), m.group(2)
        full_name = short_name
        for short_prefix, full_prefix in _SHORT_TO_FULL_PREFIX:
            if short_name.startswith(short_prefix) and short_name[len(short_prefix):len(short_prefix) + 1].isdigit():
                full_name = full_prefix + short_name[len(short_prefix):]
                break
        statuses[full_name] = status
    return statuses


# Pushed to every access-classified port unconditionally. V-220687's
# threshold is a percentage (NX-OS), not bps (IOS) - 40% matches DISA's own
# Fix Text example; per the STIG's own note, network engineers are
# responsible for the actual value, this is a reasonable default, not a
# mandated one. Only broadcast is pushed - Check Text's compliance floor is
# broadcast alone, same as L2S's V-220636.
ACCESS_PORT_FIXES = [
    'switchport block unicast',               # V-220683 (UUFB)
    'storm-control broadcast level 40',        # V-220687 (storm control)
]

# V-220685 (IP Source Guard). NX-OS's own IPSG syntax
# ('ip verify source dhcp-snooping-vlan'), not IOS's 'ip verify source').
# Depends on DHCP snooping already being active (pushed by
# nxos_stig_harden_global.py) - pushed alongside ACCESS_PORT_FIXES only when
# vlan_ids is non-empty. Confirmed live on NXCore1: pushing this with DHCP
# snooping never enabled silently fails to take effect rather than
# erroring - keeping the two in lockstep means never claiming IPSG was
# pushed when its prerequisite wasn't.
IPSG_FIX = 'ip verify source dhcp-snooping-vlan'

# V-220675/679 (802.1x). Per Check Content's own documented example - MAB is
# deliberately not included, see the module docstring for why. Stays inert
# until nxos_stig_harden_aaa.py's global prerequisites ('feature dot1x' +
# 'aaa authentication dot1x default group ...') are active.
DOT1X_FIX = [
    'dot1x pae authenticator',
    'dot1x port-control auto',
    'dot1x host-mode single-host',
]

# Satisfied by construction (access ports are never touched, only
# non-access ports get converted to trunk) rather than by a dedicated
# command of their own - independently verified by nxos_stig_audit.py's
# own parse_switchports().
SKIPPED_RULES = [
    'V-220691 (default VLAN on host ports)',
    'V-220694 (user-facing ports as access)',
]

# Parse the target device from the command line
parser = argparse.ArgumentParser(description='Push interface-scoped NX-OS L2S STIG hardening fixes to a device from inventory.yaml')
parser.add_argument('device', help='Device name as it appears in inventory.yaml (e.g. NXCore1)')
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

unused_vlan = netauto.load_unused_vlan()
native_vlan_id = netauto.load_native_vlan()

# Discover the switch's user VLANs - same set nxos_stig_harden_global.py uses to
# decide whether DHCP snooping/DAI get pushed - so IPSG is only pushed
# where its DHCP-snooping prerequisite actually exists. Passes device_name
# so a device-specific non_user_vlans_by_device override (inventory.yaml)
# applies here too; both scripts must agree on this discovery.
non_user_vlan_exclude = list(netauto.load_non_user_vlans(device_name=device_name))
if unused_vlan:
    non_user_vlan_exclude.append(unused_vlan)
if native_vlan_id:
    non_user_vlan_exclude.append(native_vlan_id)
vlan_ids = stig_common.discover_user_vlans(net_connect, exclude=non_user_vlan_exclude,
                                           exclude_names=netauto.load_non_user_vlan_names(),
                                           include_names=netauto.load_user_vlan_names())

# V-220692: trunks should carry only VLANs that actually exist in the switch's
# VLAN database, minus the default VLAN (1), the designated unused VLAN, and
# the native VLAN - same explicit-list pattern l2_stig_harden_global.py uses
# (sidesteps 'except'/'remove' semantics entirely, no risk of clobbering a
# pre-existing restriction on first run). native_vlan_id is now a genuinely
# separate exclusion from unused_vlan (see inventory.yaml for why they're
# split) - excluding unused_vlan alone used to implicitly cover native_vlan
# too since they were the same ID; now both need to be named explicitly or
# native_vlan_id would get swept into the discovered allowed-list once it
# exists in the VLAN database.
trunk_vlan_exclude = [1] + ([unused_vlan] if unused_vlan else []) + ([native_vlan_id] if native_vlan_id else [])
allowed_trunk_vlans = stig_common.discover_user_vlans(net_connect, exclude=trunk_vlan_exclude)

# Classify every switchport-capable interface so access ports get
# UUFB/IPSG/storm control and everything else gets converted to trunk with
# the shared allowed-VLAN list and native VLAN.
running_config = str(net_connect.send_command('show running-config'))
access_ports, trunk_target_ports = classify_switchports(running_config)

# V-220690: pull administratively-shutdown ('disabled') ports out of the
# trunk-conversion population - see the module docstring for why trunking
# an unused port defeats the point. Only reclassified if unused_vlan is
# configured; otherwise there's nowhere to park them and they're left as
# trunk targets, same as before this feature existed.
disabled_ports = []
if unused_vlan:
    interface_statuses = parse_interface_status(str(net_connect.send_command('show interface status')))
    disabled_ports = [name for name in trunk_target_ports if interface_statuses.get(name) == 'disabled']
    trunk_target_ports = [name for name in trunk_target_ports if name not in disabled_ports]

disabled_interface_commands = []
for name in disabled_ports:
    disabled_interface_commands.append(f'interface {name}')
    disabled_interface_commands.append('switchport')
    disabled_interface_commands.append('switchport mode access')
    disabled_interface_commands.append(f'switchport access vlan {unused_vlan}')

# Port-channel member interfaces (carry a 'channel-group <n>' line) inherit
# their L2/trunk config from the port-channel interface itself - confirmed
# live on NXCore1 that NX-OS rejects re-issuing 'switchport'/'switchport
# mode trunk'/'switchport trunk ...' directly on a member once it's bundled
# ("% Incomplete command"/"% Invalid command"), even though the member
# already carries that same config from before it was bundled. Skipped here
# to stop every run re-attempting (and failing) a redundant push - the
# port-channel interface (also in trunk_target_ports) still gets pushed
# normally, and Root Guard below is unaffected either way.
channel_members = set()
for chunk in re.split(r'^(?=interface \S+)', running_config, flags=re.M):
    m = re.match(r'interface (\S+)', chunk)
    if m and re.search(r'^\s*channel-group \d+', chunk, re.M):
        channel_members.add(m.group(1))

# V-220675/679 (802.1x): NOT pushed at all when IPSG is (or is about to be)
# active - confirmed live on NXCore1 that Nexus 9000 rejects 'feature
# dot1x' outright ("802.1X can't be enabled, IPSG is enabled in system")
# whenever IP Source Guard is configured, platform-level mutually exclusive
# per Cisco's own documentation, not a per-port conflict. vlan_ids being
# non-empty means IPSG_FIX is about to be pushed to every access port this
# run (see below); the running_config check also catches IPSG already
# configured from a prior run. Matches nxos_stig_audit.py's
# _dot1x_mab_check, which reports V-220675/679 NOT APPLICABLE under the
# same condition.
ipsg_active = bool(vlan_ids) or bool(re.search(r'^\s*ip verify source dhcp-snooping-vlan\s*$', running_config, re.M))
dot1x_target_ports = []
if not ipsg_active:
    dot1x_target_ports = access_ports
    if unused_vlan:
        parked_ports = set()
        for chunk in re.split(r'^(?=interface \S+)', running_config, flags=re.M):
            m = re.match(r'interface (\S+)', chunk)
            if m and re.search(rf'^\s*switchport access vlan {unused_vlan}\s*$', chunk, re.M):
                parked_ports.add(m.group(1))
        dot1x_target_ports = [name for name in access_ports if name not in parked_ports]

access_interface_commands = []
for name in access_ports:
    access_interface_commands.append(f'interface {name}')
    access_interface_commands += ACCESS_PORT_FIXES
    if vlan_ids:
        access_interface_commands.append(IPSG_FIX)
    if name in dot1x_target_ports:
        access_interface_commands += DOT1X_FIX

# V-220680 (Root Guard): live STP root port(s) must never receive this -
# see the module docstring for why. root_guard_ports is trunk_target_ports
# minus whatever discover_root_port_interfaces() finds.
root_ports = stig_common.discover_root_port_interfaces(net_connect)
root_guard_ports = [name for name in trunk_target_ports if name not in root_ports]

interface_commands = []
for name in trunk_target_ports:
    interface_commands.append(f'interface {name}')
    if name not in channel_members:
        # Confirmed live on NXCore1: a port with no explicit 'switchport
        # access vlan <n>' (this loop's whole population) may still be in
        # NX-OS's default L3/routed state, where 'switchport mode trunk' is
        # rejected outright. The bare 'switchport' command converts it to
        # L2 mode first - a no-op if it's already there. access_ports never
        # need this: an explicit 'switchport access vlan <n>' line can't
        # exist unless the port was already in L2 mode.
        interface_commands.append('switchport')
        interface_commands.append('switchport mode trunk')
        if allowed_trunk_vlans:
            interface_commands.append(f'switchport trunk allowed vlan {",".join(allowed_trunk_vlans)}')
        if native_vlan_id:
            interface_commands.append(f'switchport trunk native vlan {native_vlan_id}')
    if name in root_guard_ports:
        interface_commands.append('spanning-tree guard root')

applied_fixes = {}
if access_ports:
    applied_fixes['V-220683/687 (UUFB/storm control)'] = (
        f'{"; ".join(ACCESS_PORT_FIXES)} (on {len(access_ports)} access port(s): {", ".join(access_ports)})'
    )
    if vlan_ids:
        applied_fixes['V-220685 (IP Source Guard)'] = (
            f'{IPSG_FIX} (on {len(access_ports)} access port(s): {", ".join(access_ports)})'
        )
    else:
        applied_fixes['V-220685 (IP Source Guard) - SKIPPED'] = (
            'no user VLANs discovered (vlan_ids empty) - run nxos_stig_harden_global.py first if DHCP '
            'snooping should already be covering VLANs here; pushing IPSG anyway would silently fail'
        )
    if ipsg_active:
        applied_fixes['V-220675/679 (802.1x) - NOT APPLICABLE'] = (
            'IP Source Guard is active/being pushed on this device - Nexus 9000 rejects `feature dot1x` '
            'while IPSG is enabled (confirmed live), so 802.1x/MAB is never pushed here'
        )
    elif dot1x_target_ports:
        applied_fixes['V-220675/679 (802.1x)'] = (
            f'{"; ".join(DOT1X_FIX)} (on {len(dot1x_target_ports)} access port(s): {", ".join(dot1x_target_ports)}) '
            f'- stays inert until nxos_stig_harden_aaa.py\'s globals are active'
        )
if trunk_target_ports and root_guard_ports:
    applied_fixes['V-220680 (Root Guard)'] = (
        f'spanning-tree guard root (on {len(root_guard_ports)} trunk port(s): {", ".join(root_guard_ports)})'
    )
if trunk_target_ports and native_vlan_id:
    applied_fixes['V-220695 (native VLAN)'] = (
        f'switchport mode trunk; switchport trunk native vlan {native_vlan_id} '
        f'(on {len(trunk_target_ports)} non-access port(s): {", ".join(trunk_target_ports)})'
    )
if trunk_target_ports and allowed_trunk_vlans:
    applied_fixes['V-220692 (trunk VLAN pruning)'] = (
        f'switchport trunk allowed vlan {",".join(allowed_trunk_vlans)} '
        f'(on {len(trunk_target_ports)} trunk port(s))'
    )
if disabled_ports:
    applied_fixes['V-220690 (disabled ports to unused VLAN)'] = (
        f'switchport mode access; switchport access vlan {unused_vlan} '
        f'(on {len(disabled_ports)} disabled port(s): {", ".join(disabled_ports)})'
    )

commands = access_interface_commands + interface_commands + disabled_interface_commands

# Push the interface commands and close the session. read_timeout raised
# well above Netmiko's default - confirmed live that this device's per-port
# trunk conversion (potentially dozens of unused ports on a core switch)
# takes long enough that the default caused a ReadTimeout mid-batch,
# aborting the script before most of the interface loop had even run.
output = net_connect.send_config_set(commands, read_timeout=180) if commands else ''
net_connect.disconnect()
netauto.log_push('nxos_stig_harden_interfaces.py', device_name, username, commands)

if commands:
    print(f'Interface hardening commands pushed to {device_name}:')
    for command in commands:
        print('  ' + netauto.redact_secrets(command))
    print()
    print(netauto.redact_output(output))

print('\nRules addressed by this pass:')
for rule in applied_fixes:
    print('  - ' + rule)

if not access_ports:
    print('\nNo access switchports found (explicit `switchport access vlan <n>`) - nothing to push for V-220683/685/687.')
elif not ipsg_active and not dot1x_target_ports:
    print('\nEvery access port is parked on unused_vlan - nothing to push for V-220675/679.')
if trunk_target_ports and not root_guard_ports:
    print("\nSkipped V-220680 (Root Guard) - every trunk port is this switch's STP root port toward the root bridge; Root Guard must not be applied there.")
if not native_vlan_id:
    print('\nSkipped V-220695 (native VLAN) - add native_vlan to inventory.yaml to include it.')
elif not trunk_target_ports:
    print('\nNo non-access switchports found - every port already has an explicit `switchport access vlan <n>` line, nothing to push for V-220695/692.')
if trunk_target_ports and not allowed_trunk_vlans:
    print('\nSkipped V-220692 (trunk VLAN pruning) - no VLANs discovered in the VLAN database besides VLAN 1/unused_vlan.')
if not unused_vlan:
    print('\nSkipped V-220690 (disabled ports to unused VLAN) - add unused_vlan to inventory.yaml to include it.')
elif not disabled_ports:
    print('\nNo administratively-shutdown ports found via `show interface status` - nothing to push for V-220690.')

print('\nRules satisfied by construction (not pushed by this script):')
for rule in SKIPPED_RULES:
    print('  - ' + rule)
