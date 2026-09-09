#!/usr/bin/env python
"""Audit a device's running-config against the DISA Cisco IOS XE Switch
L2S/NDM STIG (the default, IOS-XE Checklist.cklb) or the Cisco IOS Switch
L2S/NDM STIG (--checklist ios, New Layer 2 switch Checklist.cklb - what the
lab's vios_l2 switches are), reporting PASS/FAIL for the rules that can be
checked from config text alone. The two STIGs share no rule IDs but mostly
the same requirements - the same checks serve both, re-keyed through
ios_xe_rule_map.py."""

import argparse
import datetime
import ipaddress
import re
import os

import capture
import ios_xe_rule_map
import netauto
import stig_common

CHECKLIST_PATH = os.path.join(netauto.PROJECT_ROOT, 'checklists', 'New Layer 2 switch Checklist.cklb')
IOS_XE_CHECKLIST_PATH = os.path.join(netauto.PROJECT_ROOT, 'checklists', 'IOS-XE Checklist.cklb')

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


# A switchport-capable interface *name* is not the same thing as a switchport.
# A routed port carries 'no switchport', and a Catalyst's out-of-band management
# port (GigabitEthernet0/0, in Mgmt-vrf) is not switchport-capable hardware at
# all, so IOS XE emits no switchport line for it in either direction. Both match
# SWITCHPORT_PREFIXES by name. Left in the access bucket they produce findings
# against ports that cannot take a switchport command: on a Catalyst-shaped
# config, a routed uplink and a Mgmt-vrf port drew FAILs from BPDU Guard, UUFB,
# IP Source Guard, storm control, 802.1x, the access-VLAN rule and the explicit-
# mode rule at once. That is the recognition-side mirror of the Fix Text false
# FAILs - the rule is right, the port is just not one it governs.
#
# Excluding by name is not an option: the lab's vios_l2 image carries a real
# switchport called GigabitEthernet0/0. The block's own contents decide it.
# Anything ambiguous stays a switchport, so the error falls on the strict side.
def _is_layer3_interface(block):
    if re.search(r'^\s*no switchport\s*$', block, re.M):
        return True
    if re.search(r'^\s*switchport\b', block, re.M):
        return False
    return bool(re.search(r'^\s*(?:ip|ipv6) address\b|^\s*vrf forwarding\b', block, re.M))


def _switchport_blocks(cfg):
    """Yield (name, block) for every interface that is a switchport: the name
    is a switchport-capable type and the block is not a Layer 3 interface."""
    for chunk in re.split(r'^(?=interface \S+)', cfg, flags=re.M):
        m = re.match(r'interface (\S+)', chunk)
        if not m or not m.group(1).startswith(SWITCHPORT_PREFIXES):
            continue
        if _is_layer3_interface(chunk):
            continue
        yield m.group(1), chunk


def parse_switchports(cfg):
    """Classify every switchport as trunk or host-facing/access: an interface
    counts as trunk only if its block has 'switchport mode trunk'; anything else
    (access mode, unset mode, dynamic negotiation) is host-facing. Layer 3
    interfaces are excluded from both - see _is_layer3_interface.
    Returns (access_blocks, trunk_blocks), each {interface_name: block_text}."""
    access, trunk = {}, {}
    for name, chunk in _switchport_blocks(cfg):
        if re.search(r'^\s*switchport mode trunk\s*$', chunk, re.M):
            trunk[name] = chunk
        else:
            access[name] = chunk
    return access, trunk


# V-220645: user-facing/untrusted ports must be *explicitly* configured as
# access switchports, not just "not trunk". parse_switchports()'s access
# bucket is defined as "lacks switchport mode trunk", so every port in it is
# trivially non-trunk by construction - checking that bucket against itself
# could never fail, making it a fake verification (why this stayed NOT
# AUTOMATED for a long time). Scans every switchport directly instead
# (Layer 3 interfaces excluded, same as parse_switchports - a routed port has
# no switchport mode to be explicit about), requiring an explicit
# 'switchport mode access' or
# 'switchport mode trunk' line - genuinely catches a port left in IOS's
# default negotiated/dynamic mode (the actual DTP/VLAN-hopping risk this rule
# is about), which l2_stig_harden_global.py now avoids by pushing 'switchport mode
# access' explicitly to every access port (it didn't always).
def _all_ports_explicit_mode(cfg):
    bad, total = [], 0
    for name, chunk in _switchport_blocks(cfg):
        total += 1
        if not re.search(r'^\s*switchport mode (trunk|access)\s*$', chunk, re.M):
            bad.append(name)
    if total == 0:
        return False, 'no switchports found in config'
    if bad:
        return False, f'left in negotiated/dynamic mode (missing explicit `switchport mode access` or `switchport mode trunk`) on: {", ".join(sorted(bad))}'
    return True, f'all {total} switchport(s) have an explicit switchport mode (trunk or access)'


# V-220645 (IOS) / V-220671 (IOS XE), identical text in both books: "If any of
# the user-facing switch ports are configured as a trunk, this is a finding."
#
# _all_ports_explicit_mode above used to be the answer to this, and it is not
# one. It asks whether every port has an explicit `switchport mode`, which
# catches a port left negotiable - a real DTP risk, and the rule's spirit - but
# it never fails an explicit trunk, which is the rule's letter. A switch with a
# user-facing port configured `switchport mode trunk` passed it. That is the
# shape of verdict this project exists to avoid: not a wrong answer, a
# confident answer to a different question.
#
# The obstacle is that "user-facing" is not in the configuration. Two facts
# about the site are, if the site declares them, and both live in
# inventory.yaml beside the VLAN names and the management subnet:
#
#   core_switch_hostname_tags - substrings marking a hostname as core or
#     distribution. Those switches have no user-facing ports at all, so the
#     rule's population is empty and NOT APPLICABLE is the honest verdict.
#   uplink_port_description_keywords - substrings marking a port's description
#     as facing another switch, an AP, or a phone rather than a user.
#
# What this cannot do is call an unlabelled trunk a finding. Every access
# switch needs at least one trunk - its uplink - so failing trunks outright
# would fail every switch in a fleet for being wired correctly. An unlabelled
# trunk is a port whose far end this cannot see, and the truthful verdict is
# that a human has to look: NOT AUTOMATED, naming the ports, rather than a
# PASS that quietly asserts they are fine.
def _port_description(block):
    match = re.search(r'^\s*description\s+(.+?)\s*$', block, re.M)
    return match.group(1) if match else ''


def _matching_tag(text, tags):
    """The first declared tag `text` contains, case-insensitively, or None."""
    lowered = (text or '').lower()
    return next((tag for tag in tags if tag and tag.lower() in lowered), None)


def _user_facing_trunk_check(cfg, core_tags=(), uplink_keywords=()):
    hostname_match = re.search(r'^hostname (\S+)', cfg, re.M)
    hostname = hostname_match.group(1) if hostname_match else ''

    core_tag = _matching_tag(hostname, core_tags)
    if core_tag:
        return None, (
            f'`{hostname}` is a core/distribution switch by the `{core_tag}` in its hostname '
            '(core_switch_hostname_tags in inventory.yaml), so it has no user-facing ports for '
            'this rule to be about'
        )

    switchports = dict(_switchport_blocks(cfg))
    if not switchports:
        return False, 'no switchports found in config'

    # A port left negotiable belongs here with the trunks: it is not
    # `switchport mode trunk`, but it will become a trunk the moment something
    # on the other end asks, which on a user-facing port is the whole DTP
    # VLAN-hopping problem this rule guards.
    trunks, negotiable = {}, {}
    for name, block in sorted(switchports.items()):
        if re.search(r'^\s*switchport mode trunk\s*$', block, re.M):
            trunks[name] = block
        elif not re.search(r'^\s*switchport mode access\s*$', block, re.M):
            negotiable[name] = block

    if not trunks and not negotiable:
        return True, (f'all {len(switchports)} switchport(s) are explicitly '
                      '`switchport mode access`, so none of them is a trunk')

    accounted, unaccounted = [], []
    for name, block in list(trunks.items()) + list(negotiable.items()):
        keyword = _matching_tag(_port_description(block), uplink_keywords)
        kind = 'trunk' if name in trunks else 'negotiable (no explicit `switchport mode`)'
        if keyword:
            accounted.append(f'{name} ({kind}, described `{keyword}`)')
        else:
            unaccounted.append(f'{name} ({kind})')

    if unaccounted:
        return 'NOT AUTOMATED', (
            'cannot tell from configuration whether these face users: '
            + ', '.join(unaccounted)
            + (f'. Accounted for by description: {", ".join(accounted)}' if accounted else '')
            + '. A trunk to another switch is required on an access switch and is not a '
            'finding, so these are not failed - name the far end in each port\'s '
            '`description` using uplink_port_description_keywords, or tag this hostname in '
            'core_switch_hostname_tags, and this answers itself'
        )
    return True, (
        f'no user-facing trunk: every non-access port is described as an uplink - '
        f'{", ".join(accounted)}'
    )


def _presence(cfg, pattern, flags=0, what=None):
    """PASS if pattern is found; reason shows the matched line, or what was
    searched for if it wasn't."""
    m = re.search(pattern, cfg, flags)
    label = what or f'a line matching `{pattern}`'
    if m:
        return True, f'found: `{m.group(0).strip()}`'
    return False, f'not found - searched for {label}'


def _absence(cfg, pattern, flags=0, what=None):
    """PASS if pattern is NOT found (for "must not have X" rules)."""
    m = re.search(pattern, cfg, flags)
    label = what or f'`{pattern}`'
    if m:
        return False, f'found (should be absent): `{m.group(0).strip()}`'
    return True, f'not found (correctly absent) - searched for {label}'


def _all_of(cfg, conditions):
    """conditions: list of (label, pattern), each tested with re.search(pattern,
    cfg, re.M). PASS only if all match; reason lists what's missing/present."""
    missing, present = [], []
    for label, pattern in conditions:
        (present if re.search(pattern, cfg, re.M) else missing).append(label)
    if missing:
        detail = f"missing: {', '.join(missing)}"
        if present:
            detail += f' (have: {", ".join(present)})'
        return False, detail
    return True, f"all present: {', '.join(present)}"


def _count_distinct(cfg, pattern, minimum, noun, flags=re.M):
    """PASS if at least `minimum` distinct values of `pattern`'s capture group
    are found. Reason lists what was actually found."""
    found = sorted(set(re.findall(pattern, cfg, flags)))
    if len(found) >= minimum:
        return True, f'found {len(found)} {noun}: {", ".join(found)}'
    if found:
        return False, f'only {len(found)} of {minimum}+ required {noun} found: {", ".join(found)}'
    return False, f'no {noun} found (need {minimum}+) - searched for `{pattern}`'


def _bpdu_guard_check(cfg):
    """V-220630: the global 'spanning-tree portfast bpduguard default' form
    only activates BPDU Guard on ports that actually have PortFast enabled -
    per the STIG's own Discussion text, BPDU Guard disables "the port that
    has PortFast configured" upon receiving a BPDU. Checking for the global
    command's presence alone (as this used to) is a false-pass risk: it can
    be sitting in the config while PortFast was never turned on anywhere,
    meaning BPDU Guard never actually protects a single port. The
    per-interface 'spanning-tree bpduguard enable' form has no such
    dependency and is accepted on its own. IOS 15.x rewrites the global
    form to include "edge" in running-config - both are accepted."""
    access, _ = parse_switchports(cfg)
    if not access:
        return False, 'no access/host-facing switchports found in config'
    global_bpduguard = bool(re.search(r'^spanning-tree portfast (edge )?bpduguard default\s*$', cfg, re.M))
    portfast_global = bool(re.search(r'^\s*spanning-tree portfast (edge )?default\s*$', cfg, re.M))

    missing = []
    for name, block in sorted(access.items()):
        if re.search(r'spanning-tree bpduguard enable', block):
            continue
        has_portfast = portfast_global or bool(re.search(r'^\s*spanning-tree portfast(?:\s+edge)?\s*$', block, re.M))
        if not (global_bpduguard and has_portfast):
            missing.append(name)

    if missing:
        return False, (
            f'BPDU Guard not functionally active on: {", ".join(missing)} - needs either per-port '
            f'`spanning-tree bpduguard enable`, or the global `spanning-tree portfast bpduguard default` '
            f'paired with PortFast enabled on that port (global command alone is a no-op without it)'
        )
    return True, f'BPDU Guard confirmed functionally active on all {len(access)} access port(s)'


def _all_access_ports_have(cfg, pattern, what, exclude_prefixes=()):
    """exclude_prefixes lets a rule exempt certain interface types (e.g.
    V-220636/storm control on FastEthernet, per the STIG's own Fix Text
    note that it's not supported on most FastEthernet interfaces) without
    affecting rules that apply to every access port regardless of type."""
    access, _ = parse_switchports(cfg)
    checked = {name: block for name, block in access.items() if not name.startswith(exclude_prefixes)}
    if not checked:
        if access:
            return True, f'no eligible access port(s) found (all {len(access)} excluded by interface type) - nothing required'
        return False, 'no access/host-facing switchports found in config'
    missing = sorted(name for name, block in checked.items() if not re.search(pattern, block))
    if missing:
        return False, f'missing {what} on: {", ".join(missing)}'
    return True, f'{what} present on all {len(checked)} eligible access port(s): {", ".join(sorted(checked))}'


# V-220623: every access port must have either 802.1x (dot1x pae authenticator
# + authentication port-control auto) or MAB (mab, for devices that don't
# support an 802.1x supplicant) - either is sufficient per DISA's own fix
# text. Partially functional on lab vios_l2, and dangerously so: `dot1x pae
# authenticator`/`mab` are rejected, but `authentication port-control auto`
# alone is accepted AND enforced (confirmed live 2026-08-28 - it blocked the
# rebuilt S1's management port). The harden deliberately skips ports on
# non-user VLANs for exactly that reason, so this check reporting those ports
# as a finding is expected and honest - the known/accepted-FAIL bucket, like
# S2's V-220634 - not a harden bug. DISA's check text has no management-VLAN
# carve-out, so the check stays strict rather than inheriting the exemption.
def _dot1x_mab_check(cfg):
    access, _ = parse_switchports(cfg)
    if not access:
        return False, 'no access/host-facing switchports found in config'
    missing = []
    for name, block in sorted(access.items()):
        has_dot1x = re.search(r'dot1x pae authenticator', block) and re.search(r'authentication port-control auto', block)
        has_mab = re.search(r'^\s*mab\s*$', block, re.M)
        if not (has_dot1x or has_mab):
            missing.append(name)
    if missing:
        return False, f'missing 802.1x (`dot1x pae authenticator` + `authentication port-control auto`) or MAB (`mab`) on: {", ".join(missing)}'
    return True, f'802.1x or MAB present on all {len(access)} access port(s): {", ".join(sorted(access))}'


def _all_trunk_ports_have(cfg, pattern, what):
    _, trunk = parse_switchports(cfg)
    if not trunk:
        return False, 'no trunk switchports found in config'
    missing = sorted(name for name, block in trunk.items() if not re.search(pattern, block))
    if missing:
        return False, f'missing {what} on: {", ".join(missing)}'
    return True, f'{what} present on all {len(trunk)} trunk port(s): {", ".join(sorted(trunk))}'


def _vlan_in_spec(vlan, spec):
    """True if vlan appears in a comma-separated list of VLAN IDs/ranges, e.g. '2-4094'."""
    for part in spec.split(','):
        part = part.strip()
        if '-' in part:
            lo, hi = part.split('-')
            if int(lo) <= vlan <= int(hi):
                return True
        elif part.isdigit() and int(part) == vlan:
            return True
    return False


def default_vlan_pruned_from_trunks(cfg):
    """PASS only if every trunk interface explicitly excludes VLAN 1 from its
    allowed-VLAN list (via 'except'/'remove', or an explicit list that omits 1).
    A trunk with no 'switchport trunk allowed vlan' line defaults to allowing every
    VLAN including 1, so that's a finding. An 'add ...' spec is additive to an
    unknown existing list and can't be reliably evaluated from config text alone,
    so it's conservatively treated as a finding too. Reason lists which specific
    trunk(s) still allow VLAN 1."""
    _, trunk = parse_switchports(cfg)
    if not trunk:
        return False, 'no trunk switchports found in config'
    bad = []
    for name, block in sorted(trunk.items()):
        m = re.search(r'switchport trunk allowed vlan (.+)$', block, re.M)
        if not m:
            bad.append(f'{name} (no allowed-vlan restriction, VLAN 1 allowed by default)')
            continue
        spec = m.group(1).strip()
        pruned = (
            (spec.startswith('except') and _vlan_in_spec(1, spec[len('except'):].strip()))
            or (spec.startswith('remove') and _vlan_in_spec(1, spec[len('remove'):].strip()))
            or (not spec.startswith(('except', 'remove', 'add')) and not _vlan_in_spec(1, spec))
        )
        if not pruned:
            bad.append(f'{name} (`switchport trunk allowed vlan {spec}` still allows VLAN 1)')
    if bad:
        return False, 'VLAN 1 not pruned on: ' + '; '.join(bad)
    return True, f'VLAN 1 pruned on all {len(trunk)} trunk port(s): {", ".join(sorted(trunk))}'


# V-220647: no access port may be assigned to a trunk's native VLAN (double-
# encapsulation/VLAN-hopping risk). Determines the actual native VLAN(s) in use
# from each trunk's 'switchport trunk native vlan <id>' line - IOS's default
# native VLAN (1) if a trunk has no explicit line - then checks every access
# port's actual VLAN (also defaulting to 1 if unset) against that set.
def _no_access_ports_on_native_vlan(cfg):
    access, trunk = parse_switchports(cfg)
    if not trunk:
        return False, 'no trunk switchports found in config, cannot determine native VLAN'
    native_vlans = set()
    for name, block in trunk.items():
        m = re.search(r'switchport trunk native vlan (\d+)', block)
        native_vlans.add(m.group(1) if m else '1')
    if not access:
        return True, f'no access ports found - nothing to check against native VLAN(s) {", ".join(sorted(native_vlans))}'
    bad = []
    for name, block in sorted(access.items()):
        m = re.search(r'switchport access vlan (\d+)', block)
        actual = m.group(1) if m else '1'
        if actual in native_vlans:
            bad.append(f'{name} (VLAN {actual})')
    if bad:
        return False, f'access port(s) assigned to the native VLAN: {", ".join(bad)}'
    return True, f'no access ports assigned to native VLAN(s) {", ".join(sorted(native_vlans))}'


# V-220641: disabled (shutdown) access ports must be assigned to the designated
# unused VLAN, and that VLAN must be pruned from all trunk links (same pruning
# logic as default_vlan_pruned_from_trunks, but for the unused VLAN instead of 1).
# Check Content's Step 1 carries "Note: Switch ports configured for 802.1x are
# exempt from this requirement" - unlike Discussion-only rationale (see
# V-220696), this Note is part of Check Content itself, so a shutdown port
# with 802.1x/MAB configured (_dot1x_mab_check's detection) is skipped rather
# than required to sit on the unused VLAN.
def _disabled_ports_unused_vlan_check(cfg, unused_vlan):
    if unused_vlan is None:
        return False, 'no `unused_vlan` configured in inventory.yaml'
    access, trunk = parse_switchports(cfg)

    bad_access = []
    exempt_count = 0
    disabled_count = 0
    for name, block in sorted(access.items()):
        if not re.search(r'^\s*shutdown\s*$', block, re.M):
            continue
        has_dot1x = re.search(r'dot1x pae authenticator', block) and re.search(r'authentication port-control auto', block)
        has_mab = re.search(r'^\s*mab\s*$', block, re.M)
        if has_dot1x or has_mab:
            exempt_count += 1
            continue
        disabled_count += 1
        m = re.search(r'switchport access vlan (\d+)', block)
        actual = m.group(1) if m else 'default (untagged, VLAN 1)'
        if not m or int(m.group(1)) != unused_vlan:
            bad_access.append(f'{name} (VLAN {actual})')
    if bad_access:
        return False, f'disabled access port(s) not assigned to VLAN {unused_vlan}: {", ".join(bad_access)}'

    bad_trunk = []
    for name, block in sorted(trunk.items()):
        m = re.search(r'switchport trunk allowed vlan (.+)$', block, re.M)
        if not m:
            bad_trunk.append(f'{name} (no allowed-vlan restriction, VLAN {unused_vlan} allowed by default)')
            continue
        spec = m.group(1).strip()
        pruned = (
            (spec.startswith('except') and _vlan_in_spec(unused_vlan, spec[len('except'):].strip()))
            or (spec.startswith('remove') and _vlan_in_spec(unused_vlan, spec[len('remove'):].strip()))
            or (not spec.startswith(('except', 'remove', 'add')) and not _vlan_in_spec(unused_vlan, spec))
        )
        if not pruned:
            bad_trunk.append(f'{name} (`switchport trunk allowed vlan {spec}` still allows VLAN {unused_vlan})')
    if bad_trunk:
        return False, f'VLAN {unused_vlan} not pruned from trunk(s): {"; ".join(bad_trunk)}'

    exempt_note = f', {exempt_count} exempt (802.1x/MAB configured)' if exempt_count else ''
    return True, f'{disabled_count} disabled access port(s) correctly assigned to VLAN {unused_vlan}{exempt_note}, pruned from all {len(trunk)} trunk port(s)'


# V-220586: presence of any of these directives (not "no "-prefixed) is a finding -
# unnecessary/nonsecure services that should stay disabled by default.
UNNECESSARY_SERVICES_PATTERN = (
    r'^\s*(boot network|ip boot server|ip bootp server|ip dns server|ip identd|'
    r'ip finger|ip http server|ip rcmd rcp-enable|ip rcmd rsh-enable|'
    r'service config|service finger|service tcp-small-servers|'
    r'service udp-small-servers|service pad|service call-home)\s*$'
)


def _no_unnecessary_services(cfg):
    found = sorted(set(re.findall(UNNECESSARY_SERVICES_PATTERN, cfg, re.M)))
    if found:
        return False, f'enabled (should be disabled): {", ".join(found)}'
    return True, 'none of the unnecessary/nonsecure services found enabled'


def _vlan_range_covers_user_vlans(cfg, pattern, user_vlans, missing_line_what):
    """PASS only if the VLAN range captured by `pattern` (e.g. from an
    `ip dhcp snooping vlan <spec>` or `ip arp inspection vlan <spec>` line)
    actually covers every VLAN in `user_vlans` - not just that *some* list is
    configured. Catches the case where the feature is scoped to the wrong VLANs
    (e.g. management/default) while the real user VLAN has none."""
    m = re.search(pattern, cfg, re.M)
    if not m:
        return False, f'missing {missing_line_what}'
    spec = m.group(1)
    if not user_vlans:
        return False, 'no genuine user VLANs discovered from `show vlan brief` (check inventory.yaml non_user_vlans / device VLAN config)'
    missing = [v for v in user_vlans if not _vlan_in_spec(int(v), spec)]
    if missing:
        return False, f'configured VLAN range `{spec}` does not cover user VLAN(s): {", ".join(missing)}'
    return True, f'`{spec}` covers all user VLAN(s): {", ".join(sorted(user_vlans, key=int))}'


def _dhcp_snooping_check(cfg, user_vlans):
    if not re.search(r'^ip dhcp snooping$', cfg, re.M):
        return False, 'missing `ip dhcp snooping` (globally enabled)'
    return _vlan_range_covers_user_vlans(
        cfg, r'ip dhcp snooping vlan (\S+)', user_vlans, 'an `ip dhcp snooping vlan <list>` line'
    )


# V-220575: vty access-class ACL must actually be scoped to the management
# subnet, not just present. A "permit any" or out-of-subnet source doesn't
# satisfy "controlling the flow of management information."
def _acl_source_network(source_spec):
    """The network an ACL permit's source names, or None if this cannot read
    one from it.

    None is not "outside the management network" and must not be reported as
    though it were - see _source_is_readable, which uses this to send the
    entry to a human instead. The case that made the difference matter is a
    non-contiguous wildcard: `0.0.255.0` is a legal ACL mask and names no
    network at all in CIDR terms, so it has no prefix length to compare, and
    reporting it as a source outside the management network would be a finding
    invented out of not being able to read the line."""
    source_spec = source_spec.strip()
    m = re.match(r'host (\S+)$', source_spec)
    if m:
        try:
            return ipaddress.ip_network(m.group(1) + '/32', strict=False)
        except ValueError:
            return None
    m = re.match(r'(\S+)\s+(\S+)$', source_spec)
    if m:
        addr, wildcard = m.groups()
        try:
            netmask = ipaddress.ip_address(int(ipaddress.ip_address(wildcard)) ^ 0xFFFFFFFF)
            return ipaddress.ip_network(f'{addr}/{netmask}', strict=False)
        except ValueError:
            return None
    # Bare address with no wildcard - a standard ACL's implicit single host
    # (`permit 10.1.1.5`). Extended ACLs never produce this shape.
    try:
        return ipaddress.ip_network(source_spec + '/32', strict=False)
    except ValueError:
        return None


def _acl_source_in_networks(source_spec, networks):
    """Whether a permit's source sits inside any one of the management
    networks. `any` never does, whatever they are."""
    if source_spec.strip() == 'any':
        return False
    source = _acl_source_network(source_spec)
    if source is None:
        return False
    return any(source.subnet_of(network) for network in networks)


# A management network is not always one prefix. A site whose out-of-band
# addressing grew a second range, or which manages from a jump network as well
# as an admin VLAN, writes several permits into the vty ACL - each one legal,
# each one inside "the management network" as the site defines it - and a
# single CIDR in inventory.yaml cannot say so. So this takes one or several.
#
# What it must not become is a list widened until it covers whatever the ACL
# already permits. The whole value of this check is that the ACL is compared
# against a management network declared independently of it; a list
# reverse-engineered from the ACL makes the rule pass by construction and
# tests nothing.
def _management_networks(subnet_spec):
    """(networks, unreadable) from inventory's management_subnet, which may be
    one CIDR, several separated by commas or whitespace, or a YAML list."""
    if isinstance(subnet_spec, str):
        items = [part for part in re.split(r'[,\s]+', subnet_spec) if part]
    elif subnet_spec:
        items = [str(part).strip() for part in subnet_spec if str(part).strip()]
    else:
        items = []
    networks, unreadable = [], []
    for item in items:
        try:
            networks.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            unreadable.append(item)
    return networks, unreadable


# Standard ACL numbers per IOS: 1-99 and 1300-1999. Everything else applied
# with access-class is treated as extended.
def _numbered_acl_kind(name):
    if not name.isdigit():
        return None
    number = int(name)
    return 'standard' if (1 <= number <= 99 or 1300 <= number <= 1999) else 'extended'


def _vty_acl_blocks(cfg):
    """Return (line_vty_chunk, acl_name_or_None, acl_block_or_None, kind) for
    EVERY 'line vty ...' stanza - handles split vty ranges (e.g. 'line vty 0 1'
    / 'line vty 2 4', a real DISA-endorsed pattern shown in the checklist's own
    V-220570 example). The old version stopped at the first 'line vty' chunk
    that had an access-class applied, silently ignoring any other vty range
    that lacked one - a false PASS if a split range left one segment open.

    `kind` is 'standard' or 'extended', because the two spell their entries
    differently and the callers have to parse accordingly. Both matter: the
    IOS book's V-220575 fix text builds an extended ACL, the IOS XE book's
    V-220523 builds a *standard* one for the same requirement. Only matching
    extended would false-FAIL a switch configured exactly per DISA's own IOS
    XE instructions. Numbered ACLs are supported too - they are common on real
    switches even though neither book's example uses one, and their entries
    live as scattered top-level lines rather than a block."""
    results = []
    for chunk in re.split(r'^(?=\S)', cfg, flags=re.M):
        if not chunk.startswith('line vty'):
            continue
        m = re.search(r'access-class (\S+) in', chunk)
        acl_name = m.group(1) if m else None
        acl_block, kind = None, None
        if acl_name:
            for c2 in re.split(r'^(?=\S)', cfg, flags=re.M):
                m2 = re.match(rf'ip access-list (standard|extended) {re.escape(acl_name)}\s*$',
                              c2.splitlines()[0] if c2.splitlines() else '')
                if m2:
                    acl_block, kind = c2, m2.group(1)
                    break
            if acl_block is None:
                numbered = re.findall(rf'^access-list {re.escape(acl_name)} (.+)$', cfg, re.M)
                if numbered:
                    acl_block = '\n'.join(numbered)
                    kind = _numbered_acl_kind(acl_name) or 'extended'
        results.append((chunk, acl_name, acl_block, kind))
    return results


# An extended ACE names its source right after the protocol, in one of three
# shapes: `any`, `host <addr>`, or `<addr> <wildcard>`. Everything after it -
# the destination, a port operator, `log` - is another entry's business, and
# this rule only asks who is permitted in.
def _take_source_spec(tokens):
    if not tokens:
        return None
    if tokens[0] == 'any':
        return 'any'
    if tokens[0] == 'host':
        return f'host {tokens[1]}' if len(tokens) >= 2 else None
    if len(tokens) >= 2:
        return f'{tokens[0]} {tokens[1]}'
    return None


# The vty ACL that survives a real switch is rarely `permit ip <source> any`.
# DISA's own fix text builds that shape, but an ACL written to let the
# management network reach SSH and nothing else reads
# `permit tcp <source> <wildcard> any eq 22 log` - narrower than what the rule
# asks for, and it was being read as an ACL with no permit entries at all, so
# the rule FAILed a switch that is more restrictive than compliant. Confirmed
# on the work fleet. Any protocol is accepted now; what the rule is actually
# about is the source, and that is still checked against the management subnet
# exactly as before.
def _acl_permit_sources(acl_block, kind):
    """Source specs from an ACL's permit entries, in whichever syntax the ACL
    uses: `permit <protocol> <source> <destination> ...` for extended,
    `permit <source>` for standard (no protocol, no destination)."""
    if kind == 'standard':
        # A trailing `log`/`log-input` is a logging keyword, not part of the
        # source - left on, the whole entry reads as an address this cannot
        # resolve, and a permit squarely inside the management subnet is
        # reported as needing review by hand.
        return [re.sub(r'\s+log(-input)?$', '', s.strip()) for s in re.findall(
            r'^\s*(?:\d+\s+)?permit\s+(.+?)\s*$', acl_block, re.M)]
    sources = []
    for rest in re.findall(r'^\s*(?:\d+\s+)?permit\s+(\S+)\s+(.+?)\s*$', acl_block, re.M):
        source = _take_source_spec(rest[1].split())
        if source:
            sources.append(source)
    return sources


# A source this cannot read as an address - `object-group MGMT`, an FQDN - is
# not the same finding as one that resolves and sits outside the management
# subnet, and must not be reported as though it were. Neither is a pass: the
# group's contents are not in the text handed to this check.
def _source_is_readable(source_spec):
    return source_spec.strip() == 'any' or _acl_source_network(source_spec) is not None


def _vty_management_acl_check(cfg, subnet_str):
    networks, unreadable_subnets = _management_networks(subnet_str)
    if unreadable_subnets:
        # A netmask instead of a prefix length is the easy typo. One bad value
        # costs this rule its verdict; it must not cost the whole report, which
        # is what an uncaught ValueError here used to do mid-fleet-run.
        return False, (f'`management_subnet` in inventory.yaml is not a network: '
                       f'{", ".join(repr(item) for item in unreadable_subnets)} '
                       f'- expected CIDR form, e.g. 10.10.50.0/24, or several of them')
    if not networks:
        return False, 'no `management_subnet` configured in inventory.yaml'
    subnet_str = ', '.join(str(network) for network in networks)

    vty_blocks = _vty_acl_blocks(cfg)
    if not vty_blocks:
        return False, 'no `line vty` block found'

    problems, compliant = [], []
    for chunk, acl_name, acl_block, kind in vty_blocks:
        header = chunk.splitlines()[0].strip()
        if not acl_name:
            problems.append(f'{header}: no `access-class <name> in` applied')
            continue
        if acl_block is None:
            problems.append(f'{header}: `access-class {acl_name} in` applied, but no matching '
                            f'`ip access-list standard|extended {acl_name}` block or '
                            f'`access-list {acl_name} ...` lines found')
            continue
        permits = _acl_permit_sources(acl_block, kind)
        shape = ('permit <source>' if kind == 'standard'
                 else 'permit <protocol> <source> <destination>')
        if not permits:
            problems.append(f'{header}: {kind} ACL `{acl_name}` has no `{shape}` lines')
            continue
        unreadable = [src for src in permits if not _source_is_readable(src)]
        if unreadable:
            problems.append(f'{header}: `{acl_name}` permits source(s) this cannot resolve from '
                            f'config text (review by hand): {", ".join(unreadable)}')
            continue
        bad = [src for src in permits if not _acl_source_in_networks(src, networks)]
        if bad:
            problems.append(f'{header}: `{acl_name}` permits source(s) outside {subnet_str}: {", ".join(bad)}')
            continue
        compliant.append(f'{header}: {kind} ACL `{acl_name}` permits only sources within {subnet_str}: {", ".join(permits)}')
    if problems:
        return False, '; '.join(problems)
    return True, '; '.join(compliant)


# V-220581: partial coverage only - confirms the vty management ACL's
# trailing deny carries `log-input` (rejected access attempts get logged
# with source/interface info instead of vanishing into the implicit deny).
# Says nothing about general data-plane traffic, and nothing about whether
# these log entries actually reach the syslog servers (see
# l2_stig_harden_acl.py - they don't, at `logging trap critical`).
def _vty_acl_log_input_check(cfg):
    vty_blocks = _vty_acl_blocks(cfg)
    if not vty_blocks:
        return False, 'no `line vty` block found'

    problems, compliant = [], []
    for chunk, acl_name, acl_block, kind in vty_blocks:
        header = chunk.splitlines()[0].strip()
        if not acl_name:
            problems.append(f'{header}: no `access-class <name> in` applied')
            continue
        if acl_block is None:
            problems.append(f'{header}: `access-class {acl_name} in` applied, but no matching '
                            f'`ip access-list standard|extended {acl_name}` block or '
                            f'`access-list {acl_name} ...` lines found')
            continue
        # A standard ACL has no protocol or destination to name, so its logged
        # trailing deny is `deny any log` - `log-input` is accepted but not
        # required there, since standard ACLs on vty lines commonly only
        # support `log`. Extended keeps requiring log-input, which is what the
        # rule's own fix text configures.
        if kind == 'standard':
            pattern, shape = r'^\s*(?:\d+\s+)?deny\s+any\s+log(-input)?\s*$', 'deny any log'
        else:
            pattern, shape = r'^\s*(?:\d+\s+)?deny\s+ip any any log-input\s*$', 'deny ip any any log-input'
        if not re.search(pattern, acl_block, re.M):
            problems.append(f'{header}: {kind} ACL `{acl_name}` has no `{shape}` line')
            continue
        compliant.append(f'{header}: `{acl_name}` has a logged trailing deny (`{shape}`)')
    if problems:
        return False, '; '.join(problems)
    return True, '; '.join(compliant)


# V-220571/572/573/574/582/597/611/613: DISA reuses the exact same evidence
# (archive / log config / logging enable) for 8 different audit-logging rules
# (account creation/modification/disabling/removal/enabling, privileges deleted,
# privileged activities, full-text privileged-command logging) - one check
# covers all of them.
def _archive_logging_enabled(cfg):
    for chunk in re.split(r'^(?=\S)', cfg, flags=re.M):
        if chunk.startswith('archive'):
            missing = [c for c in ('log config', 'logging enable') if c not in chunk]
            if missing:
                return False, f'`archive` block present but missing: {", ".join(missing)}'
            return True, 'found: `archive` / `log config` / `logging enable`'
    return False, 'missing `archive` block (with `log config` / `logging enable`)'


# V-220578: administrator activity logging - logging userinfo (privilege escalation)
# plus the same archive block as the 8-rule cluster above
def _admin_activity_logged(cfg):
    if 'logging userinfo' not in cfg:
        return False, 'missing `logging userinfo`'
    archive_ok, archive_reason = _archive_logging_enabled(cfg)
    if not archive_ok:
        return False, f'`logging userinfo` present, but {archive_reason}'
    return True, f'found: `logging userinfo`, {archive_reason}'


# V-220570 (IOS) / V-220518 (IOS XE): concurrent management sessions limited to
# an organization-defined number. The Check Content gives three ways, and DISA
# leads its Fix Text with the third:
#
#   ip http max-connections 2
#   line vty 0 4 / session-limit 2                      (where supported)
#   line vty 0 1 / transport input ssh                  (where it is not)
#   line vty 2 4 / transport input none
#
# That last pair is the one this used to miss. A switch hardened exactly as
# DISA's own Fix Text shows - vty 0-1 answering SSH, 2-4 answering nothing -
# carries neither of the other two lines, and was reported as having no session
# limit at all. It is the same false FAIL as reading the management ACL as
# `permit ip <source> any` only: the rule met by a shape the check did not know.
#
# It also matters more on a switch with HTTP off, which is the normal hardened
# state - `no ip http server` is pushed by the hardening scripts - because then
# `ip http max-connections` is configuration for a service that is not running,
# and the vty lines are the only thing actually limiting anything.
def _disabled_vty_ranges(cfg):
    """Ranges of vty lines answering nothing, as ('line vty 2 4', count) pairs."""
    disabled = []
    for chunk in re.split(r'^(?=line )', cfg, flags=re.M):
        header = re.match(r'line vty (\d+)(?:\s+(\d+))?', chunk)
        if not header or not re.search(r'^\s*transport input none\s*$', chunk, re.M):
            continue
        first = int(header.group(1))
        last = int(header.group(2)) if header.group(2) else first
        disabled.append((chunk.splitlines()[0].strip(), last - first + 1))
    return disabled


def _session_limit_check(cfg):
    http_m = re.search(r'^ip http max-connections (\d+)', cfg, re.M)
    session_m = re.search(r'^\s*session-limit (\d+)', cfg, re.M)
    disabled = _disabled_vty_ranges(cfg)
    if http_m or session_m or disabled:
        found = []
        if session_m:
            found.append(f'session-limit {session_m.group(1)}')
        for header, count in disabled:
            found.append(f'`{header}` answers nothing (`transport input none`), '
                         f'{count} line(s) taken out of service')
        if http_m:
            found.append(f'ip http max-connections {http_m.group(1)}')
        return True, f'found: {", ".join(found)}'
    return False, ('no session limit: none of `line vty ... session-limit <n>`, '
                   '`transport input none` on unused vty lines, or '
                   '`ip http max-connections <n>`')


# V-220589/590/591/592/593/594: password complexity, each is one sub-command
# inside an `aaa common-criteria policy <name>` block.
def _cc_policy_check(cfg, pattern, min_value, what):
    """Each of the six sub-rules used to be checked against ANY
    `aaa common-criteria policy` block found in config, not necessarily the
    one actually in effect - a stale/leftover block from earlier testing
    (e.g. missing this specific requirement in the real policy) could
    satisfy the check even though the policy actually applied to accounts
    doesn't meet it. Requires there be exactly one policy block; more than
    one is treated as ambiguous (can't tell which one is in effect) rather
    than silently picking one. Note: this project's harden script
    (l2_stig_harden_aaa.py) doesn't currently push a
    `username <name> common-criteria-policy <name>` line linking a specific
    account to a specific policy (per V-220587's own Fix Text, it should) -
    with only one policy block ever created, "exactly one block" is
    equivalent to "the one in effect" in practice; if this project starts
    creating multiple named policies, this check would need to correlate
    against that username-level reference instead."""
    if 'aaa new-model' not in cfg:
        return False, 'missing `aaa new-model`'
    policy_blocks = [
        chunk for chunk in re.split(r'^(?=\S)', cfg, flags=re.M)
        if chunk.startswith('aaa common-criteria policy')
    ]
    if not policy_blocks:
        return False, 'no `aaa common-criteria policy` block found'
    if len(policy_blocks) > 1:
        names = [c.split()[3] if len(c.split()) > 3 else '?' for c in policy_blocks]
        return False, f'{len(policy_blocks)} `aaa common-criteria policy` blocks found ({", ".join(names)}) - ambiguous which one is actually applied'
    chunk = policy_blocks[0]
    m = re.search(pattern, chunk, re.M)
    if m and int(m.group(1)) >= min_value:
        return True, f'found: `{m.group(0).strip()}`'
    return False, f'the single `aaa common-criteria policy` block does not have {what} >= {min_value}'


def _single_local_account_check(cfg):
    usernames = re.findall(r'^username (\S+)', cfg, re.M)
    if len(usernames) != 1:
        found = ', '.join(usernames) if usernames else 'none'
        return False, f'found {len(usernames)} `username` line(s) (need exactly 1): {found}'
    if not re.search(r'^aaa authentication \S+ \S+ group \S+ local\s*$', cfg, re.M):
        return False, f'exactly 1 local account (`{usernames[0]}`) found, but no `aaa authentication ... group <server> local` fallback line'
    return True, f'exactly 1 local account (`{usernames[0]}`), configured as fallback after the AAA server group'


# V-220617 / IOS XE V-220565: at least 2 RADIUS servers, actually used as the
# primary auth source (not just configured but unused). Checks both the classic
# single-line 'radius-server host <ip>' form and the modern block-style
# 'radius server <name>' / 'address ipv4 <ip> ...' form - confirmed live that
# this lab's vios_l2 image only accepts the modern form ("radius-server host"
# is rejected outright), but other platforms may still use the classic one.
#
# The method list may name the built-in `radius` group or a named group
# defined with `aaa group server radius <name>`. The IOS XE book's fix text
# uses a named group throughout ("aaa group server radius radius_group" /
# "aaa authentication login console group radius_group local"), so requiring
# the literal word `radius` as the group would false-FAIL a switch configured
# exactly per DISA's own IOS XE instructions. A named group is only accepted
# when it is actually defined, so an arbitrary word cannot pass for one.
def _radius_redundancy_check(cfg):
    if 'aaa new-model' not in cfg:
        return False, 'missing `aaa new-model`'
    named_groups = set(re.findall(r'^aaa group server radius (\S+)', cfg, re.M))
    method_groups = set(re.findall(r'^aaa authentication \S+ \S+ group (\S+)', cfg, re.M))
    if not (method_groups & ({'radius'} | named_groups)):
        detail = f' (defined RADIUS groups: {", ".join(sorted(named_groups))})' if named_groups else ''
        return False, ('missing an `aaa authentication ... group radius ...` line using RADIUS as '
                       f'the primary source, or a `group <name>` naming a defined '
                       f'`aaa group server radius` group{detail}')
    legacy_servers = re.findall(r'^radius-server host (\S+)', cfg, re.M) + re.findall(r'^radius host (\S+)', cfg, re.M)
    modern_servers = []
    for chunk in re.split(r'^(?=\S)', cfg, flags=re.M):
        if chunk.startswith('radius server '):
            m = re.search(r'^\s*address ipv4 (\S+)', chunk, re.M)
            if m:
                modern_servers.append(m.group(1))
    servers = sorted(set(legacy_servers + modern_servers))
    if len(servers) >= 2:
        return True, f'found {len(servers)} RADIUS server(s): {", ".join(servers)}'
    if servers:
        return False, f'only {len(servers)} of 2+ required RADIUS server(s) found: {", ".join(servers)}'
    return False, 'no RADIUS servers found (checked classic `radius-server host` and modern `radius server <name>`/`address ipv4` forms - need 2+)'


# V-220624: VTP passwords are deliberately excluded from `show running-config`
# on Cisco IOS (so they don't leak into config backups/TFTP exports) - confirmed
# live that this holds even in VTP transparent mode, not a platform quirk. IOS
# even confirms a redundant push with "Password already set to <value>" rather
# than silently no-op'ing, proving it's genuinely active despite never
# appearing in the config text. A regex against running-config can never find
# it, so this needs live `show vtp password` output instead.
#
# Three answers, not two. Which one a switch gives depends on the platform and
# on whether it will disclose the value at all:
#
#   VTP Password: <value>            the value, IOS classic
#   VTP Password is configured       set, value withheld
#   The VTP password is not configured / not set    nothing set
#
# Only the first and the "not set" wording were recognised, so the middle form
# - a switch that IS compliant and says so - fell through to "unexpected
# output" and was reported FAIL. Confirmed on the work fleet, where the
# switches are VTP transparent and answer with the middle form. The negative
# wording is tested first: "is not configured" contains "is configured".
def _vtp_password_check(vtp_password_output):
    if not vtp_password_output:
        return False, 'no VTP password set (`show vtp password` returned nothing)'
    if re.search(r'not (set|configured)', vtp_password_output, re.I):
        return False, 'no VTP password set (`show vtp password` reports none)'
    m = re.search(r'VTP Password:\s*(\S+)', vtp_password_output, re.I)
    if m:
        # The value itself is never printed - the rule only asks whether a
        # password is set, and audit output gets pasted into tickets and
        # reports. Length is enough to tell a real password from a stray
        # placeholder without disclosing it.
        return True, f'VTP password set (`show vtp password`): {len(m.group(1))} characters'
    if re.search(r'password is configured', vtp_password_output, re.I):
        return True, 'VTP password set (`show vtp password` reports it configured, value withheld)'
    return False, 'unexpected `show vtp password` output (withheld - may contain the password)'


# V-220576: exactly 3 consecutive invalid attempts, blocked for >= 900s (15 min)
def _login_block_check(cfg):
    m = re.search(r'^login block-for (\d+) attempts (\d+) within (\d+)', cfg, re.M)
    if not m:
        return False, 'missing `login block-for <secs> attempts <n> within <secs>` line'
    block_secs, attempts, within_secs = int(m.group(1)), int(m.group(2)), int(m.group(3))
    found = f'`login block-for {block_secs} attempts {attempts} within {within_secs}`'
    if attempts != 3:
        return False, f'found {found} but attempts must be exactly 3'
    if block_secs < 900:
        return False, f'found {found} but block-for must be >= 900 (15 min)'
    return True, f'found: {found}'


# V-220629: Root Guard belongs on trunk ports connecting to other switches, but
# never on this switch's own STP root port (see
# stig_common.discover_root_port_interfaces for why). A switch whose only trunk
# port(s) are all root ports (e.g. a leaf/access switch with no downstream
# switches of its own) has nothing eligible to guard - that's a PASS, not a
# finding, since there's nothing wrong to fix.
def _root_guard_check(cfg, root_ports):
    _, trunk = parse_switchports(cfg)
    eligible = sorted(name for name in trunk if name not in root_ports)
    if not eligible:
        return True, (
            'no eligible trunk ports - every trunk port is this switch\'s STP root port '
            'toward the root bridge, and Root Guard must not be applied there'
        )
    missing = [name for name in eligible if not re.search(r'spanning-tree guard root', trunk[name])]
    if missing:
        return False, (
            f'missing `spanning-tree guard root` on: {", ".join(missing)} '
            f'(root port(s) excluded from this check: {", ".join(sorted(root_ports)) or "none"})'
        )
    return True, f'`spanning-tree guard root` present on all {len(eligible)} eligible trunk port(s): {", ".join(eligible)}'


def _line_exec_timeout_ok(chunk):
    """True if `chunk` (a `line ...` block) has a compliant exec-timeout
    (nonzero, <=5 min). Returns (ok, matched_text_or_None)."""
    m = re.search(r'exec-timeout (\d+) (\d+)', chunk)
    if not m:
        return False, None
    minutes, seconds = int(m.group(1)), int(m.group(2))
    ok = not (minutes == 0 and seconds == 0) and minutes <= 5
    return ok, m.group(0)


def _exec_timeout_reason(cfg):
    """V-220596: DISA's Fix Text configures exec-timeout on both the console
    line and vty - checking cfg as a whole via stig_common.exec_timeout_ok()
    (whatever exec-timeout lines happen to be present) silently false-passes
    if one line (most commonly console, since IOS never prints an unset line
    at its own default) is left unconfigured as long as some other line is
    already compliant. Checks console and vty as separate, required scopes
    instead.
    ALL vty blocks must be individually compliant, not just one - the old
    version ORed across multiple vty blocks (e.g. a split 'line vty 0 1' /
    'line vty 2 4' range), so a device with only one segment configured
    still reported PASS even though the other segment never terminates a
    session, contradicting the check text's literal 'terminate ALL network
    connections' requirement."""
    con_ok = con_match = None
    vty_results = []
    for chunk in re.split(r'^(?=line \S)', cfg, flags=re.M):
        header = chunk.splitlines()[0] if chunk else ''
        if header.startswith('line con'):
            con_ok, con_match = _line_exec_timeout_ok(chunk)
        elif header.startswith('line vty'):
            ok, match = _line_exec_timeout_ok(chunk)
            vty_results.append((header.strip(), ok, match))

    vty_ok = bool(vty_results) and all(ok for _, ok, _ in vty_results)

    if con_ok and vty_ok:
        vty_summary = ', '.join(f'{h} (`{m}`)' for h, _, m in vty_results)
        return True, f'compliant on console (`{con_match}`) and vty: {vty_summary}'

    missing = []
    if not con_ok:
        missing.append('console (`line con 0`): ' + (f'non-compliant (`{con_match}`)' if con_match else 'no exec-timeout set'))
    if not vty_ok:
        if not vty_results:
            missing.append('vty: no `line vty` block found')
        else:
            bad = [f'{h}: ' + (f'non-compliant (`{m}`)' if m else 'no exec-timeout set') for h, ok, m in vty_results if not ok]
            missing.append('vty: ' + '; '.join(bad))
    return False, '; '.join(missing)


# V-220600: alert for audit failure events. DISA's own check discussion notes
# "Informational is the default severity level; hence, if the severity level
# is configured to informational, the logging trap command will not be
# present in the configuration file" - so a missing line means the (more
# inclusive) default, not a finding. Only an explicitly-configured level
# narrower than 'critical' (emergencies/alerts) is actually non-compliant.
_SYSLOG_SEVERITY_RANK = {
    'emergencies': 0, 'alerts': 1, 'critical': 2, 'errors': 3,
    'warnings': 4, 'notifications': 5, 'informational': 6, 'debugging': 7,
}


def _logging_trap_check(cfg):
    m = re.search(r'^logging trap (\S+)', cfg, re.M)
    if not m:
        return True, 'no explicit `logging trap <level>` line - defaults to `informational`, which satisfies this (broader than the required `critical` minimum)'
    level = m.group(1).lower()
    rank = _SYSLOG_SEVERITY_RANK.get(level)
    if rank is None:
        return False, f'found `logging trap {level}` but unrecognized severity level'
    if rank < _SYSLOG_SEVERITY_RANK['critical']:
        return False, f'found `logging trap {level}` - narrower than the required `critical` minimum (misses errors/warnings/notifications/informational events)'
    return True, f'found: `logging trap {level}`'


# V-220583/584/585: protect audit info from unauthorized modification/
# deletion, and limit privileges to change software libraries - DISA reuses
# the same evidence (file privilege 15) for all three, and all three are
# explicitly conditional: "If persistent logging is enabled ... Otherwise,
# this requirement is not applicable."
#
# No `logging persistent` line is NOT APPLICABLE, not PASS. Both are
# non-findings and the distinction looks cosmetic from inside the script, but
# it is the difference between two sentences on a checklist: PASS says the
# switch protects its persistent log files, and the switch keeps no persistent
# log files at all. Reported as PASS, three rules on every report claimed
# evidence for something never examined, and the reason line contradicted the
# status beside it. `NOT_A_FINDING` and `NOT_APPLICABLE` are also different
# statuses in a .cklb, so this is the one that transcribes correctly.
def _audit_info_protection_check(cfg):
    if not re.search(r'^logging persistent', cfg, re.M):
        return None, 'persistent logging not configured - not applicable per DISA (only required when `logging persistent` is enabled)'
    # Absence of `file privilege` is compliance, not a missing fix. The rule's
    # own Note says so: "The default privilege level required for access to the
    # file system is 15; hence, the command file privilege 15 will not be shown
    # in the configuration", and its finding is "if the switch is configured
    # with a privilege level OTHER than 15". Requiring the line to be present
    # failed every switch that had never been told to lower it - the one state
    # the rule is written to accept.
    m = re.search(r'^file privilege (\d+)', cfg, re.M)
    if m and m.group(1) != '15':
        return False, (
            f'persistent logging enabled and `file privilege {m.group(1)}` opens the file '
            'system - and the persistent log files on it - to privilege level '
            f'{m.group(1)}, below the 15 this rule requires'
        )
    if m:
        return True, 'persistent logging enabled and `file privilege 15` present'
    return True, (
        'persistent logging enabled and no `file privilege` line, so file-system access is '
        'at the IOS default of privilege 15 (which DISA notes is never shown in the config)'
    )


# V-220644: default VLAN (1) must not carry management traffic - verifies
# 'interface Vlan1' has no IP address configured. Devices in this repo use
# VLAN 10 for management (see inventory.yaml/non_user_vlans), so this should
# already pass everywhere; this is a check that a real config regression
# (someone addressing Vlan1 directly) would actually be caught.
def _no_management_on_default_vlan(cfg):
    for chunk in re.split(r'^(?=interface \S+)', cfg, flags=re.M):
        if re.match(r'interface Vlan1\s*$', chunk, re.M):
            if re.search(r'^\s*ip address \S+', chunk, re.M):
                return False, '`interface Vlan1` has an IP address configured - the default VLAN must not be used for management traffic'
            return True, '`interface Vlan1` exists but has no IP address configured'
    return True, 'no `interface Vlan1` found in config - default VLAN not used for management'


def _snmpv3_user_live_check(show_snmp_user_output, require_priv):
    """V-220604/605: confirmed live on S1 that Cisco IOS classic never writes
    SNMPv3 user config to `show running-config` at all - `snmp-server group
    ... v3 priv` showed, but no `snmp-server user ...` line ever appeared
    despite `show snmp user` confirming SHA auth + AES128 privacy were
    genuinely active. Localized/encrypted against the SNMP engine ID, same
    category of platform quirk as the VTP password (_vtp_password_check),
    so this needs live `show snmp user` output instead of running-config text."""
    auth_m = re.search(r'Authentication Protocol:\s*(\S+)', show_snmp_user_output, re.I)
    if not auth_m or auth_m.group(1).lower() == 'none':
        return False, 'no SNMPv3 user with an authentication protocol found (`show snmp user`)'
    if 'sha' not in auth_m.group(1).lower():
        return False, f'SNMPv3 user authentication protocol is not SHA: `{auth_m.group(0)}`'
    if not require_priv:
        return True, f'SNMPv3 user authenticated with SHA (`show snmp user`): `{auth_m.group(0)}`'
    priv_m = re.search(r'Privacy Protocol:\s*(\S+)', show_snmp_user_output, re.I)
    if not priv_m or 'aes' not in priv_m.group(1).lower():
        detail = f'`{priv_m.group(0)}`' if priv_m else 'no `Privacy Protocol` line'
        return False, f'SNMPv3 user auth is SHA but privacy protocol is not AES: {detail}'
    return True, f'SNMPv3 user with SHA auth + AES privacy (`show snmp user`): `{auth_m.group(0)}`, `{priv_m.group(0)}`'


def _ntp_md5_correlated_keys(cfg):
    """Key IDs used consistently across `ntp authentication-key <id> md5`,
    `ntp trusted-key <id>` and `ntp server <ip> key <id>`.

    Correlation matters: each line existing somewhere in config proves
    nothing, since a trusted key nothing points at authenticates nothing.
    Shared by both NTP rules below, which read the same evidence and reach
    opposite verdicts because their STIGs ask different questions."""
    return (set(re.findall(r'ntp authentication-key (\d+) md5 \S+', cfg))
            & set(re.findall(r'ntp trusted-key (\d+)', cfg))
            & set(re.findall(r'ntp server \S+ key (\d+)', cfg)))


def _ntp_auth_check(cfg):
    """V-220606 (IOS): Check Content's own text: "Cisco IOS is limited to MD5
    for NTP authentication, and incurs a permanent finding as it is not FIPS
    compliant." No IOS configuration can ever satisfy this rule, so it
    always reports FAIL regardless of config - the old version returned
    True once all four MD5-based commands were present anywhere in config,
    a false PASS against the checklist's own stated verdict (same shape as
    the NX-OS V-220502 bug fixed today).

    The IOS XE STIG asks a materially weaker question - see
    _ntp_auth_cryptographic_check, which is why these are separate checks
    rather than one shared between the books."""
    correlated = _ntp_md5_correlated_keys(cfg)
    if 'ntp authenticate' in cfg and correlated:
        mitigation = f'MD5-based NTP authentication is configured as the best available mitigation (key id(s) {", ".join(sorted(correlated))} correlated across authentication-key/trusted-key/server)'
    else:
        mitigation = 'MD5-based NTP authentication is not fully configured (missing `ntp authenticate`, or no key id is consistently used across the authentication-key/trusted-key/server lines)'
    return False, (
        'permanent finding on IOS - Check Text: "Cisco IOS is limited to MD5 for NTP authentication, '
        f'and incurs a permanent finding as it is not FIPS compliant." {mitigation}.'
    )


def _ntp_auth_cryptographic_check(cfg):
    """V-220554 (IOS XE): "If the Cisco switch is not configured to
    authenticate NTP sources using authentication that is cryptographically
    based, this is a finding."

    Deliberately NOT the same verdict as IOS V-220606, despite the near-
    identical rule title. IOS demands "authentication with FIPS-compliant
    algorithms", which IOS cannot provide (MD5 only) - hence a permanent
    finding there. IOS XE demands only that the authentication be
    "cryptographically based", and MD5 is a cryptographic hash: weak and
    not FIPS-approved, but squarely within what this sentence asks for. The
    IOS XE Check Content also carries no equivalent of the IOS book's
    "incurs a permanent finding" note.

    Inheriting the IOS verdict here would report a permanent FAIL against a
    rule this platform can actually satisfy - the mirror image of the false
    PASS this project usually guards against, and just as wrong."""
    correlated = _ntp_md5_correlated_keys(cfg)
    if 'ntp authenticate' not in cfg:
        return False, 'missing `ntp authenticate` - NTP authentication is not enabled'
    if not correlated:
        return False, (
            'no key id is used consistently across `ntp authentication-key <id> md5`, '
            '`ntp trusted-key <id>` and `ntp server <ip> key <id>` - the pieces exist '
            'but do not authenticate anything'
        )
    return True, (
        f'NTP sources authenticated with a cryptographically based key (MD5, key id(s) '
        f'{", ".join(sorted(correlated))} correlated across authentication-key/trusted-key/'
        'server). Note MD5 is not FIPS-approved - the IOS book requires FIPS and treats '
        'this as a permanent finding (V-220606), but this rule asks only that the '
        'authentication be cryptographically based.'
    )


# V-220567 (IOS XE): the switch must obtain its public key certificates from an
# approved service provider. The rule opens "This requirement is not applicable
# if the router or switch does not have any public key certificates", and its
# whole procedure is one step: find the trustpoint, read the URL of the CA it
# enrolled with, verify that CA is DOD or DOD-approved.
#
# The presence of a trustpoint was read as "there is a certificate to review"
# and reported NOT AUTOMATED. On the work fleet that is wrong on every switch:
# what they carry is `TP-self-signed-<serial>`, which IOS XE generates by
# itself the moment the HTTPS server comes up. It enrolls with nothing - the
# switch signs its own certificate - so there is no service provider, no CA
# URL, and nothing the review step could be performed against. Verified on a
# real switch with `show running-config | include enrollment url` (no output)
# and `show crypto pki trustpoints`.
#
# So the enrollment method, not the existence of a trustpoint, is what decides
# this rule, and it is in running-config:
#
#   `enrollment url http://ca.example.mil`  - enrolled with a CA, and the URL
#       names it. PASS or FAIL on whether its host is one of the approved ones
#       (see APPROVED_CA_HOSTS below), which is the rule's own review step.
#   anything else, or nothing at all              - NOT APPLICABLE.
#
# That last line is the whole rest of the rule, and it is deliberate. An
# `enrollment url` is the only thing this rule is about: it is what the Check
# Content says the trustpoint "will contain", and it is what a switch doing
# dynamic certificate enrolment from a CA over HTTP/S has. A switch with none -
# whether it carries a self-signed trustpoint, `enrollment terminal`, or no
# trustpoint at all - is not obtaining public key certificates from a service
# provider, so there is no provider for the rule to find fault with.
#
# `enrollment terminal` reported NOT AUTOMATED before this, on the grounds that
# a certificate could have been pasted in from a CA the config does not name.
# That is true and it is still visible - the reason line names any trustpoint
# enrolling by a method other than a URL, so a reviewer who wants to check one
# by hand can see it is there - but it is not a finding and not a rule this
# tool can leave unanswered on a fleet that does none of this.
#
# Ported from ios_router_audit.py's V-215711, itself ported from NX-OS -
# IOS/IOS XE use `crypto pki trustpoint`, NX-OS uses `crypto ca trustpoint`.
def _block_body(chunk, start):
    """The body of a top-level block: everything from `start` up to the next
    line that begins in column 1, which is the next top-level command."""
    return re.split(r'^\S', chunk[start:], maxsplit=1, flags=re.M)[0]


def _trustpoint_blocks(cfg):
    """Yield (name, body) for every `crypto pki trustpoint` in the config. The
    body stops at the next top-level line, so the certificate chain that
    follows a trustpoint is not read as part of its enrollment method."""
    for chunk in re.split(r'^(?=crypto pki trustpoint \S+)', cfg, flags=re.M):
        m = re.match(r'crypto pki trustpoint (\S+)', chunk)
        if m:
            yield m.group(1), _block_body(chunk, m.end())


# Which CA an `enrollment url` names, and whether it is an approved one, is the
# whole of this rule's Check Content: "The CA trust point will contain the URL
# of the CA in which the switch has enrolled with. Verify this is a DOD or
# DOD-approved CA." That is a question about a string in running-config, so it
# is answered here rather than handed back with "verify the issuer via `show
# crypto pki certificates`" - which was the previous verdict, and which asked a
# reviewer to log into the switch to read a URL the audit had already read.
#
# What cannot be inferred is which hosts count as approved: that is a fact
# about your PKI, so it is declared in inventory.yaml's approved_ca_hosts. The
# default is every host under .mil, which is where the DOD PKI lives - and an
# enrollment URL outside it is precisely the case the rule wants looked at, so
# defaulting this way fails toward the finding rather than away from it.
APPROVED_CA_HOSTS = ('*.mil',)


def _enrollment_url_host(url):
    """The host part of an enrollment URL, without scheme, credentials, port or
    path. `http://user:pw@ca.example.mil:80/cgi-bin` is ca.example.mil."""
    without_scheme = re.sub(r'^[A-Za-z][A-Za-z0-9+.-]*://', '', url.strip())
    authority = without_scheme.split('/', 1)[0]
    host = authority.rsplit('@', 1)[-1]
    if host.startswith('['):  # a bracketed IPv6 literal keeps its brackets
        return host.split(']', 1)[0] + ']'
    return host.split(':', 1)[0]


def _pki_trustpoint_check(cfg, approved_hosts=APPROVED_CA_HOSTS):
    approved, unapproved, unreadable, self_signed = [], [], [], []
    for name, body in _trustpoint_blocks(cfg):
        # Anything that is not `enrollment selfsigned` counts as enrollment with
        # a CA, including forms this has never seen (`enrollment profile`,
        # `enrollment mode ra`). An unknown form then reports NOT AUTOMATED
        # rather than NOT APPLICABLE, which costs a look at a switch that may
        # not have needed one - the direction that cannot hide a real finding.
        methods = [line.strip() for line in
                   re.findall(r'^\s*enrollment\s+(.+?)\s*$', body, re.M)
                   if line.split()[0] != 'selfsigned']
        if not methods:
            self_signed.append(name)
            continue
        for method in methods:
            url = re.match(r'url\s+(\S+)$', method)
            if not url:
                # `enrollment terminal` (cut and paste), `enrollment profile X`
                # (the URL is in a separate profile block), `enrollment mode ra`.
                # A CA is involved and running-config does not name it here.
                unreadable.append(f'{name} (enrollment {method})')
                continue
            host = _enrollment_url_host(url.group(1))
            matched = stig_common.matching_pattern(host, approved_hosts)
            if matched:
                approved.append(f'{name} -> {url.group(1)} (host {host} matches `{matched}`)')
            else:
                unapproved.append(f'{name} -> {url.group(1)} (host {host})')

    # A single unapproved enrollment is the finding, whatever else is alongside
    # it: the switch holds a certificate from a CA nobody approved.
    if unapproved:
        return False, (
            f'enrolled with CA(s) outside approved_ca_hosts ({", ".join(approved_hosts)}): '
            f'{", ".join(sorted(unapproved))} - either the CA is not DOD/DOD-approved, or it is '
            "and inventory.yaml's approved_ca_hosts does not say so yet"
        )
    if approved:
        return True, (
            f'enrolled with approved CA(s): {", ".join(sorted(approved))}'
            + (f'. Self-signed alongside: {", ".join(sorted(self_signed))}' if self_signed else '')
        )

    # No `enrollment url` anywhere. The wording is the justification a reviewer
    # would otherwise type into Comments on every switch in the fleet, and it
    # goes there (see stig_common.NOTE_IN_COMMENTS) rather than into Finding
    # Details, since there is no finding to evidence.
    reason = (
        'Verified via `show running-config | section crypto pki trustpoint` that no PKI '
        'enrollment URLs (`enrollment url`) are configured on the switch. The device does not '
        'utilize HTTP/S for dynamic certificate enrollment from a Certificate Authority. '
        'Therefore, this requirement is Not Applicable.'
    )
    if self_signed:
        # Named rather than dismissed: these are the self-signed trustpoints
        # IOS XE generates for its own HTTPS server, and saying so is what
        # tells a reviewer the audit saw them and did not mistake them for
        # enrolment.
        reason += (f' Self-signed trustpoint(s) present and not enrolled with any CA: '
                   f'{", ".join(sorted(self_signed))}.')
    if unreadable:
        # A CA may be involved here and running-config does not name it, so the
        # justification above cannot be left to stand on its own.
        reason += (f' Note: {", ".join(sorted(unreadable))} enrol by a method that names no URL '
                   'in the configuration - if a certificate was loaded from a CA that way, '
                   'confirm the issuer with `show crypto pki certificates`.')
    return None, reason


def _ssh_algorithm_fips_check(cfg, algo_type, required_substring, algo_desc, unavailable_note=''):
    """V-220607/608: the old regexes (`algorithm mac\\s+\\S*hmac-sha2`,
    `algorithm encryption\\s+\\S*aes`) can't cross a space, so they only
    matched when the required algorithm happened to be listed FIRST in the
    command - IOS accepts algorithms in any order. `ip ssh server algorithm
    mac hmac-sha1 hmac-sha2-256` has a compliant algorithm present and
    negotiable but would false-FAIL under the old regex. Checks for the
    required substring anywhere in the algorithm list instead.

    unavailable_note is appended to the FAIL reasons where a platform can't
    offer a compliant algorithm at all, so the report distinguishes "the fix
    was never pushed" from "no acceptable value exists on this image" - the
    same distinction V-220606's permanent-finding wording draws."""
    if 'ip ssh version 2' not in cfg:
        return False, 'missing `ip ssh version 2`'
    m = re.search(rf'^ip ssh server algorithm {algo_type}\s+(.+)$', cfg, re.M)
    if not m:
        return False, f'missing `ip ssh server algorithm {algo_type} ...`{unavailable_note}'
    algos = m.group(1).strip()
    if required_substring in algos:
        return True, f'`ip ssh version 2` + FIPS-validated {algo_desc}: `ip ssh server algorithm {algo_type} {algos}`'
    return False, (
        f'`ip ssh server algorithm {algo_type} {algos}` does not include a FIPS-validated '
        f'({required_substring}) algorithm{unavailable_note}'
    )


# V-220639: check text's own examples show UDLD can be enabled globally
# ("udld enable" in global config) OR per-interface ("udld port" under an
# interface block) - the old check only recognized the global form, false-
# failing a device that used per-interface `udld port`/`udld port aggressive`.
def _udld_check(cfg):
    if re.search(r'^udld (enable|aggressive)', cfg, re.M):
        return True, 'enabled globally: `udld enable`/`udld aggressive`'
    per_interface = []
    for chunk in re.split(r'^(?=interface \S+)', cfg, flags=re.M):
        m = re.match(r'interface (\S+)', chunk)
        if m and re.search(r'^\s*udld port\b', chunk, re.M):
            per_interface.append(m.group(1))
    if per_interface:
        return True, f'enabled per-interface (`udld port`) on: {", ".join(sorted(per_interface))}'
    return False, 'no `udld enable`/`udld aggressive` globally and no `udld port` on any interface'


# V-220651 (IOS XE): manage excess bandwidth to limit the effects of packet
# flooding. This was excluded from the IOS map because the IOS book's check is
# a single `mls qos` (V-220625), a command IOS XE does not have - inheriting
# that predicate would report a permanent FAIL on a compliant Catalyst.
#
# The IOS XE Check Content asks for the MQC shape instead, in three steps:
# class-maps matching DSCP values, a policy-map reserving bandwidth per class,
# and the policy applied outbound on the switchports. All three are
# running-config text, so all three are checkable here - `show class-map` and
# `show policy-map` print the same configuration back.
#
# Matched on DSCP value, not on the example's class-map names. The finding
# sentence is only "If quality of service (QoS) has not been enabled, this is
# a finding", so a switch that reserves the same bandwidth under a local naming
# scheme has enabled QoS and must not be failed for spelling. The STIG's own
# traffic types are still reported by name in the reason, and any of them the
# policy does not cover is said out loud on the PASS - visible to a reviewer
# transcribing the checklist, without inventing a finding DISA did not write.
#
# Coverage, unlike naming, is a finding: a policy applied to some switchports
# and not others leaves the uncovered ones exactly as floodable as before, and
# the rule's own Fix Text applies the service-policy to every port in its
# example, access and trunk alike. Ports missing it are named, the way every
# other per-port rule here names them.
STIG_QOS_TRAFFIC_TYPES = (
    ('C2_VOICE', '47'),
    ('VOICE', 'ef'),
    ('VIDEO', 'af41'),
    ('PREFERRED_DATA', 'af33'),
)

# Per-hop behaviour keywords and the DSCP value each stands for, so a class-map
# written `match ip dscp ef` and one written `match ip dscp 46` compare equal.
DSCP_KEYWORDS = {
    'default': 0, 'ef': 46,
    'af11': 10, 'af12': 12, 'af13': 14, 'af21': 18, 'af22': 20, 'af23': 22,
    'af31': 26, 'af32': 28, 'af33': 30, 'af41': 34, 'af42': 36, 'af43': 38,
    'cs1': 8, 'cs2': 16, 'cs3': 24, 'cs4': 32, 'cs5': 40, 'cs6': 48, 'cs7': 56,
}


def _dscp_value(token):
    """The numeric DSCP a token names, or None if it names none."""
    token = token.lower()
    if token in DSCP_KEYWORDS:
        return DSCP_KEYWORDS[token]
    return int(token) if token.isdigit() else None


def _class_map_dscp_values(cfg):
    """{class-map name: set of DSCP values it matches}."""
    maps = {}
    for chunk in re.split(r'^(?=class-map )', cfg, flags=re.M):
        m = re.match(r'class-map (?:match-all |match-any )?(\S+)', chunk)
        if not m:
            continue
        values = set()
        for match_line in re.findall(r'^\s*match (?:ip )?dscp (.+?)\s*$',
                                     _block_body(chunk, m.end()), re.M):
            for token in match_line.split():
                value = _dscp_value(token)
                if value is not None:
                    values.add(value)
        maps[m.group(1)] = values
    return maps


def _policy_map_classes(cfg):
    """{policy-map name: {class name: that class's body}}."""
    policies = {}
    for chunk in re.split(r'^(?=policy-map )', cfg, flags=re.M):
        m = re.match(r'policy-map (\S+)', chunk)
        if not m:
            continue
        classes = {}
        for part in re.split(r'^(?=\s+class \S+)', _block_body(chunk, m.end()), flags=re.M):
            class_name = re.match(r'\s+class (\S+)', part)
            if class_name:
                classes[class_name.group(1)] = part
        policies[m.group(1)] = classes
    return policies


def _reserves_bandwidth(class_body):
    """True if a policy-map class actually reserves capacity - `priority`,
    `priority level 1 10`, `bandwidth percent 25`, `bandwidth remaining
    percent 25`, or a shaper. A class that only marks or polices reserves
    nothing, and a policy made entirely of those is not the bandwidth
    management this rule is about."""
    return bool(re.search(r'^\s*(priority|bandwidth|shape)\b', class_body, re.M))


def _qos_bandwidth_check(cfg):
    switchports = dict(_switchport_blocks(cfg))
    if not switchports:
        return False, 'no switchports found in config'

    attached, unattached = {}, []
    for name, block in sorted(switchports.items()):
        # `type <something>` is optional and platform-dependent - a Catalyst
        # writes `service-policy output NAME`, others `service-policy type
        # queuing output NAME`. The rule is about the policy attached
        # outbound, whatever the platform spells between the two words.
        m = re.search(r'^\s*service-policy (?:type \S+ )?output (\S+)', block, re.M)
        if m:
            attached.setdefault(m.group(1), []).append(name)
        else:
            unattached.append(name)

    if not attached:
        return False, (
            'QoS is not enabled: no switchport carries a `service-policy output <policy>`, '
            'so no traffic type has bandwidth reserved and nothing limits a flood'
        )

    policies = _policy_map_classes(cfg)
    class_dscp = _class_map_dscp_values(cfg)
    reserving = {}
    for policy_name, ports in sorted(attached.items()):
        classes = policies.get(policy_name)
        if classes is None:
            return False, (
                f'`service-policy output {policy_name}` is applied to {", ".join(ports)} but no '
                f'`policy-map {policy_name}` is configured - it reserves nothing because it '
                'does not exist'
            )
        reserved = {name: body for name, body in classes.items() if _reserves_bandwidth(body)}
        if not reserved:
            return False, (
                f'`policy-map {policy_name}` is applied to {", ".join(ports)} but no class in it '
                'reserves bandwidth (no `priority`, `bandwidth` or `shape`), so it does not '
                'manage excess bandwidth'
            )
        reserving[policy_name] = reserved

    # Everything below is a PASS. What it says is which of the STIG's example
    # traffic types this switch actually reserves for, matched by DSCP, and
    # which switchports the policy does not reach.
    #
    # Ports left out used to fail the rule, on the reading that an uncovered
    # port is as floodable as before and that the Fix Text applies the policy
    # to every port in its example. That is a real argument, but it is not the
    # rule's: the finding condition is one sentence - "If quality of service
    # (QoS) has not been enabled, this is a finding" - and a switch with a
    # valid policy on some of its ports has enabled QoS. Failing it invents a
    # finding DISA did not write, which is the same mistake as failing a
    # policy for using local class-map names, and the same treatment applies:
    # said out loud on the PASS, where a reviewer transcribing the checklist
    # sees it and can act on it.
    covered, uncovered = [], []
    for label, dscp in STIG_QOS_TRAFFIC_TYPES:
        value = _dscp_value(dscp)
        if any(value in class_dscp.get(class_name, set())
               for reserved in reserving.values() for class_name in reserved):
            covered.append(f'{label} (dscp {dscp})')
        else:
            uncovered.append(f'{label} (dscp {dscp})')
    default_reserved = any('class-default' in reserved for reserved in reserving.values())

    attached_count = len(switchports) - len(unattached)
    scope = (f'all {len(switchports)}' if not unattached
             else f'{attached_count} of {len(switchports)}')
    reason = (
        f'QoS enabled: `service-policy output {"`/`".join(sorted(attached))}` on {scope} '
        f'switchport(s), reserving bandwidth for '
        f'{", ".join(covered) if covered else "locally defined classes"}'
        f'{" and class-default" if default_reserved else ""}'
    )
    if unattached:
        reason += (
            f'. No `service-policy output` on: {", ".join(unattached)} - those port(s) are '
            'as floodable as before, but the finding condition is only that QoS is not '
            'enabled, so this is reported rather than failed'
        )
    if uncovered:
        reason += (
            f'. Not reserved for: {", ".join(uncovered)} - the Check Content lists these as its '
            'example and its finding condition is only that QoS is not enabled, so this is '
            'reported rather than failed'
        )
    if not default_reserved:
        reason += '. No `class class-default` reservation, which the example also shows'
    return True, reason


# V-220566 (IOS XE): back up the configuration when it changes. This was
# NOT AUTOMATED on the strength of the IOS book's version of the rule, whose
# check is an SCP target held by the site's administrators and discoverable
# from nothing on the switch. The IOS XE Check Content asks a different and
# entirely answerable question, because it names the mechanism rather than the
# server: an EEM applet triggering on `%SYS-5-CONFIG_I` with an action copying
# the running configuration to a secure destination, plus `authorization
# bypass` in the applet and a global `file prompt quiet`. All four are
# running-config text.
#
# The finding sentence names two conditions and only two: not configured to
# conduct automated backups when changes occur, or doing so "using an insecure
# method like a cleartext password". Those FAIL. The other two the Check
# Content asks to verify are what make the applet run rather than findings DISA
# wrote, so a switch missing them passes with them named in the reason - the
# same treatment V-220651 gives a traffic type the policy does not cover.
#
# What "insecure" means is the Check Content's own note: "The absence of a
# password indicates the use of secure public/private key authentication." So a
# password in the destination is the cleartext method the rule fails, and a
# scheme that cannot be private carries the configuration in the clear whatever
# credentials it is given.
CONFIG_CHANGE_SYSLOG = '%SYS-5-CONFIG_I'
INSECURE_COPY_SCHEMES = ('ftp', 'tftp', 'http', 'rcp')


def _eem_applets(cfg):
    """{applet name: body} for every `event manager applet` in the config.

    The body is the indented run of lines under the header, the way every
    other block in a running-config is written - so it ends at the next `!`
    or the next unindented command."""
    applets = {}
    for chunk in re.split(r'^(?=event manager applet )', cfg, flags=re.M):
        match = re.match(r'event manager applet (\S+)', chunk)
        if not match:
            continue
        body = []
        for line in chunk.splitlines()[1:]:
            if line.strip() and not line.startswith(' '):
                break
            body.append(line)
        applets[match.group(1)] = '\n'.join(body)
    return applets


def _applet_copy_targets(body):
    """Every destination an applet copies the running configuration to.

    The action is a quoted CLI command - `action 3 cli command "copy
    running-config scp://..."` - so the destination is the token after the
    source, with the closing quote trimmed off it."""
    targets = []
    for match in re.finditer(
            r'copy\s+(?:system:)?running-config\s+(\S+)', body, re.I):
        targets.append(match.group(1).strip('"\''))
    return targets


def _copy_target_problem(target):
    """Why a destination is not a secure off-box backup, or '' if it is one."""
    match = re.match(r'([A-Za-z][A-Za-z0-9+.-]*)://(.*)', target)
    if not match:
        # No scheme: `flash:`, `bootflash:`, a filename. Whatever else that is,
        # it is a copy to the switch's own storage, and a switch that loses its
        # storage loses the backup with it.
        return f'`{target}` is not a remote destination'
    scheme, rest = match.group(1).lower(), match.group(2)
    if scheme in INSECURE_COPY_SCHEMES:
        return f'`{scheme}://` carries the configuration in the clear'
    authority = rest.split('/', 1)[0]
    if '@' in authority and ':' in authority.split('@')[0]:
        return 'the destination carries a cleartext password'
    return ''


def _config_backup_check(cfg):
    applets = _eem_applets(cfg)
    if not applets:
        return False, (
            'no `event manager applet` is configured, so nothing copies the configuration '
            'anywhere when it changes'
        )

    triggered = {name: body for name, body in applets.items()
                 if CONFIG_CHANGE_SYSLOG in body}
    if not triggered:
        return False, (
            f'no EEM applet triggers on `{CONFIG_CHANGE_SYSLOG}`: '
            f'`{"`/`".join(sorted(applets))}` exist but none of them fires on a '
            'configuration change'
        )

    backing_up, insecure = {}, []
    for name, body in sorted(triggered.items()):
        for target in _applet_copy_targets(body):
            problem = _copy_target_problem(target)
            if problem:
                insecure.append(f'`{name}` copies to `{target}`, where {problem}')
            else:
                backing_up.setdefault(name, []).append(target)

    # Named in the finding sentence outright, and true whatever else the switch
    # also does: a backup taken insecurely is the finding, not half of one.
    if insecure:
        return False, '; '.join(insecure)
    if not backing_up:
        return False, (
            f'`{"`/`".join(sorted(triggered))}` triggers on `{CONFIG_CHANGE_SYSLOG}` but '
            'contains no action copying the running configuration anywhere, so a change is '
            'noticed and not backed up'
        )

    # Everything below is a PASS. What it says is what the switch backs up to,
    # and which of the Check Content's two supporting settings are missing.
    destinations = ', '.join(f'`{target}`' for name in sorted(backing_up)
                             for target in backing_up[name])
    reason = (
        f'backed up on change: EEM applet `{"`/`".join(sorted(backing_up))}` triggers on '
        f'`{CONFIG_CHANGE_SYSLOG}` and copies the running configuration to {destinations}, '
        'with no password in the destination - key authentication, per the Check Content'
    )
    notes = []
    without_bypass = [name for name in sorted(backing_up)
                      if not re.search(r'^\s*authorization bypass\b', triggered[name], re.M)]
    if without_bypass:
        notes.append(
            f'no `authorization bypass` in `{"`/`".join(without_bypass)}`, which the Check '
            'Content asks for so the applet executes under AAA')
    if not re.search(r'^\s*file prompt quiet\b', cfg, re.M):
        notes.append(
            'no global `file prompt quiet`, which the Check Content asks for so the applet '
            'does not time out')
    if notes:
        reason += (
            '. ' + '; '.join(notes) + ' - the finding condition is only that backups are '
            'absent or insecure, so these are reported rather than failed')
    return True, reason


# V-220621 (IOS) / V-220569 (IOS XE): the switch must run a release Cisco still
# supports. The Check Content is `show version` plus a lookup on
# cisco.com/c/en/us/support/ios-nx-os-software, so the rule was NOT AUTOMATED
# and every report said "log into the switch and read its version" - a trip per
# switch to collect a fact the audit was already connected to read.
#
# What decides it on IOS XE is not a lookup at all, it is the numbering. Cisco
# publishes two tracks in the 16.x and 17.x trains:
#
#   Extended Maintenance (EMR)  - every third minor: 17.3, 17.6, 17.9, 17.12,
#       17.15 (and 16.3, 16.6, 16.9, 16.12). 36-48 months of support, with
#       scheduled rebuilds carrying the security fixes.
#   Standard Maintenance (SMR)  - everything between: 17.10, 17.11, 17.13,
#       17.14. Twelve months in total, no extension.
#
# A switch on an SMR is therefore a finding: within a year of that release
# shipping there are no more fixes for it, and there is no configuration that
# makes it otherwise. A switch on an EMR passes. Both answers come from the
# release number, so neither needs a table anyone has to re-read - which is
# what the previous hand-maintained SUPPORTED_RELEASES list was, and why it
# carried a staleness date and a warning about trusting it.
#
# Two things this deliberately does NOT claim. It does not say an EMR is
# currently supported: 17.3 is an EMR whose window has closed, and the reason
# line says which train it is so an old one is visible rather than implied. And
# it says nothing about classic IOS (15.x, `15.2(4)E10`), which has no EMR/SMR
# split - that reports NOT AUTOMATED with the release printed, as before.

# Cisco's published last date of support, per hardware family. A switch past
# this date fails regardless of the release it runs: no supported release
# exists for it any more. Matched as a substring of the model, so 'WS-C3850'
# covers every WS-C3850-nn variant.
PLATFORM_LAST_DATE_OF_SUPPORT = {
    'WS-C3850': ('2025-10-31', 'Catalyst 3850'),
    'WS-C3650': ('2025-10-31', 'Catalyst 3650'),
    'WS-C3750': ('2021-10-31', 'Catalyst 3750/3750-X'),
    'WS-C3560': ('2021-10-31', 'Catalyst 3560/3560-X'),
}

# The trains the EMR rule applies to. IOS XE only; classic IOS numbering does
# not carry the distinction.
IOS_XE_TRAINS = (16, 17)

# An EMR is every third minor release. Stated as arithmetic rather than a list
# so 17.18 and 17.21 are covered the day they ship.
EMR_MINOR_INTERVAL = 3

CISCO_SUPPORT_URL = 'www.cisco.com/c/en/us/support/ios-nx-os-software'


# The switch table `show version` ends with on a stackable Catalyst lives in
# stig_common, because the asset block reads the active member's MAC and serial
# out of it too - see the note above stig_common._SWITCH_TABLE_HEADER for why
# the active member is the one that matters.
def _show_version_switch_table(output):
    """(model, release) from the switch table's active row, or (None, None)."""
    active = stig_common.active_member(output)
    return (active[1], active[2]) if active else (None, None)


def _normalise_release(release):
    """17.12.04 and 17.12.4 are one release printed two ways, and only one of
    them can be the key in a table."""
    return re.sub(r'(^|\.)0+(\d)', r'\1\2', release.strip().rstrip(','))


# The switch table is asked first, and the reason is a stack.
#
# `Model Number :` is printed once per member, in member order, so the first
# match is switch 1's model - which on a mixed stack is not the switch the rule
# is about. The banner, meanwhile, gives the active member's release. Read that
# way, a stack of a C9300-24P and an active C9300-48P reports the 24P's model
# beside the 48P's release: two different pieces of hardware described as one.
# The model is what decides the hardware end-of-support check, so that is a
# wrong verdict, not just a wrong label.
#
# The table has neither problem. It marks the active member with `*`, and model
# and release come off that one row, so they cannot describe different units.
# The banner and `Model Number` remain the fallback, and have to: a classic IOS
# switch, the lab's vios_l2 image and a router print no switch table at all.
def _show_version_release(output):
    """The release from `show version`, normalised - the banner says 17.12.04
    and the IOS Software line says 17.12.4, and those are one release.

    The switch table's SW Version column first (the active member's, on a
    stack), then the banner lines for everything that prints no table."""
    _model, release = _show_version_switch_table(output)
    if release:
        return _normalise_release(release)
    for pattern in (r'Cisco IOS XE Software, Version (\S+)',
                    r'Cisco IOS Software.*?,\s*(?:Experimental )?Version ([^\s,]+)',
                    r'^Version (\S+)'):
        m = re.search(pattern, output, re.M)
        if m:
            return _normalise_release(m.group(1))
    return None


def _show_version_model(output):
    """The switch model from `show version`.

    The switch table's Model column first, for the member the table marks
    active. Then 'Model Number', the Catalyst per-member form, and finally the
    'cisco <model> (<cpu>) processor' line, which is what everything else
    prints - including the lab's vios_l2 image."""
    model, _release = _show_version_switch_table(output)
    if model:
        return model
    for pattern in (r'^Model [Nn]umber\s*:\s*(\S+)',
                    r'^\s*[Cc]isco (\S+) \(.*\) processor'):
        m = re.search(pattern, output, re.M)
        if m:
            return m.group(1)
    return None


def _ios_xe_train(release):
    """(major, minor) for an IOS XE release, or None for anything else.

    Classic IOS carries parentheses - `15.2(4)E10` - and has no EMR/SMR split,
    so the shape is what tells the two apart rather than the major number
    alone."""
    match = re.match(r'^(\d+)\.(\d+)(?:\.\S*)?$', release)
    if not match:
        return None
    major, minor = int(match.group(1)), int(match.group(2))
    return (major, minor) if major in IOS_XE_TRAINS else None


def _is_extended_maintenance(minor):
    """True for an Extended Maintenance minor - every third one, 3, 6, 9, 12,
    15, 18. Minor 0 is not a release Cisco ships, so it is excluded rather than
    passed by the arithmetic."""
    return minor > 0 and minor % EMR_MINOR_INTERVAL == 0


def _nearest_extended_maintenance(minor):
    """The EMR minors either side of an SMR, for the reason line: telling
    someone 17.13 is short-lived is only half an answer without 17.12 and 17.15
    beside it."""
    below = (minor // EMR_MINOR_INTERVAL) * EMR_MINOR_INTERVAL
    above = below + EMR_MINOR_INTERVAL
    return below, above


def _ios_release_supported_check(version_output, today=None):
    today = today or datetime.date.today()
    model = _show_version_model(version_output)
    release = _show_version_release(version_output)

    if model:
        for family, (last_date, name) in PLATFORM_LAST_DATE_OF_SUPPORT.items():
            if family.lower() in model.lower():
                if datetime.date.fromisoformat(last_date) < today:
                    return False, (
                        f'{model} is a {name} - Cisco\'s last date of support was {last_date}, '
                        f'so no release it can run is supported (running {release or "an unreadable release"}). '
                        'The fix is hardware, not an upgrade.'
                    )
                break

    if release is None or model is None:
        return 'NOT AUTOMATED', (
            f'could not read {"a release" if release is None else "a model"} from `show version` - '
            f'check the release by hand against {CISCO_SUPPORT_URL}'
        )

    train = _ios_xe_train(release)
    if train is None:
        # Classic IOS. No EMR/SMR split to apply, and no table here pretending
        # to know - the release and model are printed so the lookup is one
        # search rather than one login.
        return 'NOT AUTOMATED', (
            f'running {release} on {model} - not IOS XE numbering, so the Extended/Standard '
            f'Maintenance rule does not apply; confirm support at {CISCO_SUPPORT_URL}'
        )

    major, minor = train
    if _is_extended_maintenance(minor):
        return True, (
            f'running {release} on {model} - {major}.{minor} is an Extended Maintenance release '
            f'(every {EMR_MINOR_INTERVAL}rd minor: '
            f'{major}.{EMR_MINOR_INTERVAL}, {major}.{EMR_MINOR_INTERVAL * 2}, '
            f'{major}.{EMR_MINOR_INTERVAL * 3} ...), supported 36-48 months with scheduled '
            f'rebuilds. Keep it on a current rebuild - the train being extended is what this '
            f'checks, not how old this particular build is'
        )

    below, above = _nearest_extended_maintenance(minor)
    return False, (
        f'running {release} on {model} - {major}.{minor} is a Standard Maintenance release, '
        f'supported for 12 months only and never extended. Move to an Extended Maintenance '
        f'release: {major}.{below} or {major}.{above}'
    )


# Regex/keyword checks for rules that can be verified directly from running-config
# text. Rules with no entry here need external infrastructure (RADIUS, syslog,
# NTP, PKI) or manual/topology review, and are reported as NOT AUTOMATED.
CHECKS = {
    # --- L2S (Layer 2 Switch) ---
    # V-220642/645 were NOT AUTOMATED for a long time (see git history) until
    # l2_stig_harden_global.py started pushing explicit 'switchport access vlan
    # <default_access_vlan>' and 'switchport mode access' to every access
    # port. V-220642: IOS omits "switchport access vlan 1" when it's already
    # the default, so a missing explicit-non-1 line now unambiguously means
    # "on VLAN 1" (nothing else can explain it once ports are always assigned
    # an explicit VLAN). V-220645: see _all_ports_explicit_mode's docstring -
    # checks every switchport-capable interface directly instead of the
    # access/trunk classification bucket, which was circular.
    'V-220642': lambda cfg: _all_access_ports_have(cfg, r'switchport access vlan (?!1\s*$)\d+', 'an explicit non-default access VLAN (not VLAN 1)'),
    'V-220645': lambda cfg: _user_facing_trunk_check(
        cfg, core_switch_tags, uplink_keywords),
    'V-220623': _dot1x_mab_check,
    'V-220632': lambda cfg: _all_access_ports_have(cfg, r'switchport block unicast', 'UUFB (`switchport block unicast`)'),
    'V-220634': lambda cfg: _all_access_ports_have(cfg, r'ip verify source', 'IP Source Guard (`ip verify source`)'),
    'V-220636': lambda cfg: _all_access_ports_have(
        cfg, r'storm-control broadcast level', 'storm control (`storm-control broadcast level ...`)',
        exclude_prefixes=('FastEthernet',),
    ),
    'V-220640': lambda cfg: _all_trunk_ports_have(cfg, r'switchport nonegotiate', '`switchport nonegotiate`'),
    'V-220643': lambda cfg: default_vlan_pruned_from_trunks(cfg),
    'V-220646': lambda cfg: _all_trunk_ports_have(cfg, r'switchport trunk native vlan (?!1\s*$)\d+', 'a non-default native VLAN'),
    'V-220647': _no_access_ports_on_native_vlan,
    'V-220641': lambda cfg: _disabled_ports_unused_vlan_check(cfg, netauto.load_unused_vlan()),
    'V-220586': _no_unnecessary_services,
    'V-220630': _bpdu_guard_check,
    'V-220631': lambda cfg: _presence(cfg, r'spanning-tree loopguard default', what='`spanning-tree loopguard default`'),
    # V-220633/635 (DHCP snooping/DAI VLAN coverage) are added below, after
    # discovering the device's genuine user VLANs - a plain presence check can't
    # tell "configured for the wrong VLANs" from "configured correctly" (e.g.
    # snooping enabled on VLAN 1,10 while the real user VLAN 55 has none).
    'V-220637': lambda cfg: _absence(cfg, r'no ip igmp snooping', what='`no ip igmp snooping` (would disable it)'),
    'V-220638': lambda cfg: _presence(cfg, r'spanning-tree mode rapid-pvst', what='`spanning-tree mode rapid-pvst`'),
    'V-220639': _udld_check,
    'V-220601': lambda cfg: _count_distinct(cfg, r'^ntp server (\S+)', 2, 'NTP server(s)'),
    'V-220606': _ntp_auth_check,

    # --- NDM (Network Device Management) ---
    'V-220571': _archive_logging_enabled,
    'V-220572': _archive_logging_enabled,
    'V-220573': _archive_logging_enabled,
    'V-220574': _archive_logging_enabled,
    'V-220582': _archive_logging_enabled,
    'V-220597': _archive_logging_enabled,
    'V-220611': _archive_logging_enabled,
    'V-220613': _archive_logging_enabled,
    'V-220578': _admin_activity_logged,
    'V-220570': _session_limit_check,
    # Re-pointed at --management-subnet below when that flag is given; the
    # inventory's value is the default, as with the VLAN lists.
    'V-220575': lambda cfg: _vty_management_acl_check(cfg, netauto.load_management_subnet()),
    'V-220581': _vty_acl_log_input_check,
    'V-220587': _single_local_account_check,
    'V-220617': _radius_redundancy_check,
    'V-220590': lambda cfg: _cc_policy_check(cfg, r'^\s*upper-case (\d+)', 1, '`upper-case <n>`'),
    'V-220591': lambda cfg: _cc_policy_check(cfg, r'^\s*lower-case (\d+)', 1, '`lower-case <n>`'),
    'V-220592': lambda cfg: _cc_policy_check(cfg, r'^\s*numeric-count (\d+)', 1, '`numeric-count <n>`'),
    'V-220593': lambda cfg: _cc_policy_check(cfg, r'^\s*special-case (\d+)', 1, '`special-case <n>`'),
    'V-220594': lambda cfg: _cc_policy_check(cfg, r'^\s*char-changes (\d+)', 8, '`char-changes <n>`'),
    'V-220580': lambda cfg: _presence(cfg, r'service timestamps log datetime localtime', what='`service timestamps log datetime localtime`'),
    'V-220599': lambda cfg: _presence(cfg, r'logging buffered \d+', what='a `logging buffered <size> ...` line'),
    'V-220612': lambda cfg: _all_of(cfg, [
        ('login on-failure log', r'login on-failure log'),
        ('login on-success log', r'login on-success log'),
    ]),
    'V-220576': _login_block_check,
    'V-220625': lambda cfg: _presence(cfg, r'^mls qos\s*$', re.M, what='`mls qos`'),
    'V-220577': lambda cfg: _presence(cfg, r'banner (login|motd)', what='a `banner login` or `banner motd`'),
    'V-220589': lambda cfg: _cc_policy_check(cfg, r'^\s*min-length (\d+)', 15, '`min-length <n>`'),
    'V-220595': lambda cfg: _all_of(cfg, [
        ('service password-encryption', r'^\s*service password-encryption\s*$'),
        ('enable secret', r'enable secret'),
    ]),
    'V-220596': _exec_timeout_reason,
    'V-220600': _logging_trap_check,
    'V-220583': _audit_info_protection_check,
    'V-220584': _audit_info_protection_check,
    'V-220585': _audit_info_protection_check,
    'V-220644': _no_management_on_default_vlan,
    # The note fires on classic IOS images that only offer SHA-1 MACs. DISA
    # concedes in this rule's own Check Content that SHA-1 is FIPS-validated
    # ("allowed by NIST SP 800-131A Rev. 2 for some applications") but declines
    # it for this rule anyway, so hmac-sha1 is deliberately not pushed and not
    # accepted as a PASS - there is no compliant value on such an image.
    'V-220607': lambda cfg: _ssh_algorithm_fips_check(
        cfg, 'mac', 'hmac-sha2', 'MAC (HMAC integrity)',
        unavailable_note=(
            ' - on classic IOS images offering only hmac-sha1/hmac-sha1-96 (confirmed via '
            '`ip ssh server algorithm mac ?`) this is a permanent finding, not an unpushed fix: '
            'DISA Check Content states "SHA-1 is considered a compromised hashing standard ... '
            'DOD systems should not be configured to use SHA-1 for integrity of remote access '
            'sessions", so no algorithm this image supports can satisfy the rule'
        ),
    ),
    'V-220608': lambda cfg: _ssh_algorithm_fips_check(cfg, 'encryption', 'aes', 'encryption algorithm'),
    # V-220620: matches "logging host x.x.x.x" or the bare legacy "logging x.x.x.x"
    # form. Deliberately excludes non-IP "logging ..." directives (buffered, trap,
    # on, console, etc.) by requiring the token after "logging"/"logging host" to
    # look like an IPv4 address.
    'V-220620': lambda cfg: _count_distinct(
        cfg, r'^logging (?:host )?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', 2, 'syslog server(s)'
    ),
}

# Parse the target device from the command line
parser = argparse.ArgumentParser(description='Audit a device against DISA STIG rules from New Layer 2 switch Checklist.cklb')
parser.add_argument('device', help='Device name as it appears in inventory.yaml (e.g. S1) - with '
                                   '--from-capture, any label to report the results under')
parser.add_argument('--from-capture', metavar='PATH', dest='from_capture',
                    help='Audit output captured from a device instead of connecting to it. The '
                         'device needs no inventory.yaml entry and no credentials are prompted '
                         'for. See capture.py for the commands a capture must cover.')
parser.add_argument('--non-user-vlans', metavar='IDS', dest='non_user_vlans',
                    help='Comma-separated VLAN IDs to treat as non-user (management, servers, '
                         'unused), overriding inventory.yaml. Needed alongside --from-capture for '
                         'a switch whose VLAN scheme this inventory does not describe.')
parser.add_argument('--user-vlan-names', metavar='NAMES', dest='user_vlan_names',
                    help='Comma-separated VLAN names that are always user VLANs, whatever ID they '
                         "carry here, overriding inventory.yaml's user_vlan_names. Matched exactly "
                         'and case-insensitively against the name column of `show vlan brief`, or '
                         'as a glob if the entry has a wildcard: `*user` for the names ending in '
                         'it, `*user[0-9]*` for the numbered ones. This is what covers a fleet '
                         'whose user and voice VLANs are numbered per site and named per site too '
                         '- army-xxx-abc-user1 on VLAN 800 here, army-yyy-def-user15 on VLAN 850 '
                         'there. The name wins over --non-user-vlans, so a switch whose user VLAN '
                         'is 10 is still checked even where 10 is the management VLAN.')
parser.add_argument('--core-switch-tags', metavar='TAGS', dest='core_switch_tags',
                    help='Comma-separated substrings marking a hostname as a core or distribution '
                         "switch, overriding inventory.yaml's core_switch_hostname_tags. Those "
                         'switches have no user-facing ports, so V-220645/671 reports NOT '
                         'APPLICABLE on them. Matched case-insensitively anywhere in the hostname, '
                         'so keep them tight: this direction exempts a switch from the rule '
                         'entirely, and an over-broad tag costs a silent exemption rather than a '
                         'noisy finding.')
parser.add_argument('--uplink-keywords', metavar='WORDS', dest='uplink_keywords',
                    help='Comma-separated substrings marking a port description as facing another '
                         "switch, an AP or a phone, overriding inventory.yaml's "
                         'uplink_port_description_keywords. A trunk described this way is not a '
                         'user-facing trunk (V-220645/671); one that is not described at all is '
                         'reported for review rather than failed, because every access switch '
                         'needs an uplink.')
parser.add_argument('--non-user-vlan-names', metavar='NAMES', dest='non_user_vlan_names',
                    help='Comma-separated VLAN names to treat as non-user, overriding '
                         "inventory.yaml's non_user_vlan_names. Matched exactly and case-"
                         'insensitively against the name column of `show vlan brief`, or as a glob '
                         'if the entry has a wildcard. Use this where a fleet numbers the same VLAN '
                         'differently on each switch but names it consistently - excluding by ID '
                         'alone then drops a real user VLAN from the DHCP snooping and DAI coverage '
                         'checks. Keep patterns tight here: this direction removes VLANs from the '
                         'audited set, so an over-broad one costs a silent PASS rather than a '
                         'spurious finding.')
parser.add_argument('--management-subnet', metavar='CIDR', dest='management_subnet',
                    help="The management network in CIDR form (e.g. 10.10.50.0/24), overriding "
                         "inventory.yaml's management_subnet. V-220575/523 checks that the vty "
                         'access-class ACL permits only sources inside it, so a switch on a '
                         'management network this inventory does not describe - the usual case '
                         'with --from-capture, and the case where the inventory carries a '
                         'placeholder rather than a real address - can still be audited for it '
                         'without editing the file.')
parser.add_argument('--checklist', choices=('ios', 'ios-xe'), default='ios-xe',
                    help='Which DISA checklist to audit against. The IOS and IOS XE switch '
                         'STIGs share no rule IDs at all, so auditing against the wrong one '
                         "reports every rule NOT AUTOMATED. 'ios-xe' re-keys the same checks "
                         'onto the IOS XE numbering - see ios_xe_rule_map.py for which rules '
                         "carry over and which deliberately do not. Default: ios-xe (the work "
                         "deployment target); pass 'ios' for the lab's vios_l2 switches.")
parser.add_argument('--capture-to', metavar='PATH', dest='capture_to',
                    help='During a live audit, also write everything read from the device to a '
                         'capture file. Re-running with --from-capture against that file must '
                         'produce an identical report, which is how the offline path is verified '
                         'against a switch. Read-only; nothing is pushed.')
parser.add_argument('--approved-ca-hosts', metavar='HOSTS', dest='approved_ca_hosts',
                    help='Comma-separated hosts a `crypto pki trustpoint`\'s `enrollment url` may '
                         "name, overriding inventory.yaml's approved_ca_hosts. V-220567 passes "
                         'when every enrollment URL names one of these and fails otherwise; '
                         'matched exactly and case-insensitively against the URL\'s host, or as a '
                         'glob if the entry has a wildcard. Default: *.mil.')
parser.add_argument('--management-vlan-names', metavar='NAMES', dest='management_vlan_names',
                    help="Comma-separated VLAN names carrying the switch's management address, "
                         "overriding inventory.yaml's management_vlan_names. Matched against the "
                         'name column of `show vlan brief` exactly and case-insensitively, or as '
                         'a glob if the entry has a wildcard. `show ip interface brief` gives the '
                         'SVI an address but never says what the VLAN is for, so this is what '
                         "names the one whose address goes into the checklist's asset block. "
                         'Default: *mgt, *mgmt. Affects no verdict.')
parser.add_argument('--to-cklb', metavar='PATH', dest='to_cklb',
                    help='Also write the verdicts into a STIG Viewer 3 checklist at PATH, so '
                         'the report does not have to be retyped rule by rule. PASS/FAIL/NOT '
                         'APPLICABLE become not_a_finding/open/not_applicable; NOT AUTOMATED '
                         'becomes not_reviewed, never not_a_finding. Re-running over an existing '
                         'export re-derives everything from the new capture, including both text '
                         'boxes: a comment typed into STIG Viewer does not survive it. '
                         'PATH names a file when it has an extension; a directory otherwise, in '
                         'which case the file is named <hostname>_<DDMMMYYYY>_<the checklist\'s '
                         'own STIG versions>.cklb - e.g. SW01_06AUG2026_L2S_V3R2_NDM_V3R6.cklb.')
args = parser.parse_args()

if args.capture_to and args.from_capture:
    print('--capture-to records a live audit and --from-capture replaces one; pick one.')
    raise SystemExit(2)

device_name = args.device

# Offline runs skip both the inventory lookup and the credential prompt, so a
# switch that isn't described in this repo's inventory.yaml - and shouldn't be,
# if it's someone else's production kit - can still be audited. One session
# object serves the live-discovery commands below and run_stig_audit's
# running-config read, exactly as the single Netmiko pair does online.
if args.from_capture:
    device_info = None
    username = password = None
    try:
        audit_session = capture.load_l2s(args.from_capture)
    except capture.CaptureError as capture_error:
        print(capture_error)
        raise SystemExit(1)
    discovery_connect = audit_session
    print(f'Auditing capture {audit_session.source} as {device_name}\n')
else:
    audit_session = None
    all_devices = netauto.load_inventory()
    device_info = netauto.require_devices(all_devices, [device_name])[device_name]
    username, password = netauto.get_credentials()

# Discover genuine user VLANs (excludes management/servers/unused VLANs from
# inventory.yaml's non_user_vlans/non_user_vlans_by_device, plus unused_vlan/
# native_vlan) so V-220633/V-220635 can verify DHCP snooping/DAI actually
# cover them, not just that some VLAN list exists. Same exclude set
# l2_stig_harden_global.py uses - without also excluding unused_vlan/native_vlan
# here, VLAN 999 (native) and VLAN 1000 (unused, no live hosts) get
# misclassified as uncovered user VLANs once they exist in the database, the
# same bug already fixed for nxos_stig_audit.py's V-220684/686 (confirmed live
# on S1: V-220635 false-failed over VLAN 1000 not being in the DAI VLAN list).
# Also discovers the live STP root port(s) for V-220629 (Root Guard must never
# be checked/pushed there), the live VTP password for V-220624 (never appears
# in running-config, see _vtp_password_check), and the live SNMPv3 user info
# for V-220604/605 (same platform quirk, see _snmpv3_user_live_check). Uses a
# separate connection since run_stig_audit manages its own for running-config.
if audit_session is None:
    discovery_connect = netauto.connect(device_name, device_info, username, password,
                                             purpose='live discovery: VTP password, root port, VLANs')
    if discovery_connect is None:
        raise SystemExit(1)

# --non-user-vlans replaces the inventory's list outright rather than adding to
# it, including the unused/native VLANs folded in below. Those are this lab's
# VLAN 999/1000; carrying them onto a switch with a different numbering scheme
# would quietly exclude two real user VLANs from the DHCP snooping and DAI
# coverage checks, which is the false PASS this whole check exists to prevent.
if args.non_user_vlans:
    non_user_vlan_exclude = [vlan.strip() for vlan in args.non_user_vlans.split(',') if vlan.strip()]
else:
    non_user_vlan_exclude = list(netauto.load_non_user_vlans(device_name=device_name))
    unused_vlan = netauto.load_unused_vlan()
    native_vlan_id = netauto.load_native_vlan()
    if unused_vlan:
        non_user_vlan_exclude.append(unused_vlan)
    if native_vlan_id:
        non_user_vlan_exclude.append(native_vlan_id)

# Names are a separate axis from IDs, so --non-user-vlan-names overrides only
# the name list and leaves the ID exclusions above alone. A VLAN is non-user if
# either matches.
# Both are lists of substrings the site declares about itself, so they follow
# --non-user-vlan-names' shape: a comma-separated override for a one-off run
# against a switch inventory.yaml does not describe.
if args.core_switch_tags is not None:
    core_switch_tags = [tag.strip() for tag in args.core_switch_tags.split(',') if tag.strip()]
else:
    core_switch_tags = netauto.load_core_switch_hostname_tags()
if args.uplink_keywords is not None:
    uplink_keywords = [word.strip() for word in args.uplink_keywords.split(',') if word.strip()]
else:
    uplink_keywords = netauto.load_uplink_description_keywords()

if args.non_user_vlan_names:
    non_user_vlan_names = [name.strip() for name in args.non_user_vlan_names.split(',') if name.strip()]
else:
    non_user_vlan_names = netauto.load_non_user_vlan_names()

if args.user_vlan_names:
    user_vlan_names = [name.strip() for name in args.user_vlan_names.split(',') if name.strip()]
else:
    user_vlan_names = netauto.load_user_vlan_names()

try:
    vlan_classification = stig_common.classify_vlans(discovery_connect, exclude=non_user_vlan_exclude,
                                                     exclude_names=non_user_vlan_names,
                                                     include_names=user_vlan_names)
    user_vlans = [vid for vid, _, is_user, _ in vlan_classification if is_user]
    root_ports = stig_common.discover_root_port_interfaces(discovery_connect)
    vtp_password_output = str(discovery_connect.send_command('show vtp password'))
    snmp_user_output = str(discovery_connect.send_command('show snmp user'))
    version_output = str(discovery_connect.send_command('show version'))
    # Asset data for the exported checklist, not a verdict - so a capture
    # collected before this command joined the list is audited without it and
    # says so, rather than being refused. See capture.OPTIONAL_COMMANDS_L2S.
    ip_interface_output = capture.optional_output(discovery_connect, 'show ip interface brief')
    vlan_brief_output = str(discovery_connect.send_command('show vlan brief'))
    # Read here rather than left to run_stig_audit's own read because the
    # template names are in it: which `show template interface source user`
    # commands this switch needs is a fact about its config, so the config has
    # to be in hand before they can be asked for. A switch that sources no
    # templates asks nothing extra.
    discovery_config = str(discovery_connect.send_command('show running-config'))
    template_outputs = {
        name: str(discovery_connect.send_command(capture.template_command(name)))
        for name in capture.sourced_template_names(discovery_config)
    }
    template_bodies = {name: stig_common.parse_interface_template(output)
                       for name, output in template_outputs.items()}
    # discover_user_vlans/discover_root_port_interfaces don't hand back the raw
    # text they parsed, so --capture-to re-reads those two commands rather than
    # reshaping those helpers around recording. run_stig_audit opens its own
    # connection for running-config, which is why that is read here as well:
    # all the commands come off this one session so the capture is internally
    # consistent, at the cost of reading running-config twice during a
    # --capture-to run. All read-only, and only when explicitly asked for.
    if args.capture_to:
        recorded = {
            'show running-config': discovery_config,
            'show vlan brief': vlan_brief_output,
            'show spanning-tree': str(discovery_connect.send_command('show spanning-tree')),
            'show vtp password': vtp_password_output,
            'show snmp user': snmp_user_output,
            'show version': version_output,
            'show ip interface brief': ip_interface_output,
        }
        # The template sections go in the capture too, or an offline re-run of
        # this same audit would be refused for missing exactly what the live
        # run just read.
        for name, output in template_outputs.items():
            recorded[capture.template_command(name)] = output
        capture.write(args.capture_to, recorded)
        print(f'Wrote capture to {args.capture_to}')
except (capture.CaptureError, stig_common.InventoryError) as discovery_error:
    print(discovery_error)
    raise SystemExit(1)
discovery_connect.disconnect()

# Both of these are printed above the report rather than folded into a verdict,
# because both decide what the verdicts are able to say. A VLAN classified
# non-user is not audited for DHCP snooping or DAI coverage at all - the rule
# PASSes without ever asking about it - and a template that could not be read
# leaves the ports sourcing it looking bare. Neither shows up as a finding, so
# neither is visible unless it is stated.
coverage_rule_ids = 'V-220659/661' if args.checklist == 'ios-xe' else 'V-220633/635'
print(stig_common.describe_vlan_classification(vlan_classification, coverage_rule_ids))
print()
template_summary = stig_common.describe_template_expansion(discovery_config, template_bodies)
if template_summary:
    print(template_summary)
    print()

# What the exported checklist will say the device IS. Printed here for the same
# reason the VLAN classification above is: an asset field that could not be
# read is blank in STIG Viewer, and a blank field looks identical whether the
# audit failed to find the value or never went looking.
if args.management_vlan_names:
    management_vlan_names = [name.strip() for name in args.management_vlan_names.split(',')
                             if name.strip()]
else:
    management_vlan_names = (netauto.load_management_vlan_names()
                             or list(stig_common.MANAGEMENT_VLAN_NAMES))
target_data = stig_common.collect_target_data(
    discovery_config, version_output, vlan_brief_output, ip_interface_output,
    device_name=device_name, device_info=device_info,
    management_vlan_names=management_vlan_names)
print(target_data['notes'])
print()

# The date the output was collected, which names the exported file. A capture's
# own mtime is when it was written, which is when its switch was read; a live
# run is being read now.
if args.from_capture and os.path.exists(args.from_capture):
    captured_on = datetime.date.fromtimestamp(os.path.getmtime(args.from_capture))
else:
    captured_on = datetime.date.today()

if args.management_subnet:
    CHECKS['V-220575'] = lambda cfg: _vty_management_acl_check(cfg, args.management_subnet)

CHECKS['V-220633'] = lambda cfg: _dhcp_snooping_check(cfg, user_vlans)
CHECKS['V-220635'] = lambda cfg: _vlan_range_covers_user_vlans(
    cfg, r'ip arp inspection vlan (\S+)', user_vlans, 'an `ip arp inspection vlan <list>` line'
)
CHECKS['V-220629'] = lambda cfg: _root_guard_check(cfg, root_ports)
CHECKS['V-220624'] = lambda cfg: _vtp_password_check(vtp_password_output)
CHECKS['V-220604'] = lambda cfg: _snmpv3_user_live_check(snmp_user_output, require_priv=False)
CHECKS['V-220605'] = lambda cfg: _snmpv3_user_live_check(snmp_user_output, require_priv=True)
# The release is in running-config's `version 17.12` line, but the model is not,
# and the two together are what decides the rule - a release Cisco still ships
# for one platform can be unsupported hardware on another. So this reads
# `show version` like the other live-state checks rather than the config.
CHECKS['V-220621'] = lambda cfg: _ios_release_supported_check(version_output)

# Re-key onto the IOS XE STIG last, after the live-discovery entries above have
# been added, so those carry over too. Anything ios_xe_rule_map leaves out has
# no entry here and run_stig_audit reports it NOT AUTOMATED - the honest verdict
# for a rule whose IOS predicate would answer a different question.
# Rules the IOS XE book asks differently enough to need their own check, so
# they cannot be served by re-keying an IOS one. Applied after translate(),
# which is also why they are not in ios_xe_rule_map's RULE_MAP - there is no
# IOS rule to map them to.
if args.approved_ca_hosts:
    approved_ca_hosts = [host.strip() for host in args.approved_ca_hosts.split(',') if host.strip()]
else:
    approved_ca_hosts = netauto.load_approved_ca_hosts() or list(APPROVED_CA_HOSTS)

IOS_XE_ONLY_CHECKS = {
    'V-220554': _ntp_auth_cryptographic_check,  # weaker than IOS V-220606, see the check
    'V-220566': _config_backup_check,           # EEM applet; the IOS rule needs a server nothing here knows
    'V-220567': lambda cfg: _pki_trustpoint_check(cfg, approved_ca_hosts),  # no IOS L2S counterpart
    'V-220651': _qos_bandwidth_check,           # MQC; the IOS rule's `mls qos` cannot answer it
}

if args.checklist == 'ios-xe':
    checklist_path = IOS_XE_CHECKLIST_PATH
    audit_title = 'STIG audit (Cisco IOS XE Switch L2S/NDM)'
    CHECKS = ios_xe_rule_map.translate(CHECKS)
    CHECKS.update(IOS_XE_ONLY_CHECKS)
else:
    checklist_path = CHECKLIST_PATH
    audit_title = 'STIG audit'

# Last, so the re-keyed checks and the IOS XE-only ones are wrapped as well.
# A check reads the config it is handed, and on a switch that sources interface
# templates the config alone is not the switch's configuration.
if template_bodies:
    CHECKS = {rule_id: stig_common.through_templates(check, template_bodies)
              for rule_id, check in CHECKS.items()}

stig_common.run_stig_audit(
    device_name, device_info, checklist_path, CHECKS,
    title=audit_title,
    username=username, password=password,
    session=audit_session,
    to_cklb=args.to_cklb,
    target_data=target_data,
    captured_on=captured_on,
)
