#!/usr/bin/env python
"""Audit a device's running-config against the DISA Cisco NX-OS Switch L2S/NDM
STIG rules in New NXOS Checklist.cklb, reporting PASS/FAIL for the rules that
can be checked from config text alone."""

import argparse
import ipaddress
import re
import os

import netauto
import stig_common

CHECKLIST_PATH = os.path.join(netauto.PROJECT_ROOT, 'checklists', 'New NXOS Checklist.cklb')


# Interface types that take switchport commands on NX-OS - mgmt0, Vlan<n>
# (SVIs), and loopback<n> aren't physical/logical switchports. Same list
# nxos_stig_harden_global.py uses.
NXOS_SWITCHPORT_PREFIXES = ('Ethernet', 'port-channel')

# 'show interface status' uses abbreviated interface names ('Eth1/5',
# 'Po10') - running-config uses the full form ('Ethernet1/5',
# 'port-channel10'). Same mapping nxos_stig_harden_interfaces.py uses.
_SHORT_TO_FULL_PREFIX = (('Eth', 'Ethernet'), ('Po', 'port-channel'))

# Every status value 'show interface status' actually prints in the Status
# column - used as an anchor to pull the status out of a fixed-width table
# whose Name field is free text that can't be reliably column-sliced.
_INTERFACE_STATUSES = (
    'connected', 'disabled', 'suspended', 'notconnect', 'noOperMem',
    'inactive', 'xcvrAbsent', 'sfpAbsent', 'err-disabled',
)


def parse_interface_status(output):
    """Maps every interface name (expanded to running-config form) found in
    'show interface status' output to its Status column value. 'disabled'
    specifically means administratively shutdown - confirmed live on
    NXCore1, distinct from 'suspended'/'notconnect' which don't mean unused.
    Same parser nxos_stig_harden_interfaces.py uses to decide what to push -
    kept in sync so the audit checks the same "not in use" definition the
    harden side acts on."""
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


def parse_switchports(cfg):
    """Classify every switchport-capable interface as access or trunk based on
    explicit evidence in its own config block - NOT nxos_stig_harden_global.py's
    push-time assumption that "lacks an access VLAN, so it should become
    trunk" (that's a policy for what to push, not evidence of what's already
    there). Access: explicit 'switchport access vlan <n>' line - the only
    reliable access signal on NX-OS (confirmed live that 'switchport mode
    access' alone doesn't consistently appear in running-config, same
    omission nxos_stig_harden_global.py's own classify_switchports() works around).
    Trunk: explicit 'switchport mode trunk' line. A port with neither (still
    in NX-OS's default negotiated/L3-routed state) falls into neither bucket -
    it's not silently treated as access; V-220694's check below is the one
    that catches that ambiguous state directly.
    Returns (access_blocks, trunk_blocks), each {interface_name: block_text}."""
    access, trunk = {}, {}
    for chunk in re.split(r'^(?=interface \S+)', cfg, flags=re.M):
        m = re.match(r'interface (\S+)', chunk)
        if not m or not m.group(1).startswith(NXOS_SWITCHPORT_PREFIXES):
            continue
        name = m.group(1)
        if re.search(r'^\s*switchport access vlan \d+\s*$', chunk, re.M):
            access[name] = chunk
        elif re.search(r'^\s*switchport mode trunk\s*$', chunk, re.M):
            trunk[name] = chunk
    return access, trunk


def _all_access_ports_have(cfg, pattern, what, exclude_vlan=None):
    """exclude_vlan drops ports assigned to the given VLAN from the access
    population before checking - used to exclude unused_vlan-assigned ports
    (V-220690's disabled-port bucket) from host-facing-only requirements
    like UUFB/IPSG/storm control. Those rules' own titles say "host-facing
    or untrusted access switch ports" - a port deliberately parked on the
    black-hole VLAN isn't host-facing, it's not in use at all."""
    access, _ = parse_switchports(cfg)
    if exclude_vlan:
        access = {
            name: block for name, block in access.items()
            if not re.search(rf'^\s*switchport access vlan {exclude_vlan}\s*$', block, re.M)
        }
    if not access:
        return None, (
            'not applicable - no access-classified switchports found in config '
            '(this rule only governs host-facing access ports)'
        )
    missing = sorted(name for name, block in access.items() if not re.search(pattern, block))
    if missing:
        return False, f'missing {what} on: {", ".join(missing)}'
    return True, f'{what} present on all {len(access)} access port(s): {", ".join(sorted(access))}'


def _all_trunk_ports_have(cfg, pattern, what):
    _, trunk = parse_switchports(cfg)
    if not trunk:
        return False, 'no trunk-classified switchports found in config'
    missing = sorted(name for name, block in trunk.items() if not re.search(pattern, block))
    if missing:
        return False, f'missing {what} on: {", ".join(missing)}'
    return True, f'{what} present on all {len(trunk)} trunk port(s): {", ".join(sorted(trunk))}'


# V-220692: same pruning logic as l2_stig_audit.py's default_vlan_pruned_from_trunks,
# adapted to NX-OS's identical 'switchport trunk allowed vlan <spec>' syntax
# (confirmed same command form as IOS, per nxos_stig_harden_global.py's V-220692 push).
def _default_vlan_pruned_from_trunks(cfg):
    _, trunk = parse_switchports(cfg)
    if not trunk:
        return False, 'no trunk-classified switchports found in config'
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


# V-220694: unlike L2S's access-layer switches (default policy: non-trunk =
# access), nxos_stig_harden_global.py's core-switch policy is the inverse (default:
# non-access = trunk) - so "must be configured as access" can't be checked
# literally per-port here without topology knowledge this script doesn't
# have (which ports are host-facing vs. interconnects on a core switch).
# What IS checkable, and what the rule's underlying intent actually is (see
# l2_stig_audit.py's V-220645 - same reasoning): no switchport-capable
# interface should be left without an explicit access-or-trunk
# classification, i.e. sitting in NX-OS's default negotiated/L3-routed
# state. That ambiguous state is the real risk DISA is guarding against.
def _all_ports_explicit_mode(cfg):
    bad, total = [], 0
    for chunk in re.split(r'^(?=interface \S+)', cfg, flags=re.M):
        m = re.match(r'interface (\S+)', chunk)
        if not m or not m.group(1).startswith(NXOS_SWITCHPORT_PREFIXES):
            continue
        total += 1
        is_access = bool(re.search(r'^\s*switchport access vlan \d+\s*$', chunk, re.M))
        is_trunk = bool(re.search(r'^\s*switchport mode trunk\s*$', chunk, re.M))
        if not (is_access or is_trunk):
            bad.append(m.group(1))
    if total == 0:
        return False, 'no switchport-capable interfaces found in config'
    if bad:
        return False, (
            f'left without an explicit access or trunk classification (still in '
            f"NX-OS's default negotiated/routed state): {', '.join(sorted(bad))}"
        )
    return True, f'all {total} switchport-capable interface(s) explicitly classified as access or trunk'


def _no_access_ports_on_native_vlan(cfg, native_vlan_id):
    """V-220696: no access-classified switchport should be assigned to the
    native VLAN. Satisfied by construction in this project's design (access
    ports get real user VLANs like 50/100, the native VLAN is a dedicated
    unused/black-hole VLAN reserved for trunk native assignment only) - this
    verifies it independently rather than assuming the design held."""
    if not native_vlan_id:
        return None, 'not applicable - no native_vlan configured in inventory.yaml'
    access, _ = parse_switchports(cfg)
    if not access:
        return None, 'not applicable - no access-classified switchports found in config'
    offenders = sorted(
        name for name, block in access.items()
        if re.search(rf'^\s*switchport access vlan {native_vlan_id}\s*$', block, re.M)
    )
    if offenders:
        return False, f'access port(s) assigned to native VLAN {native_vlan_id}: {", ".join(offenders)}'
    return True, f'no access port(s) assigned to native VLAN {native_vlan_id} (checked {len(access)} access port(s))'


def _disabled_ports_on_unused_vlan(cfg, unused_vlan, interface_statuses):
    """V-220690. Check Content's literal finding condition: "If there are
    any access switch ports not in use and not in an inactive VLAN, this is
    a finding." "Not in use" is verified via 'show interface status''s
    'disabled' status (administratively shutdown) rather than parse_switchports()'s
    access/trunk split - a disabled port pushed to trunk mode by an earlier
    nxos_stig_harden_interfaces.py run (before this feature existed) would
    otherwise be invisible to this check, which only inspects access-block
    text. Every switchport-capable interface currently reported 'disabled'
    needs an explicit 'switchport access vlan <unused_vlan>' line,
    regardless of its current access/trunk classification."""
    if not unused_vlan:
        return None, 'not applicable - no unused_vlan configured in inventory.yaml'
    offenders, checked = [], 0
    for chunk in re.split(r'^(?=interface \S+)', cfg, flags=re.M):
        m = re.match(r'interface (\S+)', chunk)
        if not m or not m.group(1).startswith(NXOS_SWITCHPORT_PREFIXES):
            continue
        name = m.group(1)
        if interface_statuses.get(name) != 'disabled':
            continue
        checked += 1
        if not re.search(rf'^\s*switchport access vlan {unused_vlan}\s*$', chunk, re.M):
            offenders.append(name)
    if checked == 0:
        return None, 'not applicable - no administratively-shutdown switchport-capable interfaces found'
    if offenders:
        return False, f'disabled port(s) not assigned to unused VLAN {unused_vlan}: {", ".join(sorted(offenders))}'
    return True, f'all {checked} disabled switchport-capable interface(s) assigned to unused VLAN {unused_vlan}'


def _default_vlan_not_for_mgmt(cfg):
    """V-220693. Check Content's literal finding condition: "If the default
    VLAN is being used for management access to the switch, this is a
    finding" - its own example shows a bare 'interface Vlan1' (no config
    under it) as compliant, vs. 'interface Vlan44' carrying the actual
    management IP. Checks for an 'ip address' line specifically in Vlan1's
    block, not just any config there."""
    for chunk in re.split(r'^(?=interface \S+)', cfg, flags=re.M):
        if re.match(r'interface Vlan1\s*$', chunk, re.M):
            if re.search(r'^\s*ip address \S+', chunk, re.M):
                return False, 'interface Vlan1 has an IP address configured - default VLAN used for management'
            return True, 'interface Vlan1 has no IP address configured'
    return None, 'not applicable - no interface Vlan1 found in config'


def _snmp_v3_fips_check(cfg):
    """V-220500/501: both rules share the identical Check/Fix Text example
    ('snmp-server user NETOPS auth sha ... priv aes-128 ...') under
    different CCI categories (auth HMAC vs. priv encryption) - one check
    covers both, same shape as _ssh_macs_fips_check. Checks every
    'snmp-server user' line, not just the first - confirmed live on
    NXCore1 that a pre-existing default 'admin'/'network-admin' user (MD5
    auth, not SHA) sorts before the pushed compliant user in running-config,
    so a first-match-only search reports the wrong user's line and false
    FAILs even though a compliant user exists."""
    lines = [m.group(0).strip() for m in re.finditer(r'^snmp-server user \S+.*$', cfg, re.M)]
    if not lines:
        return False, 'no `snmp-server user` line found'
    for line in lines:
        if 'auth sha' in line and 'priv aes-128' in line:
            return True, f'FIPS-validated SNMPv3 auth/priv configured: `{line}`'
    return False, f'no `snmp-server user` line uses both auth sha and priv aes-128 - found: {"; ".join(f"`{l}`" for l in lines)}'


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
    if 'feature dhcp' not in cfg:
        return False, 'missing `feature dhcp`'
    if not re.search(r'^ip dhcp snooping$', cfg, re.M):
        return False, 'missing `ip dhcp snooping` (globally enabled)'
    return _vlan_range_covers_user_vlans(
        cfg, r'ip dhcp snooping vlan (\S+)', user_vlans, 'an `ip dhcp snooping vlan <list>` line'
    )


def _bpdu_guard_check(cfg):
    """V-220681: like L2S's V-220630, the global 'spanning-tree port type edge
    bpduguard default' form only activates BPDU Guard on ports typed as
    "edge" (NX-OS's PortFast equivalent) - checking for its presence alone is
    a false-pass risk if edge type was never enabled anywhere (globally via
    'spanning-tree port type edge default', or per-port via 'spanning-tree
    port type edge'). The per-interface 'spanning-tree bpduguard enable'
    form has no such dependency and is accepted on its own."""
    if re.search(r'spanning-tree bpduguard enable', cfg):
        return True, 'found: `spanning-tree bpduguard enable` (per-interface, no edge-type dependency)'
    has_bpduguard_default = bool(re.search(r'^spanning-tree port type edge bpduguard default\s*$', cfg, re.M))
    has_edge_type = bool(re.search(r'^\s*spanning-tree port type edge(?:\s+default)?\s*$', cfg, re.M))
    if has_bpduguard_default and has_edge_type:
        return True, 'found: `spanning-tree port type edge default` (or per-port) + `spanning-tree port type edge bpduguard default`'
    if has_bpduguard_default:
        return False, (
            '`spanning-tree port type edge bpduguard default` present but no edge port type found '
            '(`spanning-tree port type edge default` globally, or `spanning-tree port type edge` per-port) '
            '- BPDU Guard has no edge ports to activate on'
        )
    return False, 'missing BPDU Guard (`spanning-tree bpduguard enable` per-interface, or `spanning-tree port type edge bpduguard default` + edge type)'


def _password_strength_check(cfg):
    """V-220489/490/491/492: password complexity (strength-check) is enabled
    by default on NX-OS - DISA's Check Text says the compliant state is that
    `no password strength-check` should NOT be found, not that `password
    strength-check` must be explicitly present. The old check used
    `'password strength-check' in cfg`, a plain substring test that also
    matches inside `no password strength-check` - meaning a device that
    explicitly disabled it would still show a false PASS."""
    if re.search(r'^no password strength-check\s*$', cfg, re.M):
        return False, 'found `no password strength-check` - password complexity is explicitly disabled'
    return True, 'password strength-check enabled (default-on, not explicitly disabled)'


def _line_exec_timeout_ok_nxos(chunk, max_minutes=5):
    """NX-OS's exec-timeout takes a single argument (minutes only), unlike
    IOS's two-argument 'exec-timeout <min> <sec>' form. Returns
    (ok, matched_text_or_None)."""
    m = re.search(r'exec-timeout (\d+)', chunk)
    if not m:
        return False, None
    minutes = int(m.group(1))
    return minutes != 0 and minutes <= max_minutes, m.group(0)


def _exec_timeout_check(cfg):
    """V-220493: stig_common.exec_timeout_ok() assumes IOS's two-argument
    exec-timeout syntax and will never match real NX-OS config (single
    argument), causing a permanent false FAIL regardless of actual
    compliance. DISA's Check Text also configures exec-timeout on both
    `line console` and `line vty` as separate required scopes - same
    false-pass shape as L2S's V-220596 if only checked as "any exec-timeout
    line present"."""
    con_ok = con_match = vty_ok = vty_match = None
    for chunk in re.split(r'^(?=line \S)', cfg, flags=re.M):
        header = chunk.splitlines()[0] if chunk else ''
        if header.startswith('line console'):
            con_ok, con_match = _line_exec_timeout_ok_nxos(chunk)
        elif header.startswith('line vty'):
            ok, match = _line_exec_timeout_ok_nxos(chunk)
            vty_ok = bool(vty_ok) or ok
            vty_match = vty_match or match

    if con_ok and vty_ok:
        return True, f'compliant on console (`{con_match}`) and vty (`{vty_match}`)'
    missing = []
    if not con_ok:
        missing.append('console (`line console`): ' + (f'non-compliant (`{con_match}`)' if con_match else 'no exec-timeout set'))
    if not vty_ok:
        missing.append('vty: ' + (f'non-compliant (`{vty_match}`)' if vty_match else 'no exec-timeout set'))
    return False, '; '.join(missing)


def _ssh_macs_fips_check(cfg):
    """V-220488/503: both rules share the identical Fix Text example ('ssh
    macs hmac-sha2-256 hmac-sha2-512') under different CCI categories
    (replay-resistant auth vs. FIPS-validated HMAC integrity) - one check
    covers both. That Fix Text example doesn't carry over to NX-OS though
    (confirmed live on NXCore1: 'ssh macs' takes exactly one algorithm name
    per invocation, not a list) - and hmac-sha2-256/hmac-sha2-512 are
    already in NX-OS's default MAC allow-list on this platform ("Config is
    already present" pushing either), which also means they never appear in
    plain `show running-config` the way most default state doesn't. What
    running-config *does* show is explicit 'no ssh macs <algo>' overrides -
    same as 'no password strength-check' - so the actual compliant state
    here (confirmed via `show running-config all | include macs`) is
    verified by checking that everything except hmac-sha2-256/hmac-sha2-512
    is explicitly disabled: hmac-sha1/hmac-sha1-etm@openssh.com are
    genuinely weak (SHA-1), while hmac-sha2-256-etm@openssh.com/
    hmac-sha2-512-etm@openssh.com are still SHA-2-based but outside the two
    algorithms DISA's Fix Text example names, so disabled too rather than
    left to interpretation."""
    non_compliant_macs = [
        'hmac-sha1', 'hmac-sha1-etm@openssh.com',
        'hmac-sha2-256-etm@openssh.com', 'hmac-sha2-512-etm@openssh.com',
    ]
    still_allowed = [algo for algo in non_compliant_macs if f'no ssh macs {algo}' not in cfg]
    if still_allowed:
        return False, f'MAC(s) not explicitly disabled: {", ".join(still_allowed)}'
    return True, (
        'all MACs besides hmac-sha2-256/hmac-sha2-512 explicitly disabled '
        '- those two remain allowed by NX-OS default'
    )


def _ssh_ciphers_fips_check(cfg):
    """V-220504: Fix Text's example ('ssh ciphers aes128-ctr aes256-ctr')
    doesn't carry over to NX-OS as a space-separated list either - same
    one-algorithm-per-invocation quirk already confirmed for 'ssh macs'
    (V-220488/503, _ssh_macs_fips_check above). Confirmed live on NXCore1
    via `show ssh ciphers`: aes128-ctr/aes256-ctr (DISA's named pair) are
    both already permitted by NX-OS default, along with three others not
    named by DISA - aes256-gcm@openssh.com/aes128-gcm@openssh.com (still
    FIPS-validated per the platform's own `show ssh ciphers` table, just
    not the exact pair DISA names - disabled anyway rather than left to
    interpretation, same treatment as the MACs check's sha2-etm variants)
    and chacha20-poly1305@openssh.com (confirmed FIPS=no on this platform -
    genuinely non-compliant). aes192-ctr/aes128-cbc/aes192-cbc/aes256-cbc
    are already denied by NX-OS default (also confirmed via the same live
    table), so they're not part of this check - only the currently-
    permitted-but-not-DISA-named set needs an explicit `no ssh ciphers
    <algo>` override to verify."""
    non_compliant_ciphers = [
        'aes256-gcm@openssh.com', 'aes128-gcm@openssh.com', 'chacha20-poly1305@openssh.com',
    ]
    still_allowed = [algo for algo in non_compliant_ciphers if f'no ssh ciphers {algo}' not in cfg]
    if still_allowed:
        return False, f'cipher(s) not explicitly disabled: {", ".join(still_allowed)}'
    return True, (
        'all ciphers besides aes128-ctr/aes256-ctr explicitly disabled '
        '- those two remain allowed by NX-OS default'
    )


def _ssh_login_attempts_check(cfg):
    """V-220480: 3 is NX-OS's own default value on this platform - confirmed
    via `show running-config all | include login-attempts` on NXCore1, which
    only appears there and not in plain `show running-config`, same
    hidden-default pattern as `feature ntp`/the FIPS MACs above. No explicit
    line therefore means the compliant default (3) is in effect, not a
    missing/failed push. Requires exactly 3, not "3 or fewer" - the Check
    Text's required value is the literal number 3, not an org-defined
    ceiling, so a stricter override (e.g. 1) is treated as a deviation from
    the specified value rather than automatically compliant."""
    m = re.search(r'^ssh login-attempts (\d+)', cfg, re.M)
    if not m:
        return True, 'no explicit override found - NX-OS default of 3 is in effect'
    attempts = int(m.group(1))
    if attempts == 3:
        return True, f'ssh login-attempts {attempts}'
    return False, f'ssh login-attempts {attempts} does not equal the required value of 3'


def _igmp_snooping_check(cfg):
    """V-220688: 'no ip igmp snooping' as a bare substring also matches inside
    unrelated NX-OS subcommands that start with the same prefix but disable a
    different feature entirely - 'no ip igmp snooping querier', 'no ip igmp
    snooping report-suppression', 'no ip igmp snooping proxy', etc. don't
    disable snooping itself, so a device using any of those false-failed.
    Check text's last sentence requires snooping enabled "for each VLAN" with
    no stated exemption (same literal-reading discipline as V-220696's native
    VLAN check), so any per-VLAN disable is still a finding regardless of
    which VLAN it targets."""
    if re.search(r'^no ip igmp snooping\s*$', cfg, re.M):
        return False, 'IGMP snooping disabled globally: `no ip igmp snooping`'
    per_vlan_disabled = re.findall(r'^no ip igmp snooping vlan (\d+)', cfg, re.M)
    if per_vlan_disabled:
        return False, f'IGMP snooping disabled on VLAN(s): {", ".join(sorted(per_vlan_disabled, key=int))}'
    return True, 'IGMP snooping enabled globally (default), no global or per-VLAN `no ip igmp snooping` override found'


def _udld_check(cfg):
    """V-220689: Fix Text's only command is 'feature udld' - confirmed live
    on NXCore1 that 'udld enable' isn't valid NX-OS syntax at all ("%
    Invalid command"). UDLD is on by default for every fiber interface once
    the feature itself is enabled, per the STIG's own note - no separate
    enable line needed. But Check Content's own compliant-example shows a
    second, independent form: per-interface 'udld disabled' can override
    that global default on a specific port - a plain 'feature udld in cfg'
    check missed that override entirely, a false PASS if any interface has
    it. Doesn't verify the Check Content's "has fiber optic interconnections
    with neighbors" precondition (not determinable from running-config text
    alone - would need live transceiver/interface-type data) - pushing UDLD
    unconditionally is harmless even absent fiber, so this stays automated
    rather than downgraded to NOT AUTOMATED for that unverifiable precondition."""
    if 'feature udld' not in cfg:
        return False, 'missing `feature udld`'
    offenders = []
    for chunk in re.split(r'^(?=interface \S+)', cfg, flags=re.M):
        m = re.match(r'interface (\S+)', chunk)
        if m and re.search(r'^\s*udld disabled\s*$', chunk, re.M):
            offenders.append(m.group(1))
    if offenders:
        return False, f'`feature udld` enabled globally but overridden with `udld disabled` on: {", ".join(sorted(offenders))}'
    return True, '`feature udld` enabled globally, no per-interface `udld disabled` override found'


def _ntp_auth_check(cfg):
    """V-220502: Check Content's own text is explicit: "Cisco NX-OS is
    limited to MD5 for NTP authentication, and incurs a permanent finding
    as it is not FIPS compliant." No NX-OS configuration can ever satisfy
    this rule, so it always reports FAIL regardless of config - the old
    version of this check returned True once MD5-based auth commands were
    present, which is a genuine false PASS against the checklist's own
    stated verdict. Still verifies whether the MD5-based mitigation (still
    DISA's own Fix Text recommendation, despite the permanent-finding note)
    is actually in place, since that's the practical remediation even
    though it can never achieve compliance - reported as context, not as a
    pass condition. '.*' between the server and 'key <id>' below - confirmed
    live on NXCore1 that NX-OS auto-inserts 'use-vrf default' between them
    ('ntp server <ip> use-vrf default key <id>'), so a tight '\\S+ key \\d+'
    adjacency never matches even when correctly configured."""
    md5_configured = (
        'ntp authenticate' in cfg
        and bool(re.search(r'ntp authentication-key \d+ md5 \S+', cfg))
        and bool(re.search(r'ntp trusted-key \d+', cfg))
        and bool(re.search(r'^ntp server \S+.*\bkey \d+', cfg, re.M))
    )
    mitigation = (
        'MD5-based NTP authentication is configured as the best available mitigation'
        if md5_configured else
        'MD5-based NTP authentication is not even configured'
    )
    return False, (
        'permanent finding on NX-OS - Check Text: "Cisco NX-OS is limited to MD5 for NTP authentication, '
        f'and incurs a permanent finding as it is not FIPS compliant." {mitigation}.'
    )


def _dot1x_mab_check(cfg):
    """V-220675/679: identical Check Content example ('dot1x pae authenticator'
    + 'dot1x port-control auto' + 'dot1x host-mode single-host' on every
    host-facing access port) under different CCI categories - one check
    covers both, same shape as L2S's V-220623 (_dot1x_mab_check there). The
    host-mode line is required too - Check Content's own Note: "Host-mode
    must be set to single-host, multi-domain, or multi-auth. Host-mode
    multi-host is not compliant" - so an explicit non-multi-host value is
    required, not just any/no host-mode line (same strict-on-silence
    treatment as V-220645). NX-OS's MAB indicator is the interface
    subcommand 'dot1x mac-auth-bypass' (not IOS's standalone 'mab') - not
    shown in this rule's own Check Content example (only the 802.1x form
    is), so this is inferred from real NX-OS dot1x command syntax rather
    than lifted directly from the checklist text; worth confirming live if
    NXCore1 ever needs MAB rather than full 802.1x.
    exclude_vlan=unused_vlan, same as sibling host-facing-only checks
    V-220683/685/687/691 (_all_access_ports_have) - confirmed live on
    NXCore1 that parse_switchports()'s access bucket also includes the 59
    disabled ports parked on the black-hole VLAN (they carry an explicit
    'switchport access vlan <unused_vlan>' line too), which don't need
    endpoint authentication since nothing is plugged into them.

    NOT APPLICABLE whenever IP Source Guard is active anywhere on the
    device: confirmed live on NXCore1 that 'feature dot1x' is rejected
    outright ("802.1X can't be enabled, IPSG is enabled in system") while
    IPSG is configured - the two are mutually exclusive at the Nexus 9000
    platform level (not just a per-port conflict), confirmed against
    Cisco's own documentation. Since this project's V-220685 (IP Source
    Guard) push is unconditional on every access port with a discovered
    user VLAN, 802.1x/MAB can never be enabled on these switches without
    first removing IPSG entirely - N/A, not a permanent FAIL, since the
    device is structurally incapable of running both, unlike the NTP MD5
    rule where compliance is simply out of reach."""
    if re.search(r'^\s*ip verify source dhcp-snooping-vlan\s*$', cfg, re.M):
        return None, (
            'not applicable - IP Source Guard is active on this device, and Nexus 9000 platform rejects '
            '`feature dot1x` while IPSG is enabled (confirmed live: "802.1X can\'t be enabled, IPSG is '
            'enabled in system") - mutually exclusive by platform design, not a configuration gap'
        )
    access, _ = parse_switchports(cfg)
    if unused_vlan:
        access = {
            name: block for name, block in access.items()
            if not re.search(rf'^\s*switchport access vlan {unused_vlan}\s*$', block, re.M)
        }
    if not access:
        return None, 'not applicable - no access-classified switchports found in config'
    missing = []
    for name, block in sorted(access.items()):
        has_dot1x = (
            re.search(r'dot1x pae authenticator', block)
            and re.search(r'dot1x port-control auto', block)
            and re.search(r'dot1x host-mode (single-host|multi-domain|multi-auth)\b', block)
        )
        has_mab = re.search(r'dot1x mac-auth-bypass', block)
        if not (has_dot1x or has_mab):
            missing.append(name)
    if missing:
        return False, (
            f'missing 802.1x (`dot1x pae authenticator` + `dot1x port-control auto` + a compliant '
            f'`dot1x host-mode single-host|multi-domain|multi-auth`) or MAB (`dot1x mac-auth-bypass`) on: '
            f'{", ".join(missing)}'
        )
    return True, f'802.1x or MAB present on all {len(access)} access port(s): {", ".join(sorted(access))}'


# V-220513: at least 2 RADIUS servers, actually used as the primary auth source
# - same reasoning as L2S's V-220617 (_radius_redundancy_check there), adapted
# to NX-OS's 'aaa group server radius <name>' / 'server <ip>' block syntax
# shown in this rule's own Check Content example.
def _radius_redundancy_check(cfg):
    if not re.search(r'^aaa authentication login \S+ group \S+', cfg, re.M):
        return False, 'missing an `aaa authentication login ... group <name> ...` line using a RADIUS group as the primary source'
    legacy_servers = re.findall(r'^radius-server host (\S+)', cfg, re.M)
    modern_servers = []
    for chunk in re.split(r'^(?=\S)', cfg, flags=re.M):
        if chunk.startswith('aaa group server radius'):
            modern_servers += re.findall(r'^\s*server (\S+)', chunk, re.M)
    servers = sorted(set(legacy_servers + modern_servers))
    if len(servers) >= 2:
        return True, f'found {len(servers)} RADIUS server(s): {", ".join(servers)}'
    if servers:
        return False, f'only {len(servers)} of 2+ required RADIUS server(s) found: {", ".join(servers)}'
    return False, 'no RADIUS servers found (checked `radius-server host` and `aaa group server radius` `server` lines - need 2+)'


def _acl_source_in_subnet_nxos(source_spec, subnet):
    """NX-OS ACL source syntax is CIDR-based ('10.1.48.0/24', 'host <ip>',
    'any'), unlike IOS's wildcard-mask form - see l2_stig_audit.py's
    _acl_source_in_subnet for the IOS equivalent this mirrors."""
    source_spec = source_spec.strip()
    if source_spec == 'any':
        return False
    m = re.match(r'host (\S+)$', source_spec)
    if m:
        try:
            return ipaddress.ip_address(m.group(1)) in subnet
        except ValueError:
            return False
    try:
        acl_net = ipaddress.ip_network(source_spec, strict=False)
        return acl_net.subnet_of(subnet)
    except ValueError:
        return False


def _mgmt_acl_check(cfg, subnet_str):
    """V-220479: applied either via 'line vty' + 'access-class <name> in'
    (classic, first Check Content example) or 'interface mgmt0' +
    'ip access-group <name> in' (NX-OS v8+, the rule's own second example) -
    accepts either. Same intent as L2S's V-220575 (_vty_management_acl_check
    there), adapted to NX-OS's CIDR-based ACL syntax."""
    if not subnet_str:
        return False, 'no `management_subnet` configured in inventory.yaml'
    subnet = ipaddress.ip_network(subnet_str, strict=False)

    acl_name = None
    m = re.search(r'^line vty\b.*\n(?:.*\n)*?\s*access-class (\S+) in', cfg, re.M)
    if m:
        acl_name = m.group(1)
    else:
        m = re.search(r'^interface mgmt0\s*\n(?:.*\n)*?\s*ip access-group (\S+) in', cfg, re.M)
        if m:
            acl_name = m.group(1)
    if not acl_name:
        return False, 'no `access-class <name> in` on `line vty`, or `ip access-group <name> in` on `interface mgmt0`'

    acl_block = None
    for chunk in re.split(r'^(?=\S)', cfg, flags=re.M):
        if chunk.startswith(f'ip access-list {acl_name}'):
            acl_block = chunk
            break
    if acl_block is None:
        return False, f'ACL `{acl_name}` applied but no `ip access-list {acl_name}` block found'

    permits = re.findall(r'^\s*\d+\s+permit ip (host \S+|\S+) any', acl_block, re.M)
    if not permits:
        return False, f'`{acl_name}` has no `permit ip <source> any` lines'
    bad = [src for src in permits if not _acl_source_in_subnet_nxos(src, subnet)]
    if bad:
        return False, f'`{acl_name}` permits source(s) outside {subnet_str}: {", ".join(bad)}'
    return True, f'`{acl_name}` permits only sources within {subnet_str}: {", ".join(permits)}'


def _root_guard_check(cfg, root_ports):
    """V-220680: same reasoning as L2S's V-220629 (_root_guard_check there) -
    Root Guard belongs on trunk ports connecting to other switches, never on
    this switch's own STP root port toward the root bridge (forcing that
    port into root-inconsistent/blocking state would be a real outage risk)."""
    _, trunk = parse_switchports(cfg)
    eligible = sorted(name for name in trunk if name not in root_ports)
    if not eligible:
        return True, (
            "no eligible trunk ports - every trunk port is this switch's STP root port "
            'toward the root bridge, and Root Guard must not be applied there'
        )
    missing = [name for name in eligible if not re.search(r'spanning-tree guard root', trunk[name])]
    if missing:
        return False, (
            f'missing `spanning-tree guard root` on: {", ".join(missing)} '
            f'(root port(s) excluded from this check: {", ".join(sorted(root_ports)) or "none"})'
        )
    return True, f'`spanning-tree guard root` present on all {len(eligible)} eligible trunk port(s): {", ".join(eligible)}'


def _aaa_accounting_check(cfg):
    """Shared by V-220475/476/477/478/482/485/494/495/506/507/509 - all
    eleven rules share the identical Check Content pattern (verify `aaa
    accounting default group <name>` is configured, and that group has a
    real AAA server behind it) under different CCI categories (account
    creation/modification/disabling/removal/enabling, admin activity,
    config-change logging, privilege modification/deletion, logon success/
    failure, privileged activities). NX-OS reports all of these as
    accounting records sent to the same AAA server group, so one check
    covers all eleven - same reuse pattern as L2S's
    _audit_info_protection_check for V-220583/584/585."""
    m = re.search(r'^aaa accounting default group (\S+)', cfg, re.M)
    if not m:
        return False, 'missing `aaa accounting default group <name>` line'
    group_name = m.group(1)
    for chunk in re.split(r'^(?=\S)', cfg, flags=re.M):
        if chunk.startswith(f'aaa group server radius {group_name}'):
            servers = re.findall(r'^\s*server (\S+)', chunk, re.M)
            if servers:
                return True, f'`aaa accounting default group {group_name}` configured, with {len(servers)} server(s): {", ".join(servers)}'
            return False, f'`aaa accounting default group {group_name}` configured, but `aaa group server radius {group_name}` block has no `server` lines'
    return False, f'`aaa accounting default group {group_name}` configured, but no matching `aaa group server radius {group_name}` block found'


def _logging_server_present_check(cfg):
    """V-220497 (alert on audit-failure events) and V-220512 (offload log
    records to a different system) both just need >=1 syslog server
    configured - a weaker version of V-220516's >=2-distinct-servers
    redundancy check, so a device already passing V-220516 passes these
    two for free."""
    m = re.search(r'^logging server (\S+)', cfg, re.M)
    if not m:
        return False, 'no `logging server <host>` line found'
    return True, f'`logging server {m.group(1)}` configured'


def _pki_trustpoint_check(cfg):
    """V-220515: Check Content itself says this is NOT APPLICABLE when no
    PKI is implemented. When a trustpoint does exist, confirming its issuer
    is a DOD/DOD-approved provider requires reading `show crypto ca
    certificates` CN/O/OU fields against an approved-provider list - not
    derivable from running-config text, so that case stays NOT AUTOMATED
    rather than being guessed at as a PASS or FAIL."""
    m = re.search(r'^crypto ca trustpoint (\S+)', cfg, re.M)
    if not m:
        return None, 'not applicable - no CA trustpoint configured'
    return 'NOT AUTOMATED', f'CA trustpoint `{m.group(1)}` configured - verify its issuer is a DOD/DOD-approved provider via `show crypto ca certificates` (CN/O/OU review), not derivable from running-config text'


# V-220486: Check Content's own wording only condemns telnet outright
# ("should never be enabled"); everything else in its example list "should
# only be enabled if required for operations" - deliberately not a blanket
# list like L2S's V-220586. 'feature dhcp' is excluded on purpose even
# though Check Content lists it as an example: this project requires it for
# DHCP snooping/V-220684 on NXCore1's server-facing ports, a genuine
# operational need per the rule's own carve-out. 'feature imp' from Check
# Content isn't included either - not a recognized real NX-OS feature name,
# worth confirming live before ever adding it. wccp/nxapi have no
# operational use anywhere in this project, so they're treated as
# unconditionally unnecessary alongside telnet.
UNNECESSARY_FEATURES_PATTERN = r'^\s*feature (telnet|wccp|nxapi)\s*$'


def _no_unnecessary_features_check(cfg):
    found = sorted(set(re.findall(UNNECESSARY_FEATURES_PATTERN, cfg, re.M)))
    if found:
        return False, f'enabled (should be disabled): {", ".join(f"feature {name}" for name in found)}'
    return True, 'none of the unnecessary/nonsecure features (telnet/wccp/nxapi) found enabled'


def _logon_audit_records_check(cfg):
    """V-220508: Check Content's evidence ('logging logfile LOG_FILE 6' +
    'logging level authpri 6') is identical to V-220496/V-220510's already-
    automated checks, just without V-220496's 'size nnnnn' clause - reuses
    both existing patterns rather than duplicating a third slightly-looser
    logfile regex. No new harden-side push needed; both commands are
    already pushed by nxos_stig_harden_global.py."""
    has_logfile = re.search(r'^logging logfile \S+ \d+', cfg, re.M)
    has_level = re.search(r'^logging level authpriv? 6', cfg, re.M)
    if has_logfile and has_level:
        return True, 'both `logging logfile <name> <level> ...` and `logging level authpriv 6` present'
    missing = [name for name, present in (('`logging logfile <name> <level> ...`', has_logfile), ('`logging level authpriv 6`', has_level)) if not present]
    return False, f'missing: {", ".join(missing)}'


# Regex/keyword checks for rules that can be verified directly from running-config
# text. Rules with no entry here need external infrastructure (RADIUS, syslog,
# NTP, PKI) or manual/topology review, and are reported as NOT AUTOMATED.
CHECKS = {
    # --- L2S (Layer 2 Switch) ---
    # V-220683/685/687/691/692/694/695 (unicast flood blocking, IP source guard,
    # storm control, default VLAN on host ports, default VLAN pruned from trunks,
    # access ports, native VLAN) are per-interface, verified via parse_switchports()
    # above - same interface-classification approach as l2_stig_audit.py, adapted
    # to NX-OS's own reliable signals (see that function's docstring for why).
    # exclude_vlan=unused_vlan on all four - unused_vlan is a module-level
    # global assigned further down (after the device connection), but these
    # lambdas aren't called until stig_common.run_stig_audit() runs, well
    # after that assignment, so Python's late-binding closures resolve it
    # correctly at call time.
    'V-220683': lambda cfg: _all_access_ports_have(cfg, r'switchport block unicast', 'UUFB (`switchport block unicast`)', exclude_vlan=unused_vlan),
    'V-220685': lambda cfg: _all_access_ports_have(cfg, r'ip verify source dhcp-snooping-vlan', 'IP Source Guard (`ip verify source dhcp-snooping-vlan`)', exclude_vlan=unused_vlan),
    'V-220687': lambda cfg: _all_access_ports_have(cfg, r'storm-control broadcast level \d+', 'storm control (`storm-control broadcast level <n>`)', exclude_vlan=unused_vlan),
    'V-220691': lambda cfg: _all_access_ports_have(cfg, r'switchport access vlan (?!1\s*$)\d+', 'an explicit non-default access VLAN (not VLAN 1)', exclude_vlan=unused_vlan),
    'V-220692': _default_vlan_pruned_from_trunks,
    'V-220694': _all_ports_explicit_mode,
    'V-220695': lambda cfg: _all_trunk_ports_have(cfg, r'switchport trunk native vlan (?!1\s*$)\d+', 'a non-default native VLAN'),
    # V-220676 (VTP password) is added below, after a separate `show vtp
    # password` command - confirmed live on NXCore1 that NX-OS deliberately
    # omits the VTP password from `show running-config` entirely (only
    # 'feature vtp'/'vtp domain' show there), so scanning running-config text
    # for it can never pass regardless of whether it's actually set.
    'V-220681': _bpdu_guard_check,
    'V-220682': lambda cfg: 'spanning-tree loopguard default' in cfg,
    # V-220684/686 (DHCP snooping/DAI VLAN coverage) are added below, after
    # discovering the device's genuine user VLANs - a plain presence check can't
    # tell "configured for the wrong VLANs" from "configured correctly" (e.g.
    # snooping enabled on VLAN 1,10 while the real user VLAN has none).
    'V-220688': _igmp_snooping_check,
    'V-220689': _udld_check,
    # No 'feature ntp' requirement here, unlike V-220689/676/684's feature
    # checks - confirmed live on NXCore1 that NTP isn't gated behind an
    # explicit feature toggle on this platform/image ('feature ntp' pushes
    # as a no-op, "NTP feature is already enabled", and never appears in
    # `show running-config` even with NTP fully configured and working).
    # V-220516: same >=2-distinct-servers shape as V-220498's NTP check below.
    'V-220516': lambda cfg: len(set(re.findall(r'^logging server (\S+)', cfg, re.M))) >= 2,
    # V-220497/V-220512: weaker single-server versions of V-220516 above.
    'V-220497': _logging_server_present_check,
    'V-220512': _logging_server_present_check,
    # V-220496: buffer size for the local logfile, distinct from the syslog
    # server checks above.
    'V-220496': lambda cfg: bool(re.search(r'^logging logfile \S+ \d+ size \d+', cfg, re.M)),
    # V-220474: Check Text's example scopes session-limit to 'line vty' only
    # (not 'line console') - the bare command is unambiguous enough on its
    # own that a plain search doesn't risk matching anything else.
    'V-220474': lambda cfg: bool(re.search(r'session-limit \d+', cfg)),
    # V-220480: Check Text's required value is literally 3, not an
    # org-defined number - matches the exact command this project pushes.
    'V-220480': _ssh_login_attempts_check,
    'V-220488': _ssh_macs_fips_check,
    'V-220503': _ssh_macs_fips_check,
    'V-220504': _ssh_ciphers_fips_check,
    'V-220498': lambda cfg: len(set(re.findall(r'^ntp server (\S+)', cfg, re.M))) >= 2,
    'V-220502': _ntp_auth_check,
    # V-220499: UTC is the default zone (compliant, and the checklist itself
    # notes `clock timezone` may not appear in the config even when
    # compliant), and NX-OS's `clock timezone` command always requires an
    # explicit offset when it IS set - so every possible running-config
    # state is mappable to UTC/GMT. This can never fail from config text.
    'V-220499': lambda cfg: (True, 'UTC is the default (compliant); if `clock timezone` is set, NX-OS requires an explicit offset, which is inherently mappable to UTC too - this rule can never fail from config text alone'),
    'V-220515': _pki_trustpoint_check,
    'V-220486': _no_unnecessary_features_check,
    'V-220508': _logon_audit_records_check,

    # --- NDM (Network Device Management) ---
    'V-220481': lambda cfg: bool(re.search(r'banner (login|motd)', cfg)),
    'V-220489': _password_strength_check,
    'V-220490': _password_strength_check,
    'V-220491': _password_strength_check,
    'V-220492': _password_strength_check,
    'V-220493': _exec_timeout_check,
    'V-220693': _default_vlan_not_for_mgmt,
    'V-220500': _snmp_v3_fips_check,
    'V-220501': _snmp_v3_fips_check,
    'V-220675': _dot1x_mab_check,
    'V-220679': _dot1x_mab_check,
    'V-220513': _radius_redundancy_check,
    'V-220479': lambda cfg: _mgmt_acl_check(cfg, netauto.load_management_subnet()),
    # V-220487 (single local fallback account) is deliberately left NOT AUTOMATED
    # on NX-OS, unlike L2S's V-220587 - confirmed live on NXCore1 that NX-OS ties
    # every CLI username to an auto-generated SNMPv3 credential (both `admin` and
    # an explicitly-provisioned SNMPv3 user show up in both `show running-config`
    # `username`/`snmp-server user` lines AND `show user-account`), so there's no
    # config-text or live-command signal that reliably separates "real" login
    # accounts from SNMP-only shadow entries. Don't re-attempt a heuristic here
    # without new evidence - two attempts (cross-referencing snmp-server user
    # names, then the `username <name> passphrase lifetime` line) were tried and
    # reverted. NOT AUTOMATED was chosen deliberately over a single-example guess.
    'V-220475': _aaa_accounting_check,
    'V-220476': _aaa_accounting_check,
    'V-220477': _aaa_accounting_check,
    'V-220478': _aaa_accounting_check,
    'V-220482': _aaa_accounting_check,
    'V-220485': _aaa_accounting_check,
    'V-220494': _aaa_accounting_check,
    'V-220495': _aaa_accounting_check,
    'V-220506': _aaa_accounting_check,
    'V-220507': _aaa_accounting_check,
    'V-220509': _aaa_accounting_check,
    # V-220510: distinct from the aaa-accounting group above - Check Content's
    # example is a plain presence check on 'logging level authpri(v) 6', not
    # the accounting-record mechanism. Checklist itself misspells it 'authpri'
    # in Check Content but 'authpriv' in Fix Text - accepts either.
    'V-220510': lambda cfg: bool(re.search(r'^logging level authpriv? 6', cfg, re.M)),
}

# Parse the target device from the command line
parser = argparse.ArgumentParser(description='Audit a device against DISA NX-OS STIG rules from New NXOS Checklist.cklb')
parser.add_argument('device', help='Device name as it appears in inventory.yaml (e.g. NXCore1)')
args = parser.parse_args()

device_name = args.device

# Load the target device from the YAML inventory
all_devices = netauto.load_inventory()
device_info = netauto.require_devices(all_devices, [device_name])[device_name]

# Prompt for credentials
username, password = netauto.get_credentials()

# Discover genuine user VLANs (excludes management/servers/unused VLANs from
# inventory.yaml's non_user_vlans/non_user_vlans_by_device, plus unused_vlan/
# native_vlan) so V-220684/V-220686 can verify DHCP snooping/DAI actually
# cover them, not just that some VLAN list exists. Same exclude set
# nxos_stig_harden_global.py uses - without also excluding unused_vlan/native_vlan
# here, VLAN 999 (the designated black-hole/native VLAN) gets misclassified
# as an uncovered user VLAN once it exists in the database, the same bug
# already fixed on the harden side. Uses a separate connection since
# run_stig_audit manages its own for running-config.
vlan_discovery_connect = netauto.connect(device_name, device_info, username, password,
                                             purpose='live discovery: VTP password, root port, VLANs')
if vlan_discovery_connect is None:
    raise SystemExit(1)
non_user_vlan_exclude = list(netauto.load_non_user_vlans(device_name=device_name))
unused_vlan = netauto.load_unused_vlan()
native_vlan_id = netauto.load_native_vlan()
if unused_vlan:
    non_user_vlan_exclude.append(unused_vlan)
if native_vlan_id:
    non_user_vlan_exclude.append(native_vlan_id)
user_vlans = stig_common.discover_user_vlans(vlan_discovery_connect, exclude=non_user_vlan_exclude,
                                             exclude_names=netauto.load_non_user_vlan_names(),
                                             include_names=netauto.load_user_vlan_names())

# V-220676: 'show vtp password' instead of running-config - see the comment
# by CHECKS['V-220681'] above for why running-config text can't be used here.
vtp_password_output = str(vlan_discovery_connect.send_command('show vtp password'))

# V-220690: 'show interface status' for live admin state - see
# parse_interface_status()'s docstring for why running-config text alone
# (shutdown/no shutdown presence) isn't used here.
interface_statuses = parse_interface_status(str(vlan_discovery_connect.send_command('show interface status')))

# V-220680: same live STP root-port discovery l2_stig_audit.py uses for
# V-220629 - stig_common.discover_root_port_interfaces() parses 'show
# spanning-tree' generically, no NX-OS-specific handling needed.
root_ports = stig_common.discover_root_port_interfaces(vlan_discovery_connect)
vlan_discovery_connect.disconnect()

CHECKS['V-220684'] = lambda cfg: _dhcp_snooping_check(cfg, user_vlans)
CHECKS['V-220686'] = lambda cfg: _vlan_range_covers_user_vlans(
    cfg, r'ip arp inspection vlan (\S+)', user_vlans, 'an `ip arp inspection vlan <list>` line'
)
CHECKS['V-220676'] = lambda cfg: (
    bool(re.search(r'VTP password:\s*\S+', vtp_password_output)),
    'verified via `show vtp password` (NX-OS omits it from running-config)'
)
CHECKS['V-220696'] = lambda cfg: _no_access_ports_on_native_vlan(cfg, native_vlan_id)
CHECKS['V-220690'] = lambda cfg: _disabled_ports_on_unused_vlan(cfg, unused_vlan, interface_statuses)
CHECKS['V-220680'] = lambda cfg: _root_guard_check(cfg, root_ports)

stig_common.run_stig_audit(
    device_name, device_info, CHECKLIST_PATH, CHECKS,
    title='NX-OS STIG audit',
    username=username, password=password,
)
