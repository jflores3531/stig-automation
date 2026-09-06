#!/usr/bin/env python
"""Shared STIG audit runner used by ios_router_audit.py, l2_stig_audit.py, and
nxos_stig_audit.py: loads a DISA .cklb checklist, checks a device's
running-config against it, and prints a PASS/FAIL/NOT AUTOMATED report."""

import datetime
import fnmatch
import json
import os
import re

import netauto

SEVERITY_ORDER = {'high': 0, 'medium': 1, 'low': 2}


def run_stig_audit(device_name, device_info, checklist_path, checks, title, username, password,
                    not_automated_note='need manual review or external infrastructure',
                    session=None, to_cklb=None):
    """Connect to a device, check its running-config against a DISA STIG checklist's
    rules using `checks` (group_id -> predicate(running_config) -> bool, or
    -> (bool, reason) to show why a rule passed/failed, or -> (None, reason)
    to report NOT APPLICABLE when the rule's precondition doesn't hold on this
    device - e.g. a host-facing-port rule on a switch with no access ports at
    all, or -> ('NOT AUTOMATED', reason) when a rule is only conditionally
    automatable - e.g. a check that can determine NOT APPLICABLE from config
    text alone but needs manual review, like a live command's output, the
    rest of the time), and print a PASS/FAIL/NOT APPLICABLE/NOT AUTOMATED
    report. Rules with no entry in `checks` are reported as NOT AUTOMATED.

    `session` overrides connecting to the device: pass a capture.CaptureSession
    to audit text captured earlier instead of a live switch. Every check here
    is a pure function of command output, so the verdicts are identical either
    way - the only thing that changes is where the output came from. The
    stand-in implements send_command() and a no-op disconnect(), which is why
    the flow below needs no second branch."""
    with open(checklist_path, encoding='utf-8') as f:
        checklist = json.load(f)
    rules = [rule for stig in checklist['stigs'] for rule in stig['rules']]
    rules.sort(key=lambda rule: SEVERITY_ORDER.get(rule['severity'], 99))

    net_connect = session
    if net_connect is None:
        net_connect = netauto.connect(device_name, device_info, username, password)
        if net_connect is None:
            raise SystemExit(1)

    running_config = str(net_connect.send_command('show running-config'))
    net_connect.disconnect()

    results = {'PASS': 0, 'FAIL': 0, 'NOT APPLICABLE': 0, 'NOT AUTOMATED': 0}
    findings = []

    for rule in rules:
        group_id = rule['group_id']
        check = checks.get(group_id)
        reason = None

        if check is None:
            status = 'NOT AUTOMATED'
        else:
            result = check(running_config)
            passed, reason = result if isinstance(result, tuple) else (result, None)
            if isinstance(passed, str):
                status = passed
            else:
                status = 'NOT APPLICABLE' if passed is None else ('PASS' if passed else 'FAIL')
        results[status] += 1
        findings.append((status, rule, group_id, reason))

    print(f'{title} for {device_name}\n')
    print(f"{results['PASS']} passed, {results['FAIL']} failed, {results['NOT APPLICABLE']} not applicable, "
          f"{results['NOT AUTOMATED']} not automated ({not_automated_note}) out of {len(rules)} rules.\n")

    for status, rule, group_id, reason in findings:
        rule_title = re.sub(r'^The Cisco switch\s+', '', rule['rule_title'])
        print(f"[{rule['severity'].upper():6}] {status:14} {group_id}  {rule_title}")
        if reason:
            print(f"           {reason}")
        print()

    # Last, so a checklist is only written for a run that got far enough to
    # print its report - and so a failure here cannot cost the report itself.
    if to_cklb:
        source = (f'capture {net_connect.source}' if getattr(net_connect, 'source', None)
                  else f'device {device_name}')
        try:
            print(write_cklb(checklist_path, to_cklb, findings, device_name, source, title,
                             device_info=device_info))
        except (ChecklistError, OSError) as checklist_error:
            # The report above is complete and correct; only the file failed.
            # Said plainly, and with a non-zero exit so a script that asked for
            # a checklist does not carry on as though it got one.
            print(f'\nThe report above is complete, but the checklist was not written:\n'
                  f'{checklist_error}')
            raise SystemExit(2)

    return findings


# A report is read once and retyped into STIG Viewer by hand, which is the
# slowest and least reliable part of the whole exercise: 64 rules, four
# statuses, and a free-text box per rule that nobody fills in properly at
# rule 50. STIG Viewer 3's own file format is JSON - the same .cklb these
# audits already read the rules out of - so the verdicts can be written back
# into a copy of it and opened directly.
#
# The status names below are STIG Viewer 3's, and the mapping is the whole
# point of the feature, so each one is deliberate:
#
#   PASS           -> not_a_finding   the check ran and the switch complies
#   FAIL           -> open            the check ran and it does not
#   NOT APPLICABLE -> not_applicable  the rule's own precondition does not hold
#   NOT AUTOMATED  -> not_reviewed    nothing here reviewed it
#
# NOT AUTOMATED must never become not_a_finding. It is the one mapping that
# would turn "this tool did not look" into "a reviewer confirmed compliance",
# signed off under someone's name, on rules like the configuration backup one
# that genuinely need a human. not_reviewed is what STIG Viewer shows an
# unanswered rule as, which is exactly what it is - and the reason line still
# goes into finding_details, so the reviewer starts from what the audit did
# manage to determine rather than from nothing.
CKLB_STATUS = {
    'PASS': 'not_a_finding',
    'FAIL': 'open',
    'NOT APPLICABLE': 'not_applicable',
    'NOT AUTOMATED': 'not_reviewed',
}


class ChecklistError(Exception):
    """The checklist could not be written. Raised rather than degrading to a
    partial file: a .cklb that opens in STIG Viewer but carries half a run's
    verdicts is worse than none, because nothing about it looks wrong."""


def _existing_annotations(output_path):
    """Per-rule `comments` and `overrides` already in the file being replaced.

    A checklist that has been opened once is not just this tool's output any
    more. The division of labour is: the audit owns `status` and
    `finding_details` (it re-derives both on every run), the reviewer owns
    `comments` and any severity `overrides` (nothing here can re-derive
    those). Re-running the audit over yesterday's export therefore updates the
    verdicts and keeps the notes - without this, the second run silently
    deletes the reviewer's work on exactly the rules they had to answer by
    hand."""
    if not os.path.exists(output_path):
        return {}
    try:
        with open(output_path, encoding='utf-8') as existing_file:
            existing = json.load(existing_file)
        return {
            rule['group_id']: {'comments': rule.get('comments', ''),
                               'overrides': rule.get('overrides', {})}
            for stig in existing.get('stigs', []) for rule in stig.get('rules', [])
            if rule.get('comments') or rule.get('overrides')
        }
    except (ValueError, KeyError, OSError):
        # Not a readable .cklb - a stray file with the same name, or one
        # truncated by a crash. There is nothing to preserve, and refusing to
        # write over it would strand the run.
        return {}


def write_cklb(checklist_path, output_path, findings, device_name, source, title,
               device_info=None, run_at=None):
    """Write `findings` into a copy of the checklist as a STIG Viewer 3 .cklb.

    findings is run_stig_audit's list of (status, rule, group_id, reason).
    `source` says where the output came from - a device or a capture file - and
    is recorded per rule, because a verdict without its evidence's provenance
    is not evidence."""
    if os.path.abspath(checklist_path) == os.path.abspath(output_path):
        raise ChecklistError(
            f'Refusing to write over the blank checklist at {checklist_path}.\n'
            'That file is the template every audit reads its rules from; filling it in '
            'with one device\'s verdicts would leave the next run auditing against '
            "someone else's results. Choose another path.")

    with open(checklist_path, encoding='utf-8') as checklist_file:
        checklist = json.load(checklist_file)

    run_at = run_at or datetime.datetime.now()
    stamp = run_at.strftime('%Y-%m-%d %H:%M')
    kept = _existing_annotations(output_path)
    answered = {group_id: (status, reason) for status, _rule, group_id, reason in findings}

    counts = {}
    for stig in checklist.get('stigs', []):
        for rule in stig.get('rules', []):
            group_id = rule.get('group_id')
            if group_id not in answered:
                # A rule in the file the audit never reported on. It cannot
                # happen through run_stig_audit, which walks this same list,
                # but leaving it not_reviewed rather than assuming is the
                # only safe treatment if it ever does.
                continue
            status, reason = answered[group_id]
            rule['status'] = CKLB_STATUS[status]
            rule['finding_details'] = (
                f'{reason}\n\n' if reason else ''
            ) + f'{title} against {source}, {stamp}. Reported {status}.'
            if group_id in kept:
                rule['comments'] = kept[group_id]['comments']
                rule['overrides'] = kept[group_id]['overrides']
            counts[rule['status']] = counts.get(rule['status'], 0) + 1

    target = checklist.setdefault('target_data', {})
    target['host_name'] = device_name
    if device_info and device_info.get('host'):
        target['ip_address'] = device_info['host']
    target['comments'] = f'{title} against {source}, {stamp}.'

    parent = os.path.dirname(os.path.abspath(output_path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as output_file:
        json.dump(checklist, output_file, indent=2)

    summary = ', '.join(f'{counts.get(status, 0)} {status}'
                        for status in ('not_a_finding', 'open', 'not_applicable', 'not_reviewed'))
    kept_note = f', keeping reviewer comments on {len(kept)} rule(s)' if kept else ''
    return f'Wrote {output_path} for STIG Viewer 3: {summary}{kept_note}.'

def exec_timeout_ok(cfg, max_minutes=5):
    """True if every exec-timeout line sets a nonzero value no longer than
    max_minutes. 'exec-timeout 0 0' disables the timeout entirely, which is
    non-compliant, not a pass - it's excluded even though its minutes field
    (0) would otherwise be <= max_minutes."""
    matches = re.findall(r'exec-timeout (\d+) (\d+)', cfg)
    if not matches:
        return False
    for minutes, seconds in matches:
        minutes, seconds = int(minutes), int(seconds)
        if minutes == 0 and seconds == 0:
            return False
        if minutes > max_minutes:
            return False
    return True


class InventoryError(ValueError):
    """A value in inventory.yaml is not the kind of value it has to be.

    Raised rather than skipped: a VLAN ID that cannot be read leaves the
    user-VLAN classification wrong, and every DHCP snooping and DAI verdict
    downstream of it would be reported with the same confidence as a correct
    one. Refusing is the same call capture.py makes on a malformed capture."""


# A fleet does not always name a VLAN the same way twice. Where the user VLANs
# are called army-xxx-abc-user1 on one switch and army-yyy-def-user15 on the
# next - same role, different site prefix, different number, and a different
# VLAN ID under each - listing them by exact name means listing every switch's
# spelling of every one of them, and the first one missed is a real user VLAN
# silently dropped from the DHCP snooping and DAI coverage checks.
#
# So an entry carrying *, ? or [ ] is a glob (fnmatch), and anything else is
# the exact, case-insensitive match this has always done - existing inventories
# behave exactly as before. `*user` catches the names ending in it, `*user[0-9]*`
# the numbered ones, `*user*` both at the cost of also catching anything else
# with "user" in the name.
#
# Loose matching is safe in the include direction and dangerous in the exclude
# one, and that asymmetry is worth keeping in mind when writing a pattern: a
# too-broad user_vlan_names entry can only add VLANs to the audited set, which
# costs a spurious finding, while a too-broad non_user_vlan_names entry removes
# them, which costs a silent PASS on coverage nobody verified. The classification
# printed above each report names the pattern that matched, so a pattern that
# reaches further than intended is visible rather than inferred.
def _name_pattern_match(name, patterns):
    """The entry in `patterns` that matches `name`, or None. Exact match is
    case-insensitive; an entry with a wildcard is matched as a glob."""
    lowered = name.casefold()
    for pattern in patterns:
        candidate = str(pattern).strip()
        folded = candidate.casefold()
        if any(char in folded for char in '*?['):
            if fnmatch.fnmatchcase(lowered, folded):
                return candidate
        elif lowered == folded:
            return candidate
    return None


def classify_vlans(net_connect, exclude=(), exclude_names=(), include_names=()):
    """Return [(vlan_id, name, is_user, why), ...] for every VLAN in `show vlan
    brief`, with the reason each one was or was not classified a user VLAN.

    Names in `include_names`/`exclude_names` match exactly and case-insensitively,
    or as a glob if the entry carries a wildcard - see _name_pattern_match.

    discover_user_vlans keeps only the IDs; this is the same decision with its
    working shown, so an audit can print what it classified and be argued with.
    A VLAN wrongly sitting in the non-user list is invisible in the verdict -
    DHCP snooping and DAI coverage simply are not asked about it and the rule
    PASSes - so the classification has to be readable somewhere other than the
    inventory file that produced it."""
    exclude_ids = set()
    unreadable = []
    for value in exclude:
        try:
            exclude_ids.add(int(value))
        except (TypeError, ValueError):
            unreadable.append(repr(value))
    if unreadable:
        raise InventoryError(
            f'inventory.yaml: VLAN IDs must be numbers, but {", ".join(unreadable)} '
            f'{"is" if len(unreadable) == 1 else "are"} not - check non_user_vlans, '
            'non_user_vlans_by_device, unused_vlan and native_vlan')
    vlan_brief = str(net_connect.send_command('show vlan brief'))

    classified = []
    for vid, name in re.findall(r'^(\d+)\s+(\S+)', vlan_brief, re.M):
        included = _name_pattern_match(name, include_names)
        excluded = _name_pattern_match(name, exclude_names)
        if 1002 <= int(vid) <= 1005:
            classified.append((vid, name, False, 'reserved fddi/token-ring VLAN'))
        elif included:
            classified.append((vid, name, True, f'name matches user_vlan_names entry `{included}`'))
        elif int(vid) in exclude_ids:
            classified.append((vid, name, False, 'ID listed as non-user in inventory.yaml'))
        elif excluded:
            classified.append((vid, name, False,
                               f'name matches non_user_vlan_names entry `{excluded}`'))
        else:
            classified.append((vid, name, True, 'not excluded'))
    return classified


def describe_vlan_classification(classified, rule_ids):
    """The classification as report text: which VLANs the coverage rules were
    asked about, which were skipped and why, and how to correct it.

    Printed by the audits rather than buried in a verdict because the two are
    not equally visible. A user VLAN left out of this list produces no finding
    at all, so the only way to catch the omission is to read the list."""
    user = [f'{vid} {name}' for vid, name, is_user, _ in classified if is_user]
    skipped = [f'{vid} {name} ({why})' for vid, name, is_user, why in classified
               if not is_user and 'reserved' not in why]
    lines = [f'User VLANs checked for DHCP snooping/DAI coverage ({rule_ids}): '
             + (', '.join(user) or 'none')]
    if skipped:
        lines.append('  Not treated as user VLANs: ' + ', '.join(skipped))
    lines.append('  Every VLAN even one user can reside on belongs in the first list - if one is')
    lines.append("  missing, add its name to inventory.yaml's user_vlan_names (it wins over any")
    lines.append('  ID exclusion) and re-run.')
    return '\n'.join(lines)


def discover_user_vlans(net_connect, exclude=(), exclude_names=(), include_names=()):
    """Return a switch's user VLAN IDs from `show vlan brief`, excluding the
    reserved fddi/token-ring VLAN range (1002-1005), any VLAN IDs in `exclude`
    (e.g. management/servers/unused VLANs from inventory.yaml's non_user_vlans),
    and any VLAN whose name is in `exclude_names` (non_user_vlan_names).

    `include_names` is the important one on a fleet. A VLAN's number is a
    per-switch fact while its name tends to be a fleet-wide one: the user and
    voice VLANs get whatever ID each site had free, but they are called the same
    thing everywhere. A name listed here marks that VLAN a user VLAN whatever
    its number, and overrides both kinds of exclusion - so VLAN 10 named USERS
    on one switch is still audited for DHCP snooping and DAI coverage even
    though 10 is the management VLAN elsewhere and sits in non_user_vlans.
    Without that, the ID exclusion silently drops a real user VLAN and the audit
    reports PASS for coverage it never verified (V-220633/635, V-220684/686).

    `exclude_names` is the mirror, for a non-user VLAN whose ID varies instead.
    Where every non-user VLAN is consistently numbered, the ID list already
    covers them and this can stay empty.

    A name is matched exactly and case-insensitively, or as a glob if the entry
    carries a wildcard - `*user`, `*user[0-9]*` - which is what covers a fleet
    that names the same role army-xxx-abc-user1 here and army-yyy-def-user15
    there. See _name_pattern_match; a substring is never implied, so a pattern
    reaches exactly as far as it says. A loose include is the dangerous
    direction only in reverse - it can only add VLANs to the audited set, so the
    cost of an over-broad name is a spurious finding rather than a silent pass.
    An entry that matches nothing changes nothing.

    `show vlan brief` already carries the name column, so this costs no extra
    command and works on a capture exactly as it does on a live session.

    The classification itself lives in classify_vlans, which keeps the reason
    for each decision; this is that list with the reasons dropped."""
    return [vid for vid, _, is_user, _ in classify_vlans(
        net_connect, exclude=exclude, exclude_names=exclude_names,
        include_names=include_names) if is_user]


# An IOS XE interface can be configured from an interface template: the port's
# block carries one line, `source template USER_PORT`, and the commands it
# stands for - access VLAN, mode, PortFast, BPDU Guard, 802.1x - are in the
# template and appear nowhere in running-config. Every per-port rule in
# l2_stig_audit.py reads the interface block, so on a fleet that templates its
# user ports those rules were answering against a block with nothing in it:
# V-220668 and V-220671 checked false by hand against the switch that produced
# the report, V-220649 and V-220656 unanswerable either way. The commands
# exist; the config text just does not show them.
#
# `show template interface source user <name>` does, one command per template
# rather than per interface. Its body is spliced into each block that sources
# it before any check runs, so the checks need no notion of templates at all -
# they see the port's effective configuration, which is what the STIG asks
# about.
#
# Metadata is dropped by shape: the header lines this prints are `Name : value`
# with a capitalised label, and no IOS interface command begins with a capital,
# so a `description Uplink: core` in a template body survives.
_TEMPLATE_METADATA = re.compile(r'[A-Z][A-Za-z ]{0,30}:')


def parse_interface_template(output):
    """The configuration lines from `show template interface source user
    <name>` output, in order. Empty if the switch had nothing to show for that
    name - which is not the same as a template with no commands in it, and the
    caller reports it rather than silently expanding nothing."""
    lines = []
    for line in str(output).splitlines():
        stripped = line.strip()
        if not stripped or stripped in ('!', 'end'):
            continue
        if set(stripped) <= set('-=_'):  # the separator rule around the body
            continue
        if stripped.lower().startswith('building configuration'):
            continue
        if stripped.startswith('%'):  # '% Template not found' and friends
            continue
        if _TEMPLATE_METADATA.match(stripped):
            continue
        lines.append(stripped)
    return lines


def expand_interface_templates(cfg, template_bodies):
    """Return cfg with each `source template <name>` line followed by that
    template's own commands, indented to match the block they join.

    The sourcing line is kept, not replaced, so a report's evidence still shows
    where the commands came from and nothing about the switch's config is
    hidden by the expansion."""
    def splice(match):
        indent, name = match.group(1), match.group(2)
        body = template_bodies.get(name)
        if not body:
            return match.group(0)
        return '\n'.join([match.group(0)] + [indent + line for line in body])

    return re.sub(r'^([ \t]*)source template (\S+)[ \t]*$', splice, cfg, flags=re.M)


def through_templates(check, template_bodies):
    """Wrap a check so it sees the expanded config. Applied to every check
    rather than the per-port ones alone: a template body is part of the
    switch's configuration, so no rule should be answered without it."""
    return lambda cfg: check(expand_interface_templates(cfg, template_bodies))


def describe_template_expansion(cfg, template_bodies):
    """What the expansion did, for the report header. A rule that passes only
    because of a template should be traceable to it without re-reading the
    switch."""
    lines = []
    for name, body in template_bodies.items():
        sourced = len(re.findall(rf'^[ \t]*source template {re.escape(name)}[ \t]*$', cfg, re.M))
        if body:
            lines.append(f'  {name}: {len(body)} command(s), sourced by {sourced} interface(s)')
        else:
            lines.append(f'  {name}: sourced by {sourced} interface(s), but the switch showed '
                         'no commands for it - those interfaces are audited on their config '
                         'text alone')
    if not lines:
        return ''
    return 'Interface templates read and expanded into the interfaces sourcing them:\n' + '\n'.join(lines)


def discover_root_port_interfaces(net_connect):
    """Return the set of interface names that are the STP root port in any VLAN
    instance, parsed from `show spanning-tree`. Used by V-220629 (Root Guard):
    that feature must never be pushed to a switch's own root port - it's the
    port legitimately leading toward the root bridge, and guarding it forces it
    into root-inconsistent (blocking) state, a real outage risk on live gear.
    Each VLAN block's `Root ID ... Port N (ifname)` line already gives the full
    interface name, so no abbreviation-to-full-name mapping is needed. A VLAN
    where this switch IS the root bridge has no such line and contributes
    nothing."""
    output = str(net_connect.send_command('show spanning-tree'))
    root_ports = set()
    for chunk in re.split(r'^(?=VLAN\d+)', output, flags=re.M):
        m = re.search(r'Root ID.*?Port\s+\d+\s+\((\S+)\)', chunk, re.S)
        if m:
            root_ports.add(m.group(1))
    return root_ports
