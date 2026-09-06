#!/usr/bin/env python
"""Which DISA Cisco IOS XE Switch STIG rules are the same requirement as a
Cisco IOS Switch rule this project already checks.

The two STIGs share no rule IDs at all - IOS XE runs V-220518 upward, IOS
V-220570 upward, with zero overlap - but the requirements behind them are
largely identical. This map lets l2_stig_audit.py run its existing, live-proven
predicates against an IOS XE checklist instead of reporting all 64 rules
NOT AUTOMATED purely because the numbering changed.

Every entry was accepted on the basis of the literal "... this is a finding"
condition in each rule's Check Content matching its counterpart's - the
methodology this project already applies to reading a single rule, applied to
comparing two. Titles alone are not sufficient and were actively misleading:
"must have BPDU Guard enabled on all user-facing or untrusted access switch
ports" and the same sentence for IP Source Guard differ by two words, and
matching on titles paired them with each other's rules.

A mapping is a claim that one predicate answers both rules. Where that claim
does not hold, the rule is left out and reported NOT AUTOMATED, which is an
honest verdict rather than a wrong one. See EXCLUDED below.

One pair needed the books read against each other rather than each on its own.
V-220670 (IOS XE) and V-220644 (IOS) share a title - "must not use the default
VLAN for management traffic" - but their Check Content disagrees: IOS XE tests
for a management SVI on the default VLAN, while IOS describes pruning the
default VLAN from trunk links. The IOS text is a copy-paste of its own
V-220643, byte-identical including the finding sentence, so the IOS book
carries two differently-titled rules with one check text between them. The IOS
XE book fixes it. The pair is therefore mapped: l2_stig_audit's
_no_management_on_default_vlan tests what both rules are actually for, and the
newer book is the evidence for that reading rather than an inference.

Rules the IOS XE book asks differently enough to need their own check live in
l2_stig_audit.IOS_XE_ONLY_CHECKS, not here - re-keying an IOS predicate onto
them would answer a different question. Currently V-220554 (NTP, materially
weaker than IOS V-220606), V-220567 (PKI, no IOS L2S counterpart at all) and
V-220651 (QoS: the IOS rule's evidence is a single `mls qos`, a command IOS XE
does not have, so its predicate can only ever fail there - the IOS XE rule
wants the MQC shape, which l2_stig_audit._qos_bandwidth_check reads instead).
"""

# IOS XE rule -> the IOS rule whose check answers it identically.
RULE_MAP = {
    'V-220518': 'V-220570',  # limit concurrent management sessions
    'V-220519': 'V-220571',  # audit account creation
    'V-220520': 'V-220572',  # audit account modification
    'V-220521': 'V-220573',  # audit account disabling
    'V-220522': 'V-220574',  # audit account removal
    'V-220523': 'V-220575',  # enforce approved authorizations (vty ACL)
    'V-220524': 'V-220576',  # limit three consecutive invalid logon attempts
    'V-220525': 'V-220577',  # DoD Notice and Consent Banner
    'V-220526': 'V-220578',  # audit all administrator activity
    'V-220528': 'V-220580',  # audit records establish when the event occurred
    'V-220529': 'V-220581',  # audit records establish where the event occurred
    'V-220530': 'V-220582',  # audit records contain full-text of privileged commands
    'V-220531': 'V-220583',  # protect audit information from modification
    'V-220532': 'V-220584',  # protect audit information from deletion
    'V-220533': 'V-220585',  # limit privileges to change resident software
    'V-220534': 'V-220586',  # prohibit unnecessary and nonsecure functions
    'V-220535': 'V-220587',  # single local account of last resort
    'V-220537': 'V-220589',  # minimum 15-character password length
    'V-220538': 'V-220590',  # password complexity - uppercase
    'V-220539': 'V-220591',  # password complexity - lowercase
    'V-220540': 'V-220592',  # password complexity - numeric
    'V-220541': 'V-220593',  # password complexity - special character
    'V-220542': 'V-220594',  # password change must alter at least 8 characters
    'V-220543': 'V-220595',  # store only cryptographic representations of passwords
    'V-220544': 'V-220596',  # terminate connections after inactivity (exec-timeout)
    'V-220545': 'V-220597',  # audit account enabling actions
    'V-220547': 'V-220599',  # allocate audit record storage capacity
    'V-220548': 'V-220600',  # alert on audit failure events
    'V-220549': 'V-220601',  # synchronize clock with primary/secondary time source
    'V-220552': 'V-220604',  # SNMP message authentication (FIPS HMAC)
    'V-220553': 'V-220605',  # SNMP message encryption (FIPS 140-2)
    'V-220555': 'V-220607',  # FIPS-validated HMAC for SSH
    'V-220556': 'V-220608',  # cryptographic protection of remote maintenance sessions
    'V-220559': 'V-220611',  # log records when administrator privileges are deleted
    'V-220560': 'V-220612',  # audit records for successful/unsuccessful logons
    'V-220561': 'V-220613',  # log records for privileged activities
    'V-220565': 'V-220617',  # two authentication servers for administrative access
    'V-220568': 'V-220620',  # send log data to at least two central log servers
    'V-220569': 'V-220621',  # running an IOS release currently supported by Cisco
    'V-220649': 'V-220623',  # identify/authenticate network-connected endpoints (802.1x)
    'V-220650': 'V-220624',  # authenticate VTP messages with a hash
    'V-220655': 'V-220629',  # Root Guard on ports toward access-layer switches
    'V-220656': 'V-220630',  # BPDU Guard on user-facing/untrusted access ports
    'V-220657': 'V-220631',  # STP Loop Guard
    'V-220658': 'V-220632',  # Unknown Unicast Flood Blocking
    'V-220659': 'V-220633',  # DHCP snooping on all user VLANs
    'V-220660': 'V-220634',  # IP Source Guard on user-facing/untrusted access ports
    'V-220661': 'V-220635',  # Dynamic ARP Inspection
    'V-220662': 'V-220636',  # Storm Control on host-facing switchports
    'V-220663': 'V-220637',  # IGMP or MLD Snooping on all VLANs
    'V-220664': 'V-220638',  # Rapid STP where VLANs span switches
    'V-220665': 'V-220639',  # UDLD
    'V-220666': 'V-220640',  # trunk links enabled statically
    'V-220667': 'V-220641',  # disabled ports assigned to an unused VLAN
    'V-220668': 'V-220642',  # default VLAN not assigned to host-facing ports
    'V-220669': 'V-220643',  # default VLAN pruned from trunks not carrying it
    'V-220670': 'V-220644',  # default VLAN not used for management access
    'V-220671': 'V-220645',  # user-facing ports configured as access ports
    'V-220672': 'V-220646',  # native VLAN assigned to an ID other than default
    'V-220673': 'V-220647',  # no switchports assigned to the native VLAN
}

# Deliberately not mapped, and not checked anywhere else either: the IOS rule
# with the same title has no predicate worth reusing, and no IOS XE-specific
# check can answer it from config text. These report NOT AUTOMATED, which is
# what they are.
EXCLUDED = {
    'V-220566': (
        'Configuration backup. No IOS check exists to reuse (V-220618 is '
        'NOT AUTOMATED there too - it needs an SCP target this project has no '
        'access to), and IOS XE additionally fails the rule for using an '
        'insecure transfer method, which is not derivable from config text.'
    ),
}


def translate(checks, rule_map=None):
    """Re-key IOS-keyed `checks` onto IOS XE rule IDs.

    Only mapped rules carry over. Anything absent - an unmapped rule, or one in
    EXCLUDED - simply has no entry, and run_stig_audit reports rules it has no
    check for as NOT AUTOMATED."""
    rule_map = RULE_MAP if rule_map is None else rule_map
    return {xe_id: checks[ios_id] for xe_id, ios_id in rule_map.items() if ios_id in checks}
