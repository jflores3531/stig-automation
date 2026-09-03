# Design decisions

Why this repo is structured the way it is. The [README](../README.md) covers what each script does; this covers why.

Two constraints shape most of what follows. Every check is coded against the literal text of four DISA benchmarks, so where a rule cannot be answered from a device's own config it is reported unanswered rather than guessed at. And the audit path has to run on a host where nothing can be installed, which is why the offline path exists at all and why it is the one held to the strictest requirements here.

## Core principles

**Isolated high-impact changes.** The vty management ACL and the AAA/RADIUS cutover each live in their own script rather than the bulk hardening pass, so they can be run, reviewed, and rolled back independently.

**No credentials on disk or in argv.** Username and password are prompted at runtime via `getpass`. Device-level secrets (VTP, SNMPv3, RADIUS key, enable secret) load from a gitignored `secrets.yaml` — never CLI flags, where they'd land in shell history.

**No hardcoded device data.** Every IP, VLAN ID, and server address lives in `inventory.yaml`. The scripts carry STIG logic only.

**Live-tested, not just written.** Nearly every commit reflects a real push against lab hardware. Behavior that only works in theory is labeled as such.

**Coded against the literal STIG text.** Every rule check maps to the benchmark's Check Text, every fix to its Fix Text. Rules needing external infrastructure or topology judgment report NOT AUTOMATED rather than guessing — a false pass on a compliance tool is worse than no answer.

## Nothing gets installed

The switches this is aimed at are reachable only from a host where pip is not an option — no path to PyPI and no rights to install with. That constrains the offline path to the standard library, and three things follow from it.

`inventory.yaml` holds JSON rather than YAML. JSON is a subset of YAML 1.2, so one file parses under real PyYAML where it exists and under `yaml.py` — a stand-in whose `safe_load` is the stdlib `json.load` — where it does not. Vendoring PyYAML into the repo would also have worked, and was rejected: several thousand lines of someone else's code to review and keep current, for one function call, in a repo whose whole claim is that it can be read before it is trusted.

The cost is that `yaml.py` shadows an installed PyYAML for anything run from the repo root. That is harmless while the inventory stays JSON, since that parses either way, but a YAML-formatted inventory on a machine that has PyYAML fails with a `JSONDecodeError` naming the parser rather than the format — which reads like broken tooling instead of a file in the wrong dialect.

Netmiko is imported inside `netauto.connect()` rather than at module scope, so nothing on the audit path loads it. `--from-capture` and the SecureCRT collectors run on Python alone, and the collectors import nothing from this repository at all — they are copied onto the host as single files.

## Saving is a separate, deliberate step

No harden script writes to startup-config. `save_config.py` does that, and only when you run it.

The reason is that an unsaved config is recoverable. If a push locks the automation host out, reloading the device brings it back on the last saved configuration — no console needed. Saving automatically at the end of every push would trade that away: a lockout would survive the reload, and console access would become the only way back. On a device like a router reachable through one path, that is the difference between a two-minute recovery and a trip to the console.

The failure in the other direction is real but cheap. NXCore1 reloaded once with a session's worth of AAA, management-ACL and Root Guard configuration unsaved, and lost all of it — a 14-rule regression that looked like broken code and wasn't. Re-running the harden scripts restored it in minutes.

So the order is: **push → audit → confirm → save.** On NX-OS this matters twice over, since `nxos_stig_harden_global.py` stages TCAM regions for IPSG/DAI that only take effect after a reload — saving first is what makes them survive it.

## Run order

`l2_stig_harden_global.py` runs **first**. It establishes DHCP snooping and puts ports into access mode, which the other `l2_stig_harden_*.py` scripts depend on.

`l2_stig_harden_aaa.py` runs **last**. The password policy commands (V-220590-594) need `aaa new-model` already active, so they can't be folded into the bulk pass. The enable secret is pushed and confirmed working before any AAA command is sent, since the rest of the script depends on it.

`netauto.py`'s `connect()` escalates to privileged EXEC automatically using `secrets.yaml`'s `enable_secret` if one is set — a no-op if the session is already privileged. This became necessary once `aaa new-model` governs login on a device.

## Why specific scripts are split out

### `l2_stig_harden_acl.py` — vty management ACL (V-220575)
An `access-class` that excludes the automation host's own source IP blocks every future SSH connection from it, so this runs as its own script rather than inside the bulk pass. The ACL is created first, separate from applying it — an `ip access-list` has no effect until something references it — and connectivity is confirmed after it's applied, reverting automatically if that check fails.

The ACL's trailing deny carries `log-input` (V-220581, partial). It covers rejected vty access attempts only, not general traffic, and only reaches `show logging` locally, since `logging trap critical` sits above the informational severity ACL logging uses.

### `l2_stig_harden_ipsg.py` — IP Source Guard (V-220634)
IPSG only trusts the DHCP snooping binding table, so a statically-addressed host with no DHCP lease gets its traffic dropped. Kept isolated so it can be pushed or pulled independently while that gap is unresolved.

### `l2_stig_harden_dai.py` — Dynamic ARP Inspection (V-220635)
Split out for the same reason as IPSG: DAI also only trusts the DHCP snooping binding table, so a statically-addressed host can have its ARP traffic dropped once this is pushed.

The tracked fix for both is to diff `show ip device tracking all` against `show ip dhcp snooping binding` and build entries dynamically — currently blocked on IP Device Tracking not activating on this lab's `vios_l2` image.

### `ios_router_stig_harden_urpf.py` — Unicast RPF (V-216989)
uRPF is applied only to external-facing interfaces, using the interface classification in `inventory.yaml` — applying it to internal interfaces in a lab with asymmetric paths drops legitimate traffic.

It is pushed with `allow-default`. Strict-mode uRPF validates a packet's source against the routing table and discards anything with no matching route; without `allow-default`, sources reachable only via the default route fail that check and every packet from them is dropped. On a lab router whose return path to the automation host is the default route, that includes the management traffic itself.

Unlike an `access-class`, uRPF filters **per packet** rather than at connection admission, so an already-established session is not exempt from it. That makes it categorically different from the ACL and AAA scripts: their pattern of applying a change and then checking connectivity does not apply here, because a bad push drops the packets carrying the correction. This one is verified against `inventory.yaml`'s classification before the push, not after.

### `securecrt/capture_l2s_bulk.py` — unattended collection across a fleet
`capture_l2s.py` cannot connect to anything. It attaches to the SecureCRT session already in front of it, which makes it impossible to aim at the wrong device and impossible to run without a human having logged in first. That property is most of its security argument.

The bulk collector gives it up: it opens its own session to each saved SecureCRT session in turn, on credentials SecureCRT already holds. That is a materially different thing to put in front of whoever approved the audit tooling, and it deserves its own approval rather than riding along on `capture_l2s.py`'s — which is why it is a second file and not a `--all` flag on the first.

It never aborts. A switch that is offline, in a login quiet period, or refusing credentials is logged and skipped: across several hundred switches not all of them answer on a given night, and a collector that stops at the first problem would never finish one.

Auditing stays outside the loop. Running it per switch inside the collector would start a Python subprocess per device and, worse, make a failed audit indistinguishable from a failed capture in the log. Collection and audit are separate passes for that reason.

Both files are copied together: the bulk script imports the guards, the command list and the capture format from `capture_l2s.py` rather than restating them, so the two cannot drift.

### Trunk ports and DHCP snooping
`l2_stig_harden_global.py` sets both `ip dhcp snooping trust` and `ip arp inspection trust` on trunk ports. DHCP snooping bindings are learned per-switch only, so trunk and uplink ports carrying transit traffic from other switches need both trusted — otherwise DAI drops that traffic against this switch's own incomplete binding table.

## Lab hardware limitations

A handful of STIG-required commands are confirmed to not exist or function on this project's `vios_l2` lab image:

- UUFB (`switchport block unicast`) — V-220632
- Storm control — V-220636
- `mls qos` — V-220625
- `security passwords min-length`
- `file privilege 15`
- 802.1x authenticator role
- Classic `radius-server host` syntax
- SISF `device-tracking policy`
- `no ip dns server`, `no ip identd`, `no service call-home` (V-220586 still passes — the services aren't running to begin with)

### V-220607 (SSH HMAC) — a permanent finding, not a missing push

This one is a partial rather than a missing command. `ip ssh server algorithm mac hmac-sha2-256` is rejected at the *algorithm*, not the command — the caret lands under `hmac-sha2-256` — and `ip ssh server algorithm mac ?` confirms the image offers only:

```
hmac-sha1     HMAC-SHA1 (digest length = key length = 160 bits)
hmac-sha1-96  HMAC-SHA1-96 (digest length = 96 bits, key length = 160 bits)
```

SHA-1 is deliberately not pushed and not accepted as a PASS. The rule's own Check Content concedes SHA-1 is FIPS-validated ("allowed by NIST SP 800-131A Rev. 2 for some applications") — so a strict reading of the finding sentence would let `hmac-sha1` through — but the same paragraph states DOD systems "should not be configured to use SHA-1 for integrity of remote access sessions." Taking the PASS would mean reporting compliance on the exact configuration DISA calls out.

So no value this image supports can satisfy the rule, and V-220607 is a permanent finding here, in the same category as V-220606's NTP MD5. The audit says so in its FAIL reason rather than reporting a bare "missing" that reads like an unpushed fix. Pushing `hmac-sha1` would also restrict nothing in practice: with no `algorithm mac` line, IOS already permits both SHA-1 variants by default.

The matching encryption line (V-220608) is accepted, which is why the two rules split.

The scripts still push all of these unconditionally, since they're correct for real Cisco hardware.

## Mapping one STIG onto another

The Cisco IOS Switch and IOS XE Switch L2S/NDM STIGs cover largely the same requirements and share **no rule IDs at all** — IOS XE runs `V-220518` upward, IOS `V-220570` upward, with zero overlap. Auditing an IOS XE switch against the IOS checklist therefore doesn't produce wrong verdicts; it produces 64 rules of `NOT AUTOMATED`, which is worse in a specific way — it looks like broken tooling rather than a wrong argument.

`ios_xe_rule_map.py` maps the two so the same checks serve both. Getting that right needed three separate comparisons, and **each caught a class of error the others structurally could not.**

### Rule titles are not evidence

The first attempt matched on rule title and paired IOS XE's BPDU Guard rule with IOS's **IP Source Guard** rule. Both titles read "must have X enabled on all user-facing or untrusted access switch ports" and differ by two words. That table would have passed review and reported IP Source Guard's verdict under BPDU Guard's ID.

### Check Content answers "is this the same requirement?"

Pairs are accepted only where the literal `... this is a finding` condition matches in both books — the same rule this project already applies when reading a single rule, applied to comparing two. The gate is asserted in `tests/test_ios_xe_map.py`, so a future mapping that drifts fails the suite rather than shipping.

Two rules illustrate why the finding sentence, not the title, has to govern:

- **NTP authentication.** IOS (`V-220606`) requires "authentication with FIPS-compliant algorithms", which IOS cannot provide — it is a permanent finding by DISA's own text. IOS XE (`V-220554`) requires only authentication "that is cryptographically based", and MD5 is a cryptographic hash: weak, not FIPS-approved, and squarely inside what that sentence asks. Same title, opposite verdicts. Inheriting the IOS check would have reported a permanent FAIL against a rule the platform passes — a false FAIL, the mirror image of the false PASS this project usually guards against.
- **Excess bandwidth / QoS.** The finding sentences agree, the remediation does not: IOS wants `mls qos`, IOS XE wants full MQC. IOS XE's rule is left `NOT AUTOMATED` rather than answered by a check that could never pass there.

### Fix Text answers a different question: "does the same syntax satisfy it?"

Two pairs agreed on the requirement and disagreed on the commands. Both would have reported a finding against a switch configured **exactly per DISA's own IOS XE instructions**:

- **Management ACL** (`V-220523`) — IOS XE builds a *standard* ACL (`ip access-list standard` / `permit x.x.x.0 0.0.0.255`); IOS builds an extended one. The check matched only `ip access-list extended`, and parsed only `permit ip <source> any` — syntax a standard ACL never writes, having no protocol or destination to name. It now branches on ACL kind, including the trailing deny (`deny any log` vs `deny ip any any log-input`), and supports numbered ACLs, which neither book's example uses but real switches do.
- **RADIUS redundancy** (`V-220565`) — IOS XE points the method list at a named group (`aaa group server radius <name>`); the check required the literal word `radius`. It now accepts either, but a named group counts only when actually defined, so an arbitrary word cannot pass for one.

Two further Fix Text differences were checked and needed no code: `V-220552` carries extra `snmp-server view` lines the audit never reads (it uses live `show snmp user`), and `V-220556`'s apparent difference is a typo in the IOS XE document itself — `iip ssh server algorithm encryption`.

### Audits are more exposed to this than harden scripts

The same comparison run against the harden scripts found **one** divergence in 16 global fixes, and none at all in the per-interface commands — UUFB, storm control, IP Source Guard, DAI, DHCP snooping and 802.1x RADIUS all match the IOS XE Fix Text verbatim, including the modern `radius server <name>` / `address ipv4` form this project already used because `vios_l2` rejected the classic one.

That asymmetry is structural rather than luck. An audit must **recognise** whatever syntax a device happens to carry; a harden only has to **emit** one valid form, and where both books accept the same command, emitting it works everywhere. Recognition is the harder problem, so that is where the bugs are — worth knowing before porting this to a third platform.

The same asymmetry produced a second class of false FAIL that has nothing to do with syntax: **recognising which ports a rule governs.** Every per-access-port rule reads its port list from `parse_switchports()`, which classified interfaces by name. Two Layer 3 interfaces have switchport-shaped names — a routed port (`no switchport`) and a Catalyst's out-of-band management port, `GigabitEthernet0/0` in `Mgmt-vrf`, which is not switchport-capable hardware at all — and both landed in the access bucket, drawing a finding from BPDU Guard, UUFB, IP Source Guard, storm control, 802.1x, the access-VLAN rule and the explicit-mode rule at once. None of those commands can be applied to either port.

Excluding by name is not available: the lab's `vios_l2` image carries a genuine switchport called `GigabitEthernet0/0`, and one audit serves both platforms. The interface block's own contents decide it instead — `no switchport`, or an `ip address`/`vrf forwarding` with no switchport line anywhere — and anything ambiguous stays a switchport, so the error falls on the strict side. `tests/test_switchports.py` asserts both directions, including that the lab's `GigabitEthernet0/0` is still audited.

### Where DISA's own text is wrong

`V-220670` (IOS XE) and `V-220644` (IOS) share the title "must not use the default VLAN for management traffic" but their Check Content disagrees: IOS XE tests for a management SVI on the default VLAN, IOS describes pruning the default VLAN from trunk links. The IOS text is a byte-identical copy of its own `V-220643`, finding sentence included — so the IOS book ships two differently-titled rules with one check text between them, and the newer IOS XE book fixes it.

The pair is mapped anyway, and the audit tests the management SVI on both. This is a rare case of implementing a rule's evident intent over its literal Check Content, and it is only defensible because the correction comes from DISA's own later publication rather than from inference. The exception is named in `tests/test_ios_xe_map.py` with its reasoning, and the test asserts both that the exception is still needed and that the two IOS rules still share their text — so if DISA ever corrects the IOS book, the suite says the exception can go.

SNMPv3 auth/priv (V-220604/605) is config-only — there's no NMS in this lab to actually poll it.

## Captures arrive in whatever encoding saved them

The work switches are reachable only through PowerShell or SecureCRT, and both of PowerShell's obvious ways to save output add a byte order mark: `>` and `Out-File` default to UTF-16LE on Windows PowerShell 5.1, and `Out-File -Encoding utf8` writes UTF-8 with a BOM. Read as plain UTF-8, neither failed in a way that named its cause — a UTF-8 BOM glues itself to the first delimiter line, so only `show running-config` goes missing, and UTF-16 decodes to NUL-riddled text matching nothing at all. Both refusals are correct and neither is actionable, which on someone else's network costs a second trip to the switch. `capture.py` sniffs the BOM instead, and a UTF-16 file with the BOM stripped — the one case that cannot be sniffed — names the encoding in its error.

## When empty output is the answer

A capture is refused if any command came back with nothing: a command that returned nothing and a feature that is switched off look identical, and a check handed empty text reports a verdict as confidently as one handed real config.

`show snmp user` is the exception. It prints nothing at all when no SNMPv3 users are defined — a legal switch state, and a non-compliant one that V-220604/605 exist to catch. Refusing the capture there abandons the entire collection over the very finding it was sent to collect, and it fails at collection time, before there is a report to explain it. The section must still be present, so a command that was never run is still caught; it is only allowed to be empty. `_snmpv3_user_live_check` reads empty output as "no SNMPv3 user with an authentication protocol found" and FAILs, which is the right verdict. The exemption list is duplicated in `securecrt/capture_l2s.py` (standalone by design) and `tests/test_securecrt_script.py` asserts the two cannot drift.
