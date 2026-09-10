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

The cost is that `yaml.py` shadows an installed PyYAML for anything run from `scripts/`, where it sits beside the modules that import it. That is harmless while the inventory stays JSON, since that parses either way, but a YAML-formatted inventory on a machine that has PyYAML fails with a `JSONDecodeError` naming the parser rather than the format — which reads like broken tooling instead of a file in the wrong dialect.

Netmiko is imported inside `netauto.connect()` rather than at module scope, so nothing on the audit path loads it. `--from-capture` and the SecureCRT collectors run on Python alone, and the collectors import nothing from this repository at all — they are copied onto the host as single files.

## Saving is a separate, deliberate step

No harden script writes to startup-config. `save_config.py` does that, and only when you run it.

The reason is that an unsaved config is recoverable. If a push locks the automation host out, reloading the device brings it back on the last saved configuration — no console needed. Saving automatically at the end of every push would trade that away: a lockout would survive the reload, and console access would become the only way back. On a device like a router reachable through one path, that is the difference between a two-minute recovery and a trip to the console.

The failure in the other direction is real but cheap. NXCore1 reloaded once with a session's worth of AAA, management-ACL and Root Guard configuration unsaved, and lost all of it — a 14-rule regression that looked like broken code and wasn't. Re-running the harden scripts restored it in minutes.

So the order is: **push → audit → confirm → save.** On NX-OS this matters twice over, since `nxos_stig_harden_global.py` stages TCAM regions for IPSG/DAI that only take effect after a reload — saving first is what makes them survive it.

## Run order

`l2_stig_harden_global.py` runs **first**. It establishes DHCP snooping and puts ports into access mode, which the other `l2_stig_harden_*.py` scripts depend on.

`l2_stig_harden_access_ports.py` and `l2_stig_harden_trunk_ports.py` are two runs, not one, and the trunk one wants its own change window. See below.

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

### `securecrt/harden_l2s_bulk.py` — the one script in `securecrt/` that configures
Every other file in that folder is read-only and says so in its docstring. This one writes to running-config on a whole fleet, so it is a separate file with a separate name rather than a flag, for the same reason `capture_l2s_bulk.py` is separate from `capture_l2s.py`: the approval it needs is not the approval the read-only walks got.

It exists because `scripts/l2_stig_harden_logging_access.py` cannot run where these switches are reachable from. That script needs netmiko, netmiko cannot be installed on that machine, and that single fact is why `securecrt/` exists at all. Same fixes, same order, different transport.

The command lists are duplicated rather than imported, because nothing in `securecrt/` may import from the wider repository — the folder is copied to a machine that does not have the repository on it. Duplicated constants drift, and drift here would mean two tools that both claim to apply the same STIG fixes and quietly do not, so `tests/test_securecrt_harden.py` executes the netmiko script's constant section and asserts the two copies are equal.

**It never writes startup-config.** That is the escape hatch and it is deliberate: until someone runs `copy running-config startup-config`, a reload puts every switch back exactly as it was. Harden, re-audit, then save — the same order the rest of the repo runs in, and here the reason is that the audit is the only thing that can tell you the push landed as intended on an image nobody tested it against.

**The vty block is opt-in and its range is read, not assumed.** Everything else this pushes is reversible from any session that can still reach the switch. The vty lines decide how many sessions there can be, which makes a mistake in them the one mistake that takes away the means of fixing itself — so the run asks, defaulting to No. When it is included, the highest line comes off the switch. What caps inbound management sessions is how many vty lines will answer, so the organization-defined 5 means vty 0-4 answer and everything above them does not. IOS XE ships `line vty 0 4` *and* `line vty 5 15`, and configuring only the first leaves eleven lines answering while the run log records a five-session limit. A switch whose range could not be read has the block **skipped and flagged for a human**, not applied against a fallback — writing a fix whose reach is a guess and a row that reads as complete is the false PASS this repo treats as worse than a false FAIL, moved one step upstream into the remediation record.

**The syslog collectors are asked for, and only in pairs.** The netmiko script reads them from `inventory.yaml`, which nothing here can. Fewer than two, or anything that is not an IPv4 address, stops the run before a single switch is touched rather than dropping the entry quietly: a typo that silently costs a collector leaves V-220568/220620 a finding across the whole fleet, on a run whose log says it hardened them.

Nothing that changes forwarding is in it. No spanning-tree mode, no VLAN database, no `no <service>` lines, nothing per-interface — so it needs no change window for convergence behaviour, which is what makes an unattended fleet-wide push defensible in the first place.

### `l2_stig_harden_access_ports.py` / `l2_stig_harden_trunk_ports.py` — one file split by blast radius
These were one script, `l2_stig_harden_interfaces.py`. The two halves shared a `show running-config` and a port classifier and nothing else — different rules, different commands, and, the reason they are now separate files, completely different consequences for being wrong.

An access port serves one endpoint. A bad push there costs one desk, and the session that made the mistake is still up to fix it. That half can go out on a working day.

A trunk port is the uplink, and the session pushing to it is usually riding it. Two of its fixes decide whether it keeps forwarding: `switchport trunk allowed vlan <list>` replaces the allowed list outright, so a management VLAN not in the discovered list is pruned off the uplink the moment it lands; `switchport trunk native vlan <id>` changes what untagged frames land in at both ends, and a neighbour still on the old native VLAN is a mismatch. Root Guard is a third, and is the one already handled rather than warned about — V-220629 on this switch's own root port forces it into root-inconsistent/blocking and takes out the path to the root bridge, so the root port is discovered live and excluded.

Keeping them in one script meant every access-port fix inherited the trunk half's change window. Splitting them costs a second connection when you run both, and buys the ability to run the safe half whenever you like — the same trade `l2_stig_harden_acl.py`, `_ipsg.py` and `_dai.py` already make.

The port classifier moved to `stig_common.py` in the process, which fixed something separate. The harden side had its own copy that classified by interface name alone, while the audit's excluded Layer 3 interfaces by block contents. That divergence was a false FAIL on the audit side and worse on the hardening side: `switchport mode access` sent to a routed port converts it and takes its address with it. One classifier now answers both, so a port the audit judges as access and a port the hardening configures as access are the same port.

### A port's real configuration may not be in its own block
`l2_stig_audit.py` has expanded `source template <name>` since interface templates showed up in the fleet, because a port audited on its own three-line block draws findings against configuration nobody read. The harden scripts did not, and the consequence there is worse than a wrong verdict.

A port whose block is only `source template UPLINK` carries no `switchport mode trunk` line. Classified off the raw config it lands in the access bucket, and the access pass sends it `switchport mode access` and `spanning-tree portfast` — collapsing the uplink, and putting PortFast on a port that receives BPDUs as a matter of course, which is the exact condition BPDU Guard exists to shut down. The trunk pass has the quieter mirror of the same bug: it skips that uplink and reports a clean run on a switch whose trunks were never touched.

Both now read the templates off the switch (`stig_common.read_interface_templates`, one `show template interface source user <name>` per distinct template, nothing at all for a switch that uses none) and splice them in before classifying. `tests/test_harden_port_classification.py` pins it, including the raw-config behaviour it corrects, so the bug cannot come back unnoticed.

The Ansible role still classifies with regex against the raw running-config and has not been fixed. It carries a warning at the top of its interface tasks saying so.

### The default access VLAN is assigned deliberately, not in bulk
V-220642 (host-facing ports off the default VLAN) is no longer pushed by anything. A port's access VLAN says what the thing plugged into it can reach, and moving a port needs the new VLAN to be right for that device — an SVI, a DHCP scope, a route out. Bulk-assigning it moved the lab's own management port and cut the session pushing the change (2026-08-28), and the guard added afterwards — skip ports that already carry an explicit VLAN — could not see a VLAN that came from a template.

Template expansion fixes that reading, but not the underlying point: a port genuinely still on VLAN 1 is a port with something live on it. The rule is printed as a deliberate unpushed finding on every run, and the audit reports it as a finding, which is the honest outcome.

V-220641 (disabled ports on an unused VLAN) is a different case and **is** pushed. A shut port forwards nothing whatever VLAN it is on, so it is the one access-VLAN assignment that does not depend on knowing what is plugged in — there is nothing plugged in that is working. It lands on shut ports only, and `shutdown` is read from the expanded config, since a port can be shut by the template it sources as easily as by its own block. Where the shut port is templated, the explicit VLAN line overrides its template and outlives the shutdown, so the run names those ports rather than doing it quietly.

V-220642 also came out of the access script's `SIDE_EFFECT_RULES`, where it had been listed as satisfied by the access-VLAN push. Leaving it there would have been the script's own output claiming a pass it no longer earns.

### 802.1x is a deployment, not a line in a bulk pass
V-220623 was pushed per-port by the interface script, skipping access ports on non-user VLANs. That skip was added after `authentication port-control auto` landed on the lab's own management port and blocked the supplicant-less host mid-push (2026-08-28) — and it was the wrong shape of fix. What locked out that one port locks out every port on a switch with no 802.1x infrastructure behind it: with no RADIUS authenticator reachable and no supplicant on the endpoint, a port set to `port-control auto` authenticates nobody and forwards nothing. On an access switch full of user devices that is not a lockout of the automation host, it is a lockout of the floor.

Nothing per-port pushes any part of it now, in the Python or the Ansible role. The rule is reported as a deliberate unpushed finding on every run rather than half-applied, and the audit's check is unchanged and still reports it. `l2_stig_harden_aaa.py` still pushes the global prerequisites, which are inert on their own: with no port set to authenticate, nothing authenticates against them.

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
- **Excess bandwidth / QoS.** The finding sentences agree, the remediation does not: IOS wants `mls qos`, IOS XE wants full MQC. `mls qos` does not exist on IOS XE, so the IOS predicate could only ever FAIL there however compliant the switch is. The pair is not mapped; IOS XE gets its own MQC check instead — see "Rules that stopped needing a login" below.

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

## Configuration that running-config does not show

An audit reads `show running-config` and treats it as the device's configuration. On the work fleet that assumption is false: user ports are configured from an **interface template**, so the port's block carries one line — `source template USER_PORT` — and the access VLAN, switchport mode, PortFast, BPDU Guard and 802.1x it stands for appear nowhere in the config text. Read against config alone those ports look bare, and four rules reported a finding against ports that are configured correctly (`V-220649`, `V-220656`, `V-220668`, `V-220671`, checked by hand against the running-config that produced them).

`show template interface source user <name>` shows the body — one command per template rather than one per interface, which matters on a switch with 48 templated ports. Its commands are spliced into every block that sources them before any check runs, so no check needs a notion of templates: they see the port's effective configuration, which is what the STIG asks about. The `source template` line is kept rather than replaced, so a report's evidence still shows where the commands came from.

Two consequences worth naming:

- **Which commands a capture must carry is now a function of the config it carries.** The template names are only knowable from running-config, so `capture.load_l2s()` loads twice: once for the fixed commands, then again demanding a section per template the config sources. A capture that sources templates it does not carry is refused, by the same rule that refuses one missing `show vtp password` — the alternative is a report full of findings against interfaces whose configuration was never read, and those verdicts read exactly like real ones. `securecrt/capture_l2s.py` collects the same second pass, so captures taken the normal way already carry it.
- **Expansion must not become a pass.** Splicing commands into a block could just as easily hide a genuine gap, which is the failure this project exists to avoid, so `tests/test_interface_templates.py` pins both directions: a templated port draws no findings for what its template configures, and a template missing BPDU Guard still produces the BPDU Guard finding against every port sourcing it.

The same reading of a real report against the switch that produced it found two more false FAILs of the recognition kind, both fixed with `tests/test_false_fails.py` pinning them:

- `V-220650` (VTP): `show vtp password` has three wordings, and the one the fleet answers with — `VTP Password is configured`, set but not disclosed — matched neither the `VTP Password: <value>` form nor the "not set" form, so it fell through to "unexpected output" and FAILed a switch that has a VTP password.
- `V-220523` (management ACL): the check read only `permit ip <source> any`, the shape DISA's own fix text builds. An ACL written to let the management network reach SSH and nothing else says `permit tcp <source> <wildcard> any eq 22 log` — *narrower* than what the rule asks for — and was read as an ACL with no permit entries at all. Any protocol is accepted now; the rule is about the source, and that is still checked against `management_subnet`. A source that cannot be resolved from config text at all (`object-group MGMT`) is reported as needing review by hand rather than as a source outside the subnet, which would be a claim the audit cannot support.

## A rule's evidence is not always in running-config

V-220555 and V-220556 both print `ip ssh version 2` in their Check Content, and a Catalyst 9300 or 3850 never writes that line. SSHv1 is gone on those trains, so v2-only is not a non-default setting and IOS XE renders nothing for it; `show ip ssh` reports `SSH Enabled - version 2.0` instead. Grepping the config for the line failed both rules on a switch doing exactly what they ask — a false FAIL across a fleet of 9300s, and the recognition-side mirror of the Fix Text false FAILs this project already fixed.

Neither rule's finding sentence asks for the line. They ask whether the session is protected with FIPS-validated HMAC and a FIPS-approved cipher. So `_sshv2_evidence` accepts either source and the report says which one it used.

`show ip ssh` is consulted **first** and settles it on its own wherever it answers. running-config is a statement of intent; `show ip ssh` is what the switch is actually running, and where the two disagree the running switch is the one an assessor cares about. Ordered the other way round, a stale or ineffective `ip ssh version 2` line outvoted live output saying the switch was still answering SSHv1 — a false PASS reachable from a real config, and the reason the fallback is a fallback rather than the first test.

Two readings are refused, because getting them wrong is worse than the false FAIL. `SSH Enabled - version 1.99` is IOS reporting compatibility mode, where the switch still answers SSHv1; counting it as v2 would be a false PASS on a switch that accepts the very protocol the rule exists to eliminate. `SSH Disabled` is refused for the obvious reason.

`show ip ssh` joins `OPTIONAL_COMMANDS_L2S` rather than the required list. That tuple's usual rule is that a missing optional command costs an empty field in the asset block, never a verdict — and this one does feed a verdict, which is worth being explicit about. Absence here does not answer a rule against empty output; it falls back to the running-config line, which is exactly what the check did before the command was collected. No capture taken before this existed is refused, and no verdict is reached on nothing.

## Rules that stopped needing a login

`NOT AUTOMATED` is an honest verdict, but it is also a task: someone has to go to the switch and answer the rule by hand. Reading one real IOS XE report line by line against the switch that produced it showed that four of them were answerable already — three from config text the audit had in front of it, one from a command it was one line away from running. What each of them actually needed was a closer reading of the Check Content.

- **Persistent logging (`V-220531/532/533`)** reported `PASS` with a reason that read "not applicable". Both are non-findings, so nothing was wrong with the verdict arithmetic — but on a checklist they are different sentences, and `NOT_A_FINDING` claims the switch protects persistent log files it does not keep. They report `NOT APPLICABLE` now, which is what the rule's own Step 1 says ("Otherwise, this requirement is not applicable") and what transcribes correctly into a `.cklb`. The same rules also failed a compliant switch: DISA's Note says the default file-system privilege *is* 15 and that `file privilege 15` therefore never appears in the config, while the finding condition is a privilege level **other** than 15. Requiring the line to be present failed every switch that had never been told to lower it.

- **PKI (`V-220567`)** reported `NOT AUTOMATED` on every switch, because every switch has a trustpoint. What they carry is `TP-self-signed-<serial>`, which IOS XE generates by itself the first time its HTTPS server starts. The rule asks for the CA the switch **enrolled** with, and a self-signed trustpoint enrolled with nothing — confirmed on a live switch with `show running-config | include enrollment url`, which printed nothing, and `show crypto pki trustpoints`. So the enrollment method decides the rule, and it is in the config: `enrollment url` or `enrollment terminal` means a CA whose issuer still needs a CN/O/OU review (`NOT AUTOMATED`, now with the URL printed so the lookup does not need a login either), `enrollment selfsigned` or no enrollment at all means there is no certificate from a provider to review (`NOT APPLICABLE`). Any enrollment form this has not seen counts as a CA, so an unknown case costs a manual look rather than hiding a finding.

- **Supported release (`V-220569`/`V-220621`)** needs `show version`, which is one more command on a session the audit already opens — so it is collected with the VTP password and the SNMPv3 users, and captures carry it. On IOS XE the answer is then in the numbering rather than in a lookup. Cisco ships two tracks in the 16.x and 17.x trains: Extended Maintenance releases every third minor (17.3, 17.6, 17.9, 17.12, 17.15) with 36–48 months of support and scheduled rebuilds, and Standard Maintenance releases between them (17.10, 17.11, 17.13, 17.14) with twelve months and no extension. So an SMR is a finding — within a year there are no more fixes for it and no configuration changes that — and an EMR passes, both decided by arithmetic on the release number. That replaced a hand-maintained list of releases someone had read off cisco.com, which needed a staleness date and a warning about trusting it, and which reported `NOT AUTOMATED` for every release nobody had got round to adding. Two things it deliberately does not claim: that an EMR is *currently* supported (17.3 is an EMR whose window has closed, so the reason line names the train and leaves that visible), and anything at all about classic IOS, which has no EMR/SMR split and still reports `NOT AUTOMATED` with the release printed. Hardware is separate and still a table: a `WS-C3850` past its last date of support fails whatever it runs, with the date given rather than asserted — and the model it is matched against comes from the switch table's row for the member marked active, not from the first `Model Number :` line. Those differ on a mixed stack, where `Model Number` is printed once per member in member order while the banner gives the active member's release: reading one from each names one switch's hardware beside another switch's software, and since the model decides this table, that is a wrong verdict rather than a wrong label. The banner and `Model Number` remain the fallback for everything that prints no switch table — classic IOS, the lab's vios_l2 image, routers.

- **Excess bandwidth / QoS (`V-220651`)** was excluded from the rule map because the IOS book's evidence is a single `mls qos`, a command IOS XE does not have. The IOS XE book asks for the MQC shape instead — DSCP class-maps, a policy-map reserving bandwidth per class, and `service-policy output` on the switchports — and all three are config text, since `show class-map` and `show policy-map` print the configuration back. The check matches on **DSCP value, not class-map name**: the finding sentence is only "If quality of service (QoS) has not been enabled, this is a finding", so a switch that reserves the same bandwidth under a local naming scheme has enabled QoS and must not be failed for spelling. The STIG's own traffic types (`C2_VOICE`/47, `VOICE`/ef, `VIDEO`/af41, `PREFERRED_DATA`/af33, `class-default`) are still reported by name, and any the policy does not cover is said out loud on the `PASS` — visible to whoever transcribes the checklist, without inventing a finding DISA did not write. Coverage is reported the same way, and for the same reason. A policy on some switchports and not others does leave the rest exactly as floodable as before, and the rule's own Fix Text applies the service-policy to every port in its example — that argument is real, but it is not the rule's. The finding condition is one sentence, and a switch running a valid policy on some of its ports has enabled QoS, so the uncovered ports are named on the `PASS` rather than failed. Failing them would invent a finding DISA did not write, which is the same mistake as failing a policy for its class-map spelling.

- **Configuration backup on change (`V-220566`)** sat in the excluded list on the strength of the IOS book's version of the rule, whose evidence is an SCP server held by the site's administrators rather than by the switch — nothing on the device discovers it. The IOS XE book asks about the **mechanism** instead, and names it outright: an EEM applet triggering on `%SYS-5-CONFIG_I`, an action copying the running configuration to a secure destination, `authorization bypass` inside the applet, and a global `file prompt quiet`. All four are running-config text. Its finding sentence names two conditions and only two — no automated backup when changes occur, or one taken "using an insecure method like a cleartext password" — so those `FAIL`, with an insecure transport or a password in the destination read as the second (the Check Content's own note is that *absence* of a password indicates key authentication). The other two are what make the applet run rather than findings DISA wrote, so a switch missing them passes with them named in the reason, the same treatment QoS gives an uncovered traffic type.

With that one automated, **every rule in the IOS XE checklist returns a real verdict except `V-220671`** — see below — and that one answers itself once the site declares what only the site knows. `ios_xe_rule_map.EXCLUDED` is consequently empty, and kept rather than deleted: it is where a rule goes when the IOS predicate would answer the wrong question.

- **User-facing ports as access ports (`V-220645` / `V-220671`, identical text in both books)** was answered by a check that asks whether every port carries an explicit `switchport mode`. That catches a port left negotiable — a real DTP risk, and the rule's spirit — but it never fails an explicit trunk, which is the rule's letter: *"If any of the user-facing switch ports are configured as a trunk, this is a finding."* A switch with a user-facing port configured `switchport mode trunk` passed it. Not a wrong answer so much as a confident answer to a different question, which is the failure mode this project is built around.

  The obstacle is that **"user-facing" is not in the configuration**, and no amount of parsing invents it. Two facts about the site are, if the site declares them: `core_switch_hostname_tags` (substrings marking a hostname as core or distribution — those switches have no user-facing ports, so the rule's population is empty and the verdict is `NOT APPLICABLE`) and `uplink_port_description_keywords` (substrings marking a description as facing another switch, an AP or a phone — matched case-insensitively, so a fleet writing `Downlink`, `DOWNLINK` and `downlink` in three closets means one thing by all three). A trunk described that way is not a user-facing trunk. The shipped list carries `UPLINK`, `DOWNLINK`, `TO-CORE` and `TO-DIST`, because an access switch trunks up to its distribution switch and often down to another access switch in the same area, and both are switch-to-switch links.

  What it deliberately will **not** do is fail an unlabelled trunk. Every access switch needs at least one — its uplink — so failing trunks outright would fail a whole fleet for being wired correctly. An unlabelled trunk is a port whose far end this cannot see, so it is reported `NOT AUTOMATED` naming the ports, rather than a `PASS` that quietly asserts they are fine. Ports left with no explicit `switchport mode` go into the same bucket: not `switchport mode trunk`, but a trunk the moment something asks.

`tests/test_manual_review_rules.py` pins all six, in both directions — the newly automated verdicts, and the cases that must still report `NOT AUTOMATED` rather than a guess.

## Each verdict says what was read to reach it

Every answered rule now carries one more line, in the report and in the exported checklist's box:

```
Inspected with: `show ip ssh`, `show running-config`
```

The reason says why the rule got its verdict; this says where that came from. For most rules the answer is `show running-config` and reading it costs nothing. For the ones it is not — `show snmp user` for the SNMPv3 rules, `show vtp password` for VTP, `show version` for the release rule, `show spanning-tree` for Root Guard, `show vlan brief` for the DHCP snooping and DAI coverage, `show ip ssh` for SSHv2 — a reviewer asking how the rule was determined would otherwise have to reconstruct it from the code.

The map is written out per rule rather than inferred from the closures. Inference here would be clever and unverifiable, and this is evidence about evidence: naming a command a check did not read is a wrong claim inside a signed checklist, and unlike a wrong verdict nobody can catch it by looking harder at the switch. `tests/test_inspection_commands.py` pins every entry against the set of commands the collector actually runs, so a command that is not collected cannot be claimed.

**A rule with no check claims nothing.** NOT AUTOMATED covers two different situations and only one of them read anything: a rule with no entry in `CHECKS` was skipped, while a check that *returns* `'NOT AUTOMATED'` — `_user_facing_trunk_check`, say — did read the config and then decided the rule needs a human. The first gets no line at all, because "Inspected with: `show running-config`" under a rule nothing examined is the checklist misrepresenting its own work. The second gets one, because it is as true there as on a PASS.

Where the config sources interface templates, every rule's line names the `show template interface source user <name>` commands too. That is not padding: with templates expanded, every check really did read those bodies, and a verdict about a templated port was reached partly from them.

The mechanism is opt-in. An audit that passes no `rule_commands` map claims nothing, which is the right default for one whose commands have not been mapped — all three audits here pass one.

### And a second line, for looking rather than reading

```
Inspected with: `show running-config`
Verify with: `show running-config | section ^line vty`
```

Two claims, two labels, and the separation is the whole point. The audit reads `show running-config` **once** and greps the text in Python; it never sends a `| include` or `| section`. Putting the filtered form under "Inspected with" would be the report describing a command nobody ran — the exact failure `tests/test_inspection_commands.py` was written to prevent, committed by the file that added the test.

So the filtered command gets its own label and its own meaning: this is what a reviewer types on the switch to see the evidence for themselves, six months later, without reading any of this code. That is worth having, and it is not a statement about what happened during the run.

A rule with no filter gets no line. A filter that prints nothing reads on a switch as *this is not configured* — a finding the rule may not have — so a wrong filter is worse than none. The suite applies every filter to a config that satisfies its rule and requires non-empty output, using a small simulator for what IOS `include` and `section` actually do. That test's fixture is the unhardened config plus the blocks the harden scripts push, since the ordinary fixture is missing most of this evidence on purpose.

`show running-config all` is not offered anywhere: nothing in this project collects it, and a filter against a command that is never run is a filter nobody can reproduce.

## The report, as a file STIG Viewer opens

A printed report is read once and retyped into STIG Viewer rule by rule, and that transcription is the least reliable step in the whole exercise: 64 rules, four statuses, and a free-text box per rule that nobody is filling in carefully by rule 50. STIG Viewer 3's format is `.cklb` — the same JSON these audits already read their rules out of — so `--to-cklb` writes the verdicts back into a copy of it.

That makes one table load-bearing in a way a printed line never was. A wrong entry in `CKLB_STATUS` is a compliance claim inside a signed artifact:

| audit | .cklb | why |
|---|---|---|
| PASS | `not_a_finding` | the check ran and the switch complies |
| FAIL | `open` | the check ran and it does not |
| NOT APPLICABLE | `not_applicable` | the rule's own precondition does not hold |
| NOT AUTOMATED | `not_reviewed` | nothing here reviewed it |

The last row is the one that matters. `NOT AUTOMATED` must never become `not_a_finding`: that turns "this tool did not look" into "a reviewer confirmed compliance", under someone's name, on exactly the rules that need a human — configuration backups, a CA's issuer. `not_reviewed` is what STIG Viewer shows an unanswered rule as, which is what it is. The reason line still goes into `finding_details`, so a reviewer starts from whatever the audit did manage to determine rather than from nothing.

The second half is what a re-run does. Once a checklist has been opened it is not only this tool's output any more, so ownership is split: the audit owns `status` and `finding_details` and re-derives both on every run; the reviewer owns `comments` and any severity `overrides`, and those are carried across. Without that, the second run silently deletes the reviewer's notes on precisely the rules they had to answer by hand. Writing over `checklists/*.cklb` itself is refused outright — that is the blank template every audit reads its rules from, and filling it in with one device's verdicts would leave the next run auditing against someone else's results.

## Redaction that refuses

A capture is a verbatim copy of a production switch, which is why `captures/` is gitignored and why nothing here uploads one. But there is a standing need to show one to someone — a vendor case, a ticket, a question — and without a tool that need gets met by hand, under time pressure, on the one line that gets missed.

`sanitize_capture.py` is blunt on purpose: every value of a kind becomes the same placeholder, so nothing in the output maps back to what it replaced. The cost is stated in the tool, in its output's first lines, and here: **a redacted capture is for reading, not for re-auditing.** A redacted ACL source no longer falls inside `management_subnet` and redacted VLAN IDs no longer match the user-VLAN list, so an audit of one reports findings against a switch that does not have them. Nothing stops that run, because nothing in the text can honestly detect it — so it is said instead of guarded.

Two design decisions carry the weight:

- **It scans its own output and refuses to write if anything still looks sensitive.** A partially redacted file is worse than no file: it arrives with REDACTED at the top and gets treated as safe. The scan reports line numbers and the shape it saw, never the value — the point of the message is to be read on a terminal, and printing the value would put the thing being redacted back on the screen.
- **What it keeps is as deliberate as what it removes.** Command names, interface names, block structure, IOS keywords, model and release all survive; without them the file stops being a configuration and becomes a shape nobody can ask a question about. The model and release are not CUI, and `V-220569` needs them.

Every leak in `tests/test_sanitize_capture.py` was a real one first, found by running the rules against a config shaped like a real switch's rather than against the test fixture: the SNMPv3 `auth` and `priv` passphrases survived untouched (running-config keeps those in the clear); `ntp authentication-key 1 md5 <hash> 7` had its key *id* redacted and its hash left, because a generic `key` rule was matching the tail of `authentication-key`; and the capture's own `show vtp password` delimiter was rewritten into a section header `capture.py` could no longer parse. The mirror failure is over-redaction, and it is tested too: `The VTP password is not configured.` came out as `The VTP password <redacted> not configured.`

## Addressing that lives somewhere other than a config

Two of the questions this repo gets asked are not about compliance at all: what is actually on this segment, and what does the diagram say the addressing is. Both were being answered by retyping, which is where a transposed octet comes from.

- **`arp_inventory.py`** reads `show ip arp <subinterface>`. An ARP table is a snapshot of who has spoken, not an inventory of what exists — a host quiet longer than the four-hour timeout is simply absent, and a stale entry outlives its host — so the CSV carries the age column and marks the two rows that are not hosts: the router's own address (age `-`), and an incomplete entry, which is an ARP request nothing answered. An incomplete entry prints no interface, which makes filtering by interface a question about where the output came from: output the router itself filtered is all one interface's by construction, a pasted whole table is not, and guessing wrong would attribute a host to the wrong segment.
- **`pdf_ips.py`** reads a Visio-exported PDF, parsing the file itself — objects, page tree, content streams, text-showing operators — because the host it runs on has no PDF library and cannot be given one. The limit worth knowing is that it reads *text*: a diagram flattened to an image contains pixels that look like text to a person and nothing to a parser. That case is reported as "this file has no text in it", not as an empty result, because an empty CSV reads like "the diagram has no addresses on it". Text in a PDF also has no reading order beyond the order it was drawn in, so the `context` column is the text drawn around each address — usually its label, sometimes the label of the next box over. It is a hint for finding the address on the page, and the tool says so rather than presenting it as an assertion.

## Captures arrive in whatever encoding saved them

The work switches are reachable only through PowerShell or SecureCRT, and both of PowerShell's obvious ways to save output add a byte order mark: `>` and `Out-File` default to UTF-16LE on Windows PowerShell 5.1, and `Out-File -Encoding utf8` writes UTF-8 with a BOM. Read as plain UTF-8, neither failed in a way that named its cause — a UTF-8 BOM glues itself to the first delimiter line, so only `show running-config` goes missing, and UTF-16 decodes to NUL-riddled text matching nothing at all. Both refusals are correct and neither is actionable, which on someone else's network costs a second trip to the switch. `capture.py` sniffs the BOM instead, and a UTF-16 file with the BOM stripped — the one case that cannot be sniffed — names the encoding in its error.

## When empty output is the answer

A capture is refused if any command came back with nothing: a command that returned nothing and a feature that is switched off look identical, and a check handed empty text reports a verdict as confidently as one handed real config.

`show snmp user` is the exception. It prints nothing at all when no SNMPv3 users are defined — a legal switch state, and a non-compliant one that V-220604/605 exist to catch. Refusing the capture there abandons the entire collection over the very finding it was sent to collect, and it fails at collection time, before there is a report to explain it. The section must still be present, so a command that was never run is still caught; it is only allowed to be empty. `_snmpv3_user_live_check` reads empty output as "no SNMPv3 user with an authentication protocol found" and FAILs, which is the right verdict. The exemption list is duplicated in `securecrt/capture_l2s.py` (standalone by design) and `tests/test_securecrt_script.py` asserts the two cannot drift.

## Inventory is a different question from compliance

`securecrt/inventory_l2s.py` walks the same saved sessions the STIG collector
does and asks one command, `show version`, where that one asks seven. The split
is not tidiness. `show running-config` is much the slowest of the seven on a
large switch, so an audit of six hundred devices is an evening and an inventory
of the same six hundred is a coffee break — and something you can re-run on a
Tuesday because you want to know what is out there is a different tool from
something you schedule.

Keeping them apart cost one thing and bought another. The cost is a third file
in `securecrt/`, which must be copied with the other two: it reuses their
session discovery, connect handling and `show version` readers rather than
carrying copies that could drift, because an inventory disagreeing with a
checklist about which release a switch runs would be worse than no inventory.
What it bought is that neither has to compromise — the audit is free to be slow
and thorough, and the inventory is free to be fast and shallow.

The STIG walk's own log keeps the model and drops the serial and release. It
keeps the model because a verdict means something different on a C9300 than on
a WS-C3850 whose hardware is past support, and that log is the file listing
both. It drops the other two because the inventory answers them better and more
often, and two files carrying the same fact disagree the day one of them is a
week old.

## A stack is more than one asset

`show version` describes a stack the way an audit needs it: the active member's
model and serial, and the release every member runs. An inventory needs the
other thing — each chassis is its own asset with its own serial on its own
property record, and a three-member stack read from `show version` alone leaves
two of them unaccounted for.

So the inventory walk asks two more short commands and joins all three on the
member number: `show switch` for which members exist and which is Active,
Standby or Member; `show license udi` for each member's PID and SN; and
`show version`'s switch table for each member's release. A stack becomes one
CSV row per chassis, sharing a hostname and an address.

The join leaves a cell blank rather than filling it from another member. A
serial beside the wrong chassis number is worse in an asset record than an
empty cell — the empty one gets chased, the wrong one gets filed. A platform
that answers neither extra command (not stackable, or a release without
`show license udi`) falls back to what `show version` says about the one
switch, which is exactly the row the walk produced before either command was
asked for.

## The dialog that would have stopped the night

SecureCRT raises a New Host Key dialog on the first SSH connection to a switch
it has not seen. With a person in the chair that is one press of Enter on
Accept & Save. In an unattended walk it is a modal box no script can dismiss,
and the run stops on switch 1 of six hundred until somebody comes back to the
machine — the same class of failure as a progress dialog inside the loop, and
the reason there are none.

`/ACCEPTHOSTKEYS` on the connect string makes the same trust decision that
button makes, without drawing it. What it does not do is accept a key that has
*changed* on a host already in the database: that stays an error and lands in
the log with its own comment, which is the one host-key case worth a human's
attention. A build old enough not to know the option rejects it rather than
ignoring it, so the first connection that fails that way drops the flag for the
rest of the run and retries — one switch pays for finding out, not the walk.
