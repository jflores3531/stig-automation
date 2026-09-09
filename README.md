# STIG Automation — DISA STIG Compliance for Cisco Infrastructure

Python tooling that **audits and remediates Cisco network devices against DISA STIG benchmarks** — the hardening standard required on U.S. Department of Defense networks. Built on [Netmiko](https://github.com/ktbyers/netmiko) over SSH for live runs — and on the standard library alone for the offline audit path, which is the one that runs where nothing can be installed.

Manually STIG-checking a single switch means working through ~65 rules by hand against the running-config, then doing it again after every change. These scripts automate that check across four DISA benchmarks and push the fixes.

| Platform | DISA Benchmarks | Rules | Automated checks |
|---|---|---|---|
| Cisco IOS XE Switch | L2S + NDM | 64 | 63 (64 with site declarations) |
| Cisco IOS Switch | L2S + NDM | 65 | 62 |
| Cisco NX-OS Switch | L2S + NDM | 64 | 57 |
| Cisco IOS Router | NDM + RTR | 127 | 59 |

Rules needing external infrastructure (a backup server, an NMS) or topology/policy judgment are reported **NOT AUTOMATED** rather than guessed at. One of them, `V-220671`, becomes answerable once the site declares two facts about itself in `inventory.yaml` — which hostnames are core/distribution switches, and which port descriptions mark an uplink — because "user-facing" is not something a configuration says — a false pass on a compliance tool is worse than no answer. Every rule check is coded against the STIG's literal Check Text, and every fix against its Fix Text.

**Run against production hardware.** The read-only path — SecureCRT collection, the offline audit, the checklist export and the fleet inventory — has been exercised against Cisco Catalyst **3850s and 9300s on a production network**, including stacks. Several of the parsers here exist because that is where they were first proved wrong: the release and model on an image that prints no version banner, per-member serials on a stack, a domain line spaced unlike the manual's.

Development and the hardening scripts are validated against a 7-device virtual lab (2 IOS routers, 3 IOSvL2 switches, 2 NX-OS cores). See [`docs/DESIGN.md`](docs/DESIGN.md) for the reasoning behind script isolation, run order, and credential handling.

## What's here

Every script lives in [`scripts/`](scripts/) and is run from the repository root — `python3 scripts/<name>.py`. The names below are given bare for readability. `inventory.yaml`, `secrets.yaml`, `checklists/`, `backups/` and `audit_logs/` sit at the root beside `scripts/`, and are found there no matter which directory a script is invoked from.

### Shared
- **`netauto.py`** — Inventory loading, device-name validation, credential prompting, Netmiko SSH connection handling, automatic privilege escalation.
- **`inventory.yaml`** — Device inventory and STIG-hardening config (NTP/syslog/RADIUS server IPs, VLAN IDs, management subnet, automation host). No credentials. Written as JSON — see `scripts/yaml.py` — which parses under real PyYAML too, since JSON is a subset of YAML 1.2.
- **`secrets.yaml`** (gitignored) — Plaintext secrets for the `*_stig_harden*.py` scripts. Copy `secrets.yaml.example` to start.
- **`yaml.py`** — Stand-in for PyYAML on hosts where nothing can be installed: `safe_load` reads the inventory with the stdlib `json` parser. Sitting in `scripts/` beside its importers, it shadows any real PyYAML present for anything run from there, which is harmless while `inventory.yaml` stays JSON — that parses under either.

### Reading what is already out there
- **`arp_inventory.py`** — What is actually live on a subinterface, from the router's ARP table, as a CSV. Reads a device from `inventory.yaml` or a pasted `show ip arp` with `--from-file`. The router's own address, and an incomplete entry (an ARP request nothing answered), are marked as what they are rather than listed as hosts.
- **`pdf_ips.py`** — The addresses out of a PDF network diagram — a Visio export, usually — into a CSV with the page and the label drawn beside each one. Parses the PDF itself (objects, page tree, content streams) because the host it runs on has no PDF library and cannot get one. A diagram flattened to an image has no text to find, and that is reported as itself rather than as a diagram with no addresses on it.
- **`merge_walk_csvs.py`** — Merges the per-run `inventory_*.csv` or `run_log_*.csv` files the two SecureCRT walkers below write, one per run, into one file — `python3 scripts/merge_walk_csvs.py <folder>`. Scoping a walk by distribution node (SecureCRT session folder) turns one run into one per node, and one CSV into one per node; this reads every matching CSV in a folder and merges them back, deduplicating to the newest row per switch by its own timestamp column, with `switch_number` folded into the key wherever the header carries one so a stack's members are never collapsed into each other. An `inventory_*.csv` and a `run_log_*.csv` are never merged together — they answer different questions — and a folder holding both needs `--prefix` to say which to merge. `--no-dedupe` keeps every row from every file instead, e.g. to see how many attempts a switch took across reruns.

### Backup & save
- **`backup_config.py`** — Back up running-config + VLANs; keeps a "latest" copy per device plus a timestamped archive pruned to 5.
- **`config_diff.py`** — Compare current running-config/VLANs against the last backup.
- **`save_config.py`** — Save running-config to startup-config on one device or all. Run it *after* a harden pass and its audit, not as part of one — see [`docs/DESIGN.md`](docs/DESIGN.md).

### Audit & hardening
- **`stig_common.py`** — Shared audit engine: loads a DISA `.cklb` checklist, checks the device against it, reports PASS/FAIL/NOT AUTOMATED by severity.
- **`securecrt/capture_l2s.py`** — Runs *inside* SecureCRT (Script → Run) against an already-open session, sending the read-only show commands — plus one per interface template the config turns out to source — then, when it finds the repo next to itself, audits them and writes **one** file: the filled-in `.cklb`, named `<hostname>_<DDMMMYYYY>_L2S_V3R2_NDM_V3R6.cklb`. The capture it read is a working file and is deleted once the checklist exists; no report `.txt` is written. The whole flow is one action: connect, run script, open the checklist in STIG Viewer. Where the audit cannot run on that machine, the capture is kept instead and the dialog says where to audit it. Collection is standalone by design (no netmiko, no repo imports), and the offline audit itself needs only Python — `yaml.py` stands in for PyYAML and netmiko is imported lazily, only when a live connection is actually opened.
- **`securecrt/inventory_l2s.py`** — Inventories every saved SecureCRT session: connect, send `show version` — plus `show switch` and `show license udi` **only when its switch table names more than one chassis** — read what the switch is off them, disconnect. Writes one `inventory_<stamp>.csv` — `hostname, ip_address, switch_number, role, model, serial_number, ios_version, comment, session, timestamp` — and nothing else. **A stack is one row per chassis**, since each member is its own asset with its own serial and `show version` names only the active one; `show switch` gives the members and their Active/Standby/Member roles, `show license udi` gives each one's model and serial, and the three are joined on the member number. A standalone switch therefore costs one round trip rather than three: the two extra commands exist to account for members `show version` does not describe, and a switch that is its own whole stack has none. A release printing no switch table is not read as one switch — that is exactly where `show license udi` is the fallback for model and serial. Deliberately separate from the STIG walk below: one to three short commands per switch instead of seven, so a fleet that takes hours to audit takes minutes to count, and can be re-run whenever you want to know what is out there. A switch nobody reached is still a row, with its data columns blank and its comment saying **Connection timed out** or **System refused connection**. Each run writes its own CSV — a snapshot, not an accumulated history — and there is no resume, because the run is short enough to repeat. Needs `capture_l2s.py` and `capture_l2s_bulk.py` beside it, whose session discovery, connect handling and `show version` readers it reuses rather than duplicating.
- **`securecrt/capture_l2s_bulk.py`** — The same thing unattended, across every saved SecureCRT session: connect, send the commands, audit them, write the `.cklb`, disconnect. One output folder holds the whole fleet, since each name carries the switch that produced it. Host keys are **not** accepted blind: `ACCEPT_HOST_KEYS` is `False` in `capture_l2s_bulk.py`, because host-key checking is the part of SSH that says the switch is the switch, and a fleet walk is the wrong place to waive it. The cost is that the **New Host Key** dialog a first connection raises is a modal box no script can dismiss, so a switch whose key is not already in SecureCRT's database stops an unattended run until somebody clicks it — connect to a new switch once by hand and the walks handle it from then on. Setting it `True` restores the old behaviour, where the walk answers that dialog the way its default button does; the retry that recovers from a SecureCRT build rejecting the flag outright applies either way. Each run also writes a `run_log_<stamp>.csv` accounting for every session in the list — `hostname, ip_address, model, comment, outcome, session, timestamp` — so a switch nobody could reach is a row saying **Connection timed out** or **System refused connection** rather than a gap. For an inventory of the fleet rather than an audit of it, use `securecrt/inventory_l2s.py` below. A re-run visits only the sessions not yet done (tracked in `collected.csv` beside the checklists — a checklist is named for the switch's own hostname, which is not knowable before connecting, so its existence cannot be tested in advance); deleting a checklist puts its switch back in the queue. Two switches reporting the same hostname are kept apart by address rather than one landing on the other's file. Where the audit cannot run on that machine at all — settled once, before the walk, not per switch — it offers to collect captures alone for auditing elsewhere. It never aborts — a switch that is offline, in a login quiet period or refusing credentials is logged and skipped, because on a fleet of hundreds not all of them answer on a given night. Deliberately separate from `capture_l2s.py`, which cannot connect to anything and so cannot be pointed at the wrong device; this one logs into every switch on its own authority, which is a materially different thing to put in front of whoever approved the tooling. Copy both files together — it imports the guards, command list and capture format from `capture_l2s.py` rather than duplicating them.
- **`securecrt/harden_l2s_bulk.py`** — The only script in `securecrt/` that **configures devices**. It pushes the same logging/audit and access-control fixes as `scripts/l2_stig_harden_logging_access.py` to every saved session, or to one distribution-node folder, over SecureCRT instead of netmiko — which is the whole point, since netmiko cannot be installed on the machine these switches are reachable from. Same commands, same order; the lists are duplicated because nothing in `securecrt/` may import from the repo, and `tests/test_securecrt_harden.py` asserts the two copies are identical so they cannot drift. It is a separate file with a separate name rather than a flag on one of the walks above, because a script that logs into a fleet on its own authority and writes to running-config is a materially different thing to put in front of whoever approved read-only tooling. **It never writes startup-config** — until someone runs `copy running-config startup-config`, a reload puts the switch back exactly as it was, so the order is harden, re-audit, then save deliberately. **The vty block is off unless asked for**, defaulting to No: everything else is reversible from any session that can still reach the switch, while the vty lines decide how many sessions there can be. When it is asked for, the range is read off each switch — the limit is **5**, so vty 0-4 answer and everything above them is taken out of service. IOS XE ships `line vty 0 4` *and* `line vty 5 15`, and configuring only the first leaves eleven lines answering while the row claims a five-session limit; on a switch whose only range is `line vty 0 4` there is nothing above it and what gets pushed is DISA's own example verbatim — and a switch whose range could not be read has the block **skipped and flagged**, never applied on an assumed `0 4`. The syslog collectors are read straight out of `inventory.yaml` when the folder is still inside the repo — it is JSON, so that needs no import from the wider project — and the prompt comes up prefilled; where the folder has been copied away, or the file lists fewer than two usable addresses, the box is empty and they are typed in. Two or none either way, since a switch logging to one server is a partial fix for V-220568/220620 that reads as a finished one. Each run writes a `harden_log_<stamp>.csv` accounting for every session — `hostname, ip_address, outcome, rejected, comment, session, timestamp` — so a switch that was unreachable, or that rejected a command its image does not have, is a row rather than a gap. The scope prompt is a prefix match on the session path, so typing a session's full name scopes the run to that one switch — how you test it on a lab switch first — and the confirmation box **names** the sessions it matched, not just their count, because a partial filter takes in neighbours (`10.1.2.3` also matches `10.1.2.30`). A `STOP` file in the log folder ends the run cleanly at the end of the current switch. Needs `capture_l2s.py` and `capture_l2s_bulk.py` beside it.
- **`capture.py`** — Offline auditing. Every check is a pure function of command output, so an audit can read a capture file instead of a switch — for networks where the tooling can't be pointed at the devices directly. A malformed, truncated or partial capture is refused rather than audited, since a check handed empty text returns a verdict just as confidently as one handed real config. That includes a `show running-config` that **stopped before its `end`** — the collector reads up to the prompt, so a `SW01#` inside a banner or a description ends the read early, and what comes back opens exactly like a config because it is the opening of one. Every other guard waves it through, and the rules answered against the part that never arrived — aaa, line vty, logging, ntp, snmp and ssh all sit near the end of a config — come back as findings on a switch that configured every one of them. Which commands a capture must cover is partly a fact about the capture: a config whose interfaces say `source template <name>` must also carry that template, or the per-port rules would be answered against configuration nobody read.
- **`sanitize_capture.py`** — Redact a capture so it can leave the network it came from: addressing, hostnames, VLAN names and IDs, ACL names, descriptions, credentials, certificates and serials, overwritten with placeholders rather than swapped for consistent fakes. It scans its own output before writing and refuses the file if anything still looks sensitive, because a partially redacted capture is more dangerous than none — it gets treated as safe. The redacted copy is for reading, not for re-auditing: the placeholders change verdicts.
- **`l2_stig_audit.py`** — Audit against the IOS XE Switch L2S/NDM STIG (the default) or the IOS Switch one (`--checklist ios` — what the lab's vios_l2 switches are). Full interface-scoped coverage, live discovery for root ports/VTP/user VLANs. `--from-capture` audits collected output; `--capture-to` records a live run so the two can be compared; `--to-cklb` writes the verdicts into a STIG Viewer 3 checklist instead of leaving them to be retyped. Interface templates are read and expanded into the ports that source them, so a templated port is audited on what it is actually configured with — see [`docs/DESIGN.md`](docs/DESIGN.md).
- **`ios_xe_rule_map.py`** — The IOS and IOS XE switch STIGs share no rule IDs, but 60 of the IOS XE STIG's 64 rules are the same requirement as an IOS rule already checked here. This maps them, accepting a pair only when the literal "this is a finding" condition matches in both. Three more — NTP, PKI and QoS — the IOS XE book asks differently enough to need their own checks, which live in `l2_stig_audit.py` rather than the map: re-keying the IOS predicate onto them would answer a different question. One rule (configuration backups) is deliberately excluded and reports NOT AUTOMATED, because nothing on the switch can answer it.
- **`nxos_stig_audit.py`** — Audit against the NX-OS Switch L2S/NDM STIG.
- **`ios_router_audit.py`** — Audit against the IOS Router NDM/RTR STIG. Most RTR rules need topology/policy context and report NOT AUTOMATED.
- **`l2_stig_harden_logging_access.py`** — Only the logging/audit and access-control fixes, as their own script: log timestamps, buffer size, login success/failure logging, `logging userinfo`, `logging trap critical`, syslog servers, the `archive`/`log config` block that answers eight rules at once, the failed-login lockout, `exec-timeout` on vty **and** console, the SSH transport crypto (`ip ssh version 2` plus FIPS-approved MAC and encryption lists, V-220555/220556), and the concurrent-session limit — **5**, the organization-defined number the rest of the project's harden scripts already push; the 2 in DISA's example is an example, and the rule's finding sentence asks only that a limit exist. Nothing here touches the data plane — no spanning-tree mode, no VLAN database, no `no <service>` lines — so it needs no change window for forwarding behaviour. `--dry-run` prints the commands without connecting. **The vty lines are off by default**: everything else here is reversible from any session that can reach the switch, while the vty block decides how many sessions there can be — the one mistake that would take away the means of fixing it. `--with-vty` adds them (with `--sessions N` to change the count), and until it is run V-220518/220570 stays a finding, which the script says in its own output rather than leaving to the next audit. When it does run it pushes both `session-limit` *and* DISA's primary method of taking the spare vty lines out of service with `transport input none`, and deliberately omits `ip http max-connections` — a limit on a server hardening turns off is not a control. The console `exec-timeout` is pushed either way; it can strand nobody.
- **`l2_stig_harden_global.py`** — Bulk L2S hardening: BPDU/Loop Guard, Rapid-PVST, UDLD, IGMP + DHCP snooping, archive logging, VTP, per-port access/trunk hardening, NTP, syslog, SNMPv3. **Run first** — the other `l2_stig_harden_*.py` scripts depend on it.
- **`l2_stig_harden_ipsg.py`** — IP Source Guard (V-220634) on access ports. See Notes for the static-host caveat.
- **`l2_stig_harden_dai.py`** — Dynamic ARP Inspection (V-220635) on user VLANs. Same static-host caveat.
- **`l2_stig_harden_access_ports.py`** — Host-facing port fixes: explicit access mode, PortFast (V-220630b — without it the global `bpduguard default` is inert everywhere, a false PASS), UUFB, and speed-scaled storm control (FastEthernet skipped, per DISA's own Fix Text note). Never sends a trunk command or touches a trunk-classified port, so it is safe to run on a working day. **It never sets an access VLAN** — neither V-220642's default VLAN nor V-220641's unused VLAN — because a port's VLAN says what the thing plugged into it can reach and this pass does not know what is plugged in; both are printed as unpushed findings instead. **Interface templates are read off the switch and expanded before any port is classified**, since a port whose block is only `source template <name>` carries no `switchport mode trunk` line of its own — off the raw config a templated uplink reads as an access port, and this script would have sent it `switchport mode access` and PortFast. **802.1x/MAB (V-220623) is deliberately not pushed** — `authentication port-control auto` on a switch with no reachable RADIUS authenticator and no supplicant on the endpoint authenticates nobody and forwards nothing, which on an access switch full of user devices is an outage rather than a hardening step. The script prints it as an unpushed finding on every run and the audit still reports it as one.
- **`l2_stig_harden_trunk_ports.py`** — Uplink port fixes: `switchport nonegotiate`, DHCP snooping and DAI trust, the allowed-VLAN list discovered from the switch's own VLAN database, the native VLAN, and Root Guard on every trunk **except this switch's own STP root port** (discovered live — guarding it forces root-inconsistent/blocking state and takes out the path to the root bridge). Templates are expanded before classification here too — a templated trunk read off the raw config is an access port, which here means the trunk fixes silently skip a real uplink and the run reports a clean pass. Split from the access half because these are the commands that can take the switch away from you: the allowed-VLAN list replaces what the uplink carries and the native VLAN changes what untagged frames land in, and the session pushing them is usually riding that trunk. Give it its own change window with console access to hand.
- **`l2_stig_harden_acl.py`** — vty management ACL (V-220575), scoped to the automation host. Run as its own script.
- **`l2_stig_harden_aaa.py`** — `aaa new-model` + RADIUS auth (V-220587/617) + password policy (V-220589-594). **Run last.**

#### NX-OS
- **`nxos_stig_harden_global.py`** — NX-OS equivalent of `l2_stig_harden_global.py`, enabling required features (`feature udld`, `feature dhcp`, `feature vtp`, `feature ntp`) before applying fixes.
- **`nxos_stig_harden_interfaces.py`** — Per-port NX-OS fixes: UUFB, IP Source Guard, storm control, DAI trust, VLAN pruning.
- **`nxos_stig_harden_acl.py`** — NX-OS management ACL (V-220479), scoped to the automation host.
- **`nxos_stig_harden_aaa.py`** — NX-OS RADIUS auth and accounting. NX-OS falls back to the local account automatically when RADIUS is unreachable.

#### IOS Router
- **`ios_router_stig_harden_global.py`** — Global RTR/NDM fixes: disable gratuitous ARP, CDP, AUX port; enable CEF; NTP, syslog, SSH FIPS ciphers, password encryption.
- **`ios_router_stig_harden_acl.py`** — vty management ACL (V-215667), the router port of `l2_stig_harden_acl.py`.
- **`ios_router_stig_harden_aaa.py`** — AAA/RADIUS (V-215709) plus password complexity (V-215681-686). `local` stays last in the method list, so SSH login still succeeds if RADIUS is unreachable.
- **`ios_router_stig_harden_urpf.py`** — Unicast Reverse Path Forwarding (V-216989) on external-facing interfaces. Requires `allow-default` — see [`docs/DESIGN.md`](docs/DESIGN.md).

## Requirements

Which of the two paths applies is decided by whether the host lets you install anything.

**Offline audit — nothing installed, and nothing installable.** On the work machine neither netmiko nor PyYAML can be installed at all, so the offline path is written not to need them: `yaml.py` stands in for PyYAML, and netmiko is imported inside `netauto.connect()`, which an offline audit never calls. The SecureCRT collectors and `l2_stig_audit.py --from-capture` therefore run on a stock Python and nothing else — copy `scripts/` and `checklists/` in and run them. This is the deployment target, not a fallback.

The inventory it reads can be this small:

```json
{
  "devices": {},
  "non_user_vlans": [1, 10],
  "unused_vlan": 999,
  "native_vlan": 998,
  "management_subnet": "10.0.0.0/24"
}
```

`devices` stays an empty object because `load_inventory()` indexes that key directly; captures are audited under whatever label you pass on the command line, so no switch needs an entry. `management_subnet` takes one prefix or several (a list, or one comma-separated string) — a management network is not always a single range — and is **not** optional — with it absent the vty management ACL rule (V-220575, or V-220523 under the IOS XE checklist) reports FAIL on every device with the missing key as its reason, rather than a real verdict about the switch. `automation_host` is not needed here: only the `*_harden_acl.py` scripts read it, and those push config over a live connection. Every key is documented in [`inventory.yaml.example`](inventory.yaml.example).

Across a fleet where each site numbers its user and voice VLANs differently, add `user_vlan_names: ["USERS", "VOICE"]`. Those names are matched against the name column of `show vlan brief`, which every capture already carries, and they override `non_user_vlans` — so a switch whose user VLAN is 10 is still checked even though 10 is the management VLAN elsewhere and sits in that ID list. Without it the ID exclusion wins and the audit reports PASS for DHCP snooping and DAI coverage it never verified. `non_user_vlan_names` is the mirror, for a non-user VLAN whose ID moves instead; where every non-user VLAN is consistently numbered, leave it empty. `--user-vlan-names` and `--non-user-vlan-names` override either list for one run.

**Live runs — Netmiko over SSH.** Only for scripts that actually open a connection: the `*_stig_harden*.py` pushes, live audits, and the backup/diff/save utilities. On a host where installs are possible:

```
pip install -r requirements.txt
```

The Ansible roles under [`ansible/`](ansible/) are in the same category — fleet runs from a machine that can install Ansible and its collections.

Copy `secrets.yaml.example` to `secrets.yaml` and fill in real values before running any `*_stig_harden*.py` script that needs them.

## Usage

Each script prompts for your SSH username and password via `getpass` (not echoed or stored).

**On Windows, in PowerShell**, the commands below are the same with two changes: run them with
`python`, not `python3` (`python3` is usually not on PATH, and where it is it can be the Microsoft
Store stub, which opens the Store instead of running anything), and put each command on **one
line** — the `\` continuations here are bash, and PowerShell's continuation character is a
backtick. Paths take `\` or `/`; both work. The checklist export below, as PowerShell takes it:

```powershell
python scripts/l2_stig_audit.py SW01 --from-capture captures\SW01.capture --to-cklb checklists\out\SW01.cklb
```

Output directories are created if they do not exist.

```bash
# Back up one device or all devices
python3 scripts/backup_config.py R1
python3 scripts/backup_config.py

# Diff current running-config against last backup
python3 scripts/config_diff.py R1

# STIG audit. l2_stig_audit.py defaults to the IOS XE STIG (the deployment
# target); the lab's vios_l2 switches are IOS, hence --checklist ios there.
# The two STIGs share no rule IDs, so the wrong checklist reports every rule
# NOT AUTOMATED.
python3 scripts/l2_stig_audit.py S1 --checklist ios
python3 scripts/nxos_stig_audit.py NXCore1
python3 scripts/ios_router_audit.py R1

# Audit without connecting. Collect the read-only show commands into a
# file - a logged terminal session works - then audit it from anywhere. A
# switch whose ports are configured from interface templates needs one more
# command per template; the audit names any that are missing and refuses the
# capture rather than reporting against config it could not see.
# --capture-to records a live run; auditing that file must give the same
# report, which is how the offline path is checked against a real switch.
python3 scripts/l2_stig_audit.py S1 --checklist ios --capture-to captures/S1.capture
python3 scripts/l2_stig_audit.py S1 --checklist ios --from-capture captures/S1.capture

# An IOS XE switch needs no flag - that checklist is the default.
python3 scripts/l2_stig_audit.py SW01 --from-capture captures/SW01.capture

# Write the verdicts straight into a STIG Viewer 3 checklist instead of
# retyping 64 rules. PASS/FAIL/NOT APPLICABLE become not_a_finding/open/
# not_applicable; NOT AUTOMATED becomes not_reviewed, never not_a_finding.
# Re-running over the same file re-derives everything from the new capture,
# including both text boxes - see "Getting a report into STIG Viewer 3".
python3 scripts/l2_stig_audit.py SW01 --from-capture captures/SW01.capture \
    --to-cklb checklists/out/SW01.cklb

# Give --to-cklb a directory instead and the audit names the file itself:
# <hostname>_<DDMMMYYYY>_<the checklist's own STIG versions>.cklb, e.g.
# SW01_06AUG2026_L2S_V3R2_NDM_V3R6.cklb. The hostname is the switch's own and
# the date is the capture's, so re-running on the same day writes the same
# file rather than piling up one per run.
python3 scripts/l2_stig_audit.py SW01 --from-capture captures/SW01.capture \
    --to-cklb checklists/out

# Redact a capture so it can be shown to someone off the network. Writes
# <name>.redacted.capture beside it, and refuses to write anything at all if a
# value it recognises as sensitive survives the pass.
python3 scripts/sanitize_capture.py captures/SW01.capture
python3 scripts/sanitize_capture.py captures/SW01.capture --also-redact "PROJECT NAME"

# Addressing from places other than a config: the ARP table of a subinterface,
# and a diagram someone sent as a PDF.
python3 scripts/arp_inventory.py R1 --interface Gi0/0.100 -o vlan100.csv
python3 scripts/arp_inventory.py R1 --from-file pasted-arp.txt --interface Gi0/0.100
python3 scripts/pdf_ips.py diagram.pdf -o addressing.csv
python3 scripts/pdf_ips.py diagram.pdf --all-text   # what it saw, when an answer looks wrong

# Fleet-sized: run securecrt/capture_l2s_bulk.py inside SecureCRT and it walks
# every saved session, leaving one checklist per switch in the output folder.
# Only if that machine cannot run the audit does it collect captures instead,
# which are then audited in one pass elsewhere. The loop below is Windows cmd,
# not bash.
for %f in (C:\captures\*.capture) do ^
    python scripts/l2_stig_audit.py %~nf --from-capture "%f" --to-cklb C:\Documents\checklists

# Scoping the walk by distribution node instead of the whole fleet leaves one
# inventory_*.csv or run_log_*.csv per node in the output folder. Merge them
# back into one file, deduplicated to each switch's newest row.
python3 scripts/merge_walk_csvs.py C:\Documents\netauto_inventory
python3 scripts/merge_walk_csvs.py C:\Documents\netauto_checklists --prefix run_log_

# STIG hardening for an L2 switch - run in this order:
python3 scripts/l2_stig_harden_global.py S1 # bulk fixes, run first
python3 scripts/l2_stig_harden_ipsg.py S1   # IP Source Guard - can drop a statically-addressed host, see Notes
python3 scripts/l2_stig_harden_dai.py S1    # DAI - same static-host risk as IPSG, see Notes
python3 scripts/l2_stig_harden_acl.py S1    # vty management ACL - run isolated
python3 scripts/l2_stig_harden_aaa.py S1    # AAA/RADIUS + password policy - run last

# NX-OS hardening - global first, then the isolated scripts
python3 scripts/nxos_stig_harden_global.py NXCore1
python3 scripts/nxos_stig_harden_interfaces.py NXCore1
python3 scripts/nxos_stig_harden_acl.py NXCore1
python3 scripts/nxos_stig_harden_aaa.py NXCore1

# IOS router hardening - same order
python3 scripts/ios_router_stig_harden_global.py R1
python3 scripts/ios_router_stig_harden_urpf.py R1     # external-facing interfaces only
python3 scripts/ios_router_stig_harden_acl.py R1
python3 scripts/ios_router_stig_harden_aaa.py R1

# Persist the result - only after re-auditing and confirming it's what you wanted.
# Until this runs, a reload reverts the device, which is the escape hatch if a
# push locked you out.
python3 scripts/save_config.py NXCore1
python3 scripts/save_config.py            # or every device in the inventory

# Tests - no framework, no device needed. A fresh clone has no inventory.yaml
# (gitignored), and the suites that drive the audit through the CLI need one -
# the example's placeholder values are enough to make all of them pass.
cp inventory.yaml.example inventory.yaml
python3 tests/test_capture.py
python3 tests/test_ios_xe_map.py
python3 tests/test_securecrt_script.py
python3 tests/test_switchports.py
python3 tests/test_securecrt_bulk.py
python3 tests/test_user_vlans.py
python3 tests/test_interface_templates.py
python3 tests/test_false_fails.py
python3 tests/test_manual_review_rules.py
python3 tests/test_cklb_export.py
python3 tests/test_checklist_target.py
python3 tests/test_sanitize_capture.py
python3 tests/test_arp_inventory.py
python3 tests/test_pdf_ips.py
```

## Getting a report into STIG Viewer 3

End to end, on Windows, from a switch to an open checklist. There is no separate
conversion step - `--to-cklb` is a flag on the audit, and one run produces both the
printed report and the file.

**1. Collect, or use a capture you already have.**

```powershell
python scripts/l2_stig_audit.py SW01 --capture-to captures\SW01.capture
```

Or collect it from SecureCRT, on a machine where nothing else may touch the network:
`securecrt\capture_l2s.py`, run from an already-connected session (Script > Run...). That one
writes the finished checklist and nothing else - no capture, no report - so if that is the whole
of what you need, skip to step 4.

**2. Audit, writing the checklist in the same pass.**

```powershell
python scripts/l2_stig_audit.py SW01 --from-capture captures\SW01.capture --to-cklb checklists\out
```

Given a **directory**, the audit names the file itself:

```
SW01_06AUG2026_L2S_V3R2_NDM_V3R6.cklb
```

The switch, the date the capture was taken, and the version and release of each STIG in the
checklist it was audited against - read out of that checklist, so pointing the audit at next
quarter's `.cklb` moves the versions in the name with it. The date carries no time of day: two
exports of one switch on one day are the same audit re-run, and writing to the same file is what
writes one file per switch per day. Pass a path ending in `.cklb` instead and that exact path is
used, as before. Either way the output directory is created if it does not exist.

The name you pass on the command line (`SW01`) is only a label when auditing a capture. The
switch's own `hostname` is what names the file and fills the checklist's **Host Name** - along with
three more fields on STIG Viewer's Asset tab that would otherwise be typed in by hand per switch:

| Field | Read from |
|---|---|
| Host Name | `hostname` in the running-config |
| IP Address | the SVI of the VLAN whose name ends in `mgt`/`mgmt`, via `show vlan brief` + `show ip interface brief` |
| MAC Address | `Base Ethernet MAC Address` in `show version` |
| FQDN | `<hostname>.<domain name>`, from `hostname` + `ip domain name` |

The report prints what it put in each one, and why any of them is empty - a blank field in STIG
Viewer looks the same whether nothing was found or nothing was looked for. If your management VLAN
is named something else, `--management-vlan-names` (or `management_vlan_names` in `inventory.yaml`)
takes the names or globs that identify it; none of this affects a verdict.

**3. Read what it says.** The usual report, then one line at the end:

```
26 passed, 33 failed, 4 not applicable, 1 not automated (need manual review or external infrastructure) out of 64 rules.

[HIGH  ] PASS           V-220569  must be running an IOS release that is currently supported by Cisco Systems.
           running 17.12.4 on C9300-48P - 17.12 is an Extended Maintenance release ...
...
Wrote checklists\out\SW01_06AUG2026_L2S_V3R2_NDM_V3R6.cklb for STIG Viewer 3: 26 not_a_finding, 33 open, 4 not_applicable, 1 not_reviewed.
```

Above the report, before any verdict, it also prints the asset fields it read:

```
Checklist asset fields:
  IP address:  x.x.x.5 (from Vlan10 (army-xxx-abc-mgt))
  MAC address: 00:1A:2B:3C:4D:5E
  FQDN:        SW01.example.mil
```

**4. Open it.** STIG Viewer 3 → **File → Open Checklist** → the `.cklb` the run just named. Every
rule arrives with its status set and its reason written into whichever box that verdict belongs in:

| Verdict | Where the reason goes | Why |
|---|---|---|
| `open` (FAIL) | **Finding Details** | It is the evidence for a finding, which is what an assessor reads first |
| `not_a_finding` (PASS) | **Comments** | Nothing to evidence; the note explains what was checked |
| `not_applicable` | **Comments** | Where a not-applicable justification is expected |
| `not_reviewed` (NOT AUTOMATED) | **Comments** | How far the audit got on a rule you now have to finish |

The note is the reason and only the reason — no status (STIG Viewer shows that beside the box) and
no provenance line, which would be the same sentence 64 times in one file. Which capture the run
read, and when, is recorded once in the asset block's own comment. A rule the audit never looked at
leaves an empty box, which is what unanswered should look like.

**A re-run replaces the whole file.** The checklist states what one capture said, so the new
capture wins outright: an export is the blank checklist plus that capture's findings and nothing
else. Nothing is read back out of the file being replaced — not Finding Details, not Comments, not
a severity override. The box a verdict does not use is cleared rather than left holding the
previous run's sentence.

So **nothing you type in STIG Viewer survives the next run to the same path**: an answer on a
`not_reviewed` rule, an override and its justification, all of it. Annotate a copy the audit does
not write to, or export the next run to a different folder.

**5. Answer what the tool could not.** The `not_reviewed` rules are the ones needing a person - the
configuration-backup server, for instance. Put your answer in that rule's **Comments** box in STIG
Viewer and save. Per the rule above, re-running the audit to the same path will overwrite it, so
annotate the copy you intend to keep - and send the next run somewhere else:

```powershell
python scripts/l2_stig_audit.py SW01 --from-capture captures\SW01.capture --to-cklb checklists\out
```

Every field is re-derived from the new capture. What the file says about a switch is always what
the latest capture said about it, and only that.

A live run is the same flag, and prompts for credentials:

```powershell
python scripts/l2_stig_audit.py SW01 --to-cklb checklists\out
```

So are the other two platforms:

```powershell
python scripts/nxos_stig_audit.py NXCore1 --to-cklb checklists\out\NXCore1.cklb
python scripts/ios_router_audit.py R1 --to-cklb checklists\out\R1.cklb
```

Give each device its own output file - which a directory does for you, since the name carries the
hostname. Two switches pointed at one explicit `.cklb` path leaves the second one's verdicts over
the first one's, under whichever host name was written last.

Filled-in checklists are gitignored (`checklists/out/`) - the blank ones in `checklists/` are the
templates every audit reads its rules from, and a completed one names a device and its findings.

## Notes

- Devices are defined in `inventory.yaml` by name, host, and Netmiko `device_type` (e.g. `cisco_ios`, `cisco_nxos`). Every address in `inventory.yaml.example` is written `x.x.x.x` so that no real addressing is committed, even as an example - replace them after copying. Until `management_subnet` is a real network, V-220575/523 reports `not a network` rather than a verdict; `--management-subnet 10.0.0.0/24` overrides it for a one-off run.
- Backups are written to `backups/`, with dated copies in `backups/archive/`.
- The L2 audit prints, above the report, which VLANs it classified as user VLANs and which it skipped and why. A VLAN wrongly excluded there produces no finding at all - DHCP snooping and DAI coverage is simply never asked about it - so the list is the only place that omission is visible. Any VLAN even one user can reside on belongs in it; `user_vlan_names` in `inventory.yaml` is how to put it there, and it overrides any ID exclusion. Entries are exact names, or globs where they carry a wildcard - `"*user"`, `"*user[0-9]*"`, `"*tel"` - which is how a fleet that calls the same role `army-xxx-abc-user1` on VLAN 800 at one site and `army-yyy-def-user15` on VLAN 850 at the next is described once rather than switch by switch. Where names are site-then-role, one pattern per role (users, voice) covers every switch; matching the site prefix instead (`"army-xxx-abc-*"`) also works but takes the management VLAN with it. The classification names the pattern that matched each VLAN, so a pattern reaching further than intended is visible in the report.
- STIG rules requiring external infrastructure (a configuration-backup server) or manual/topology review are reported NOT AUTOMATED rather than guessed at. Where a rule turns out to be answerable from what the switch already says — a self-signed trustpoint for the PKI rule, `show version` for the supported-release rule, MQC for the QoS rule — it is answered instead; see [`docs/DESIGN.md`](docs/DESIGN.md).
- `l2_stig_harden_ipsg.py` and `l2_stig_harden_dai.py` both only trust the DHCP snooping binding table — a statically-addressed host with no DHCP lease is invisible to either and can have its traffic dropped once they're pushed. Confirmed live. If a statically-addressed host (e.g. the automation host itself) is directly connected to a device, consider skipping one or both scripts for that device until this has a real fix.
- Scripts that push config append a JSON-line audit record (timestamp, script, device, username, commands) to `audit_logs/audit.log`. Not tracked in git.
- Several STIG-required commands don't exist or function on this lab's `vios_l2` image — see [`docs/DESIGN.md`](docs/DESIGN.md) for the list and why the scripts still push them.

