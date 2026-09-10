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

Anything marked **configures devices** writes to running-config. Everything else only reads.
The reasoning behind the ones that look odd — why scripts are split, what is deliberately
not pushed, which STIG readings were argued over — is in [`docs/DESIGN.md`](docs/DESIGN.md).

### Shared
| | |
|---|---|
| `netauto.py` | Inventory loading, credential prompting, Netmiko SSH, privilege escalation. |
| `stig_common.py` | The audit engine: reads a `.cklb`, checks the device, reports PASS/FAIL/NOT APPLICABLE/NOT AUTOMATED. Each answered rule also names what it was read from and the filtered command that shows the same evidence on the switch. |
| `inventory.yaml` | Devices and hardening config — NTP/syslog/RADIUS addresses, VLAN IDs, management subnet. No credentials. Written as JSON. |
| `secrets.yaml` *(gitignored)* | Secrets for the `*_harden*.py` scripts. Copy `secrets.yaml.example`. |
| `yaml.py` | Stand-in for PyYAML where nothing can be installed — `safe_load` via the stdlib `json` parser. |

### Reading what is already out there
| | |
|---|---|
| `arp_inventory.py` | What is live on a subinterface, from the router's ARP table, as a CSV. |
| `pdf_ips.py` | Addresses out of a PDF network diagram, with the page and label beside each. |
| `merge_walk_csvs.py` | Merges the per-run CSVs the SecureCRT walks write into one file, newest row per switch. |
| `backup_config.py` | Back up running-config + VLANs; a latest copy per device plus a pruned archive. |
| `config_diff.py` | Compare current running-config/VLANs against the last backup. |
| `save_config.py` | running-config to startup-config. Run it *after* a harden pass **and** its audit. |

### Auditing
| | |
|---|---|
| `l2_stig_audit.py` | IOS XE Switch L2S/NDM (default) or IOS Switch (`--checklist ios`). Interface-scoped, with live discovery for root ports, VTP and user VLANs. `--from-capture` audits collected output, `--to-cklb` writes a STIG Viewer 3 checklist. |
| `nxos_stig_audit.py` | NX-OS Switch L2S/NDM. |
| `ios_router_audit.py` | IOS Router NDM/RTR. Most RTR rules need topology context and report NOT AUTOMATED. |
| `capture.py` | Offline auditing from a capture file. Refuses a malformed, truncated or partial capture rather than auditing it. |
| `sanitize_capture.py` | Redact a capture so it can leave the network. Refuses to write if anything sensitive survives the pass. |
| `ios_xe_rule_map.py` | Maps 60 of the IOS XE STIG's 64 rules onto the IOS rule that asks the same thing, accepting a pair only where the finding sentence matches in both. |

### SecureCRT
Run inside SecureCRT (Script → Run) where netmiko cannot be installed. Copy the folder together —
they import from each other. Host keys are **not** accepted blind, so a switch whose key SecureCRT
has never seen stops an unattended run on a modal dialog; connect to it once by hand first.

| | |
|---|---|
| `capture_l2s.py` | One open session: send the read-only commands, audit them, write the `.cklb`. Cannot connect to anything, so it cannot be aimed at the wrong device. |
| `capture_l2s_bulk.py` | The same across every saved session, unattended. One `run_log_<stamp>.csv` accounting for every session, including the ones nothing answered from. |
| `inventory_l2s.py` | `show version` per session into one `inventory_<stamp>.csv`. A stack is one row per chassis. Minutes where the audit takes an evening. |
| `harden_l2s_bulk.py` | **Configures devices.** Logging/audit, access control, SSH crypto, the V-220534 service block. vty limit opt-in. Never writes startup-config. |
| `harden_access_ports_bulk.py` | **Configures devices.** The access-port fixes on every host-facing port. Never sends a trunk command. Reads and expands interface templates before classifying any port. |

### Hardening — IOS / IOS XE switch
Run in the order listed. Each is separate because of what it can cost you if it is wrong.

| | |
|---|---|
| `l2_stig_harden_global.py` | **Run first.** BPDU/Loop Guard, Rapid-PVST, UDLD, IGMP + DHCP snooping, archive logging, VTP, NTP, syslog, SNMPv3. |
| `l2_stig_harden_logging_access.py` | Logging/audit, access control, SSH crypto, unnecessary services. Touches no forwarding, so it needs no change window. vty lines behind `--with-vty`. |
| `l2_stig_harden_access_ports.py` | Host-facing ports: access mode, PortFast, UUFB, storm control, unused VLAN on shut ports. Safe on a working day. 802.1x is deliberately not pushed. |
| `l2_stig_harden_trunk_ports.py` | Uplink ports: `nonegotiate`, snooping/DAI trust, allowed-VLAN list, native VLAN, Root Guard. **Its own change window** — these decide what the uplink carries. |
| `l2_stig_harden_ipsg.py` | IP Source Guard (V-220634). Static-host caveat in Notes. |
| `l2_stig_harden_dai.py` | Dynamic ARP Inspection (V-220635). Same caveat. |
| `l2_stig_harden_acl.py` | vty management ACL (V-220575). Its own script — a wrong `access-class` locks out every future session. |
| `l2_stig_harden_aaa.py` | **Run last.** `aaa new-model`, RADIUS auth, password policy. |

### Hardening — NX-OS
| | |
|---|---|
| `nxos_stig_harden_global.py` | Enables the required features first, then applies the global fixes. |
| `nxos_stig_harden_interfaces.py` | Per-port: UUFB, IPSG, storm control, DAI trust, VLAN pruning. |
| `nxos_stig_harden_acl.py` | Management ACL (V-220479). |
| `nxos_stig_harden_aaa.py` | RADIUS auth and accounting. |

### Hardening — IOS router
| | |
|---|---|
| `ios_router_stig_harden_global.py` | Disable gratuitous ARP, CDP, AUX; enable CEF; NTP, syslog, SSH FIPS ciphers. |
| `ios_router_stig_harden_acl.py` | vty management ACL (V-215667). |
| `ios_router_stig_harden_aaa.py` | AAA/RADIUS plus password complexity. `local` stays last, so SSH still works if RADIUS is unreachable. |
| `ios_router_stig_harden_urpf.py` | uRPF (V-216989) on external interfaces. Needs `allow-default` — see Notes. |

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

# STIG audit. Defaults to the IOS XE STIG; --checklist ios for classic IOS.
# The two share no rule IDs, so the wrong one reports every rule NOT AUTOMATED.
python3 scripts/l2_stig_audit.py S1 --checklist ios
python3 scripts/nxos_stig_audit.py NXCore1
python3 scripts/ios_router_audit.py R1

# Audit without connecting: collect the show commands into a file - a logged
# terminal session works - then audit it anywhere. --capture-to records a live
# run, and auditing that file must give the same report.
python3 scripts/l2_stig_audit.py S1 --checklist ios --capture-to captures/S1.capture
python3 scripts/l2_stig_audit.py S1 --checklist ios --from-capture captures/S1.capture

# An IOS XE switch needs no flag - that checklist is the default.
python3 scripts/l2_stig_audit.py SW01 --from-capture captures/SW01.capture

# Write the verdicts into a STIG Viewer 3 checklist instead of retyping 64
# rules. NOT AUTOMATED becomes not_reviewed, never not_a_finding.
# See docs/STIG-VIEWER.md.
python3 scripts/l2_stig_audit.py SW01 --from-capture captures/SW01.capture \
    --to-cklb checklists/out/SW01.cklb

# Give --to-cklb a directory and the audit names the file itself, e.g.
# SW01_06AUG2026_L2S_V3R2_NDM_V3R6.cklb - so a re-run on the same day
# overwrites rather than piling up.
python3 scripts/l2_stig_audit.py SW01 --from-capture captures/SW01.capture \
    --to-cklb checklists/out

# Redact a capture so it can leave the network. Refuses to write at all if
# anything it recognises as sensitive survives the pass.
python3 scripts/sanitize_capture.py captures/SW01.capture
python3 scripts/sanitize_capture.py captures/SW01.capture --also-redact "PROJECT NAME"

# Addressing from places other than a config: the ARP table of a subinterface,
# and a diagram someone sent as a PDF.
python3 scripts/arp_inventory.py R1 --interface Gi0/0.100 -o vlan100.csv
python3 scripts/arp_inventory.py R1 --from-file pasted-arp.txt --interface Gi0/0.100
python3 scripts/pdf_ips.py diagram.pdf -o addressing.csv
python3 scripts/pdf_ips.py diagram.pdf --all-text   # what it saw, when an answer looks wrong

# Fleet-sized: capture_l2s_bulk.py walks every saved SecureCRT session and
# leaves one checklist per switch. Where that machine cannot run the audit it
# collects captures instead, audited elsewhere in one pass (Windows cmd).
for %f in (C:\captures\*.capture) do ^
    python scripts/l2_stig_audit.py %~nf --from-capture "%f" --to-cklb C:\Documents\checklists

# Scoping the walk per distribution node leaves one CSV per node. Merge them
# into one file, deduplicated to each switch's newest row.
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

`--to-cklb` is a flag on the audit, not a separate conversion step: one run produces
both the printed report and the checklist file. The end-to-end walkthrough on Windows —
collect, audit, open, and what a re-run does to anything typed into STIG Viewer — is in
[`docs/STIG-VIEWER.md`](docs/STIG-VIEWER.md).

## Notes

- Devices are defined in `inventory.yaml` by name, host, and Netmiko `device_type` (e.g. `cisco_ios`, `cisco_nxos`). Every address in `inventory.yaml.example` is written `x.x.x.x` so that no real addressing is committed, even as an example - replace them after copying. Until `management_subnet` is a real network, V-220575/523 reports `not a network` rather than a verdict; `--management-subnet 10.0.0.0/24` overrides it for a one-off run.
- Backups are written to `backups/`, with dated copies in `backups/archive/`.
- The L2 audit prints, above the report, which VLANs it classified as user VLANs and which it skipped and why. A VLAN wrongly excluded there produces no finding at all - DHCP snooping and DAI coverage is simply never asked about it - so the list is the only place that omission is visible. Any VLAN even one user can reside on belongs in it; `user_vlan_names` in `inventory.yaml` is how to put it there, and it overrides any ID exclusion. Entries are exact names, or globs where they carry a wildcard - `"*user"`, `"*user[0-9]*"`, `"*tel"` - which is how a fleet that calls the same role `army-xxx-abc-user1` on VLAN 800 at one site and `army-yyy-def-user15` on VLAN 850 at the next is described once rather than switch by switch. Where names are site-then-role, one pattern per role (users, voice) covers every switch; matching the site prefix instead (`"army-xxx-abc-*"`) also works but takes the management VLAN with it. The classification names the pattern that matched each VLAN, so a pattern reaching further than intended is visible in the report.
- STIG rules requiring external infrastructure (a configuration-backup server) or manual/topology review are reported NOT AUTOMATED rather than guessed at. Where a rule turns out to be answerable from what the switch already says — a self-signed trustpoint for the PKI rule, `show version` for the supported-release rule, MQC for the QoS rule — it is answered instead; see [`docs/DESIGN.md`](docs/DESIGN.md).
- `l2_stig_harden_ipsg.py` and `l2_stig_harden_dai.py` both only trust the DHCP snooping binding table — a statically-addressed host with no DHCP lease is invisible to either and can have its traffic dropped once they're pushed. Confirmed live. If a statically-addressed host (e.g. the automation host itself) is directly connected to a device, consider skipping one or both scripts for that device until this has a real fix.
- Scripts that push config append a JSON-line audit record (timestamp, script, device, username, commands) to `audit_logs/audit.log`. Not tracked in git.
- Several STIG-required commands don't exist or function on this lab's `vios_l2` image — see [`docs/DESIGN.md`](docs/DESIGN.md) for the list and why the scripts still push them.

