# STIG Automation — DISA STIG Compliance for Cisco Infrastructure

Python and Ansible tooling that **audits and remediates Cisco network devices against DISA STIG benchmarks** — the hardening standard required on U.S. Department of Defense networks. Built on [Netmiko](https://github.com/ktbyers/netmiko) over SSH for live runs — and on the standard library alone for the offline audit path, which is the one that runs where nothing can be installed.

Manually STIG-checking a single switch means checking ~65 rules by hand against the running-config, then doing it again after every change. The scripts I created automate the compliance check across three platforms, and pushes the fixes.

| Platform | DISA Benchmarks | Rules | Automated checks |
|---|---|---|---|
| Cisco IOS Switch | L2S + NDM | 65 | 61 |
| Cisco NX-OS Switch | L2S + NDM | 64 | 57 |
| Cisco IOS Router | NDM + RTR | 127 | 59 |

Rules needing external infrastructure (PKI, org-defined DoS safeguards) or topology/policy judgment are reported **NOT AUTOMATED** rather than guessed at — a false pass on a compliance tool is worse than no answer. Every rule check is coded against the STIG's literal Check Text, and every fix against its Fix Text.

Validated against a 7-device virtual lab (2 IOS routers, 3 IOSvL2 switches, 2 NX-OS cores). Ansible roles under [`ansible/`](ansible/) replicate the Python hardening for fleet-wide runs. See [`docs/DESIGN.md`](docs/DESIGN.md) for the reasoning behind script isolation, run order, and credential handling.

## What's here

### Shared
- **`netauto.py`** — Inventory loading, device-name validation, credential prompting, Netmiko SSH connection handling, automatic privilege escalation.
- **`inventory.yaml`** — Device inventory and STIG-hardening config (NTP/syslog/RADIUS server IPs, VLAN IDs, management subnet, automation host). No credentials. Written as JSON — see `yaml.py` — which parses under real PyYAML too, since JSON is a subset of YAML 1.2.
- **`secrets.yaml`** (gitignored) — Plaintext secrets for the `*_stig_harden*.py` scripts. Copy `secrets.yaml.example` to start.
- **`yaml.py`** — Stand-in for PyYAML on hosts where nothing can be installed: `safe_load` reads the inventory with the stdlib `json` parser. It shadows any real PyYAML present, which is harmless while `inventory.yaml` stays JSON — that parses under either.

### Backup & save
- **`backup_config.py`** — Back up running-config + VLANs; keeps a "latest" copy per device plus a timestamped archive pruned to 5.
- **`config_diff.py`** — Compare current running-config/VLANs against the last backup.
- **`save_config.py`** — Save running-config to startup-config on one device or all. Run it *after* a harden pass and its audit, not as part of one — see [`docs/DESIGN.md`](docs/DESIGN.md).

### Audit & hardening
- **`stig_common.py`** — Shared audit engine: loads a DISA `.cklb` checklist, checks the device against it, reports PASS/FAIL/NOT AUTOMATED by severity.
- **`securecrt/capture_l2s.py`** — Runs *inside* SecureCRT (Script → Run) against an already-open session, sending the five read-only show commands and writing a capture file — then, when it finds the repo next to itself, runs the audit and opens the report, making the whole flow one action: connect, run script, read report. Collection is standalone by design (no netmiko, no repo imports), and the offline audit itself needs only Python — `yaml.py` stands in for PyYAML and netmiko is imported lazily, only when a live connection is actually opened.
- **`securecrt/capture_l2s_bulk.py`** — The same collection unattended, across every saved SecureCRT session: connect, send the five commands, write a capture, disconnect. It never aborts — a switch that is offline, in a login quiet period or refusing credentials is logged and skipped, because on a fleet of hundreds not all of them answer on a given night. Deliberately separate from `capture_l2s.py`, which cannot connect to anything and so cannot be pointed at the wrong device; this one logs into every switch on its own authority, which is a materially different thing to put in front of whoever approved the tooling. Copy both files together — it imports the guards, command list and capture format from `capture_l2s.py` rather than duplicating them.
- **`capture.py`** — Offline auditing. Every check is a pure function of command output, so an audit can read a capture file instead of a switch — for networks where the tooling can't be pointed at the devices directly. A malformed, truncated or partial capture is refused rather than audited, since a check handed empty text returns a verdict just as confidently as one handed real config.
- **`l2_stig_audit.py`** — Audit against the IOS XE Switch L2S/NDM STIG (the default) or the IOS Switch one (`--checklist ios` — what the lab's vios_l2 switches are). Full interface-scoped coverage, live discovery for root ports/VTP/user VLANs. `--from-capture` audits collected output; `--capture-to` records a live run so the two can be compared.
- **`ios_xe_rule_map.py`** — The IOS and IOS XE switch STIGs share no rule IDs, but 58 of the IOS XE STIG's 64 rules are the same requirement as an IOS rule already checked here. This maps them, accepting a pair only when the literal "this is a finding" condition matches in both. Four rules are deliberately excluded and report NOT AUTOMATED — reusing their IOS check would answer a different question.
- **`nxos_stig_audit.py`** — Audit against the NX-OS Switch L2S/NDM STIG.
- **`ios_router_audit.py`** — Audit against the IOS Router NDM/RTR STIG. Most RTR rules need topology/policy context and report NOT AUTOMATED.
- **`l2_stig_harden_global.py`** — Bulk L2S hardening: BPDU/Loop Guard, Rapid-PVST, UDLD, IGMP + DHCP snooping, archive logging, VTP, per-port access/trunk hardening, NTP, syslog, SNMPv3. **Run first** — the other `l2_stig_harden_*.py` scripts depend on it.
- **`l2_stig_harden_ipsg.py`** — IP Source Guard (V-220634) on access ports. See Notes for the static-host caveat.
- **`l2_stig_harden_dai.py`** — Dynamic ARP Inspection (V-220635) on user VLANs. Same static-host caveat.
- **`l2_stig_harden_interfaces.py`** — Per-port L2S fixes split out of the bulk pass: access vs. trunk classification, UUFB, storm control, allowed-VLAN scoping, 802.1x/MAB.
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

**Offline audit — nothing installed, and nothing installable.** On the work machine neither netmiko nor PyYAML can be installed at all, so the offline path is written not to need them: `yaml.py` stands in for PyYAML, and netmiko is imported inside `netauto.connect()`, which an offline audit never calls. The SecureCRT collectors and `l2_stig_audit.py --from-capture` therefore run on a stock Python and nothing else — copy the files in and run them. This is the deployment target, not a fallback.

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

`devices` stays an empty object because `load_inventory()` indexes that key directly; captures are audited under whatever label you pass on the command line, so no switch needs an entry. `management_subnet` is **not** optional — with it absent the vty management ACL rule (V-220575, or V-220523 under the IOS XE checklist) reports FAIL on every device with the missing key as its reason, rather than a real verdict about the switch. `automation_host` is not needed here: only the `*_harden_acl.py` scripts read it, and those push config over a live connection. Every key is documented in [`inventory.yaml.example`](inventory.yaml.example).

**Live runs — Netmiko over SSH.** Only for scripts that actually open a connection: the `*_stig_harden*.py` pushes, live audits, and the backup/diff/save utilities. On a host where installs are possible:

```
pip install -r requirements.txt
```

The Ansible roles under [`ansible/`](ansible/) are in the same category — fleet runs from a machine that can install Ansible and its collections.

Copy `secrets.yaml.example` to `secrets.yaml` and fill in real values before running any `*_stig_harden*.py` script that needs them.

## Usage

Each script prompts for your SSH username and password via `getpass` (not echoed or stored).

```bash
# Back up one device or all devices
python3 backup_config.py R1
python3 backup_config.py

# Diff current running-config against last backup
python3 config_diff.py R1

# STIG audit. l2_stig_audit.py defaults to the IOS XE STIG (the deployment
# target); the lab's vios_l2 switches are IOS, hence --checklist ios there.
# The two STIGs share no rule IDs, so the wrong checklist reports every rule
# NOT AUTOMATED.
python3 l2_stig_audit.py S1 --checklist ios
python3 nxos_stig_audit.py NXCore1
python3 ios_router_audit.py R1

# Audit without connecting. Collect the five read-only show commands into a
# file - a logged terminal session works - then audit it from anywhere.
# --capture-to records a live run; auditing that file must give the same
# report, which is how the offline path is checked against a real switch.
python3 l2_stig_audit.py S1 --checklist ios --capture-to captures/S1.capture
python3 l2_stig_audit.py S1 --checklist ios --from-capture captures/S1.capture

# An IOS XE switch needs no flag - that checklist is the default.
python3 l2_stig_audit.py SW01 --from-capture captures/SW01.capture

# Fleet-sized: collect from every saved SecureCRT session by running
# securecrt/capture_l2s_bulk.py inside SecureCRT, then audit the lot in one
# pass. Collection and audit stay separate so a failed audit can't be
# mistaken for a failed capture. The loop below is Windows cmd, not bash.
for %f in (C:\captures\*.capture) do ^
    python l2_stig_audit.py %~nf --from-capture "%f" > "%~dpnf_report.txt"

# STIG hardening for an L2 switch - run in this order:
python3 l2_stig_harden_global.py S1 # bulk fixes, run first
python3 l2_stig_harden_ipsg.py S1   # IP Source Guard - can drop a statically-addressed host, see Notes
python3 l2_stig_harden_dai.py S1    # DAI - same static-host risk as IPSG, see Notes
python3 l2_stig_harden_acl.py S1    # vty management ACL - run isolated
python3 l2_stig_harden_aaa.py S1    # AAA/RADIUS + password policy - run last

# NX-OS hardening - global first, then the isolated scripts
python3 nxos_stig_harden_global.py NXCore1
python3 nxos_stig_harden_interfaces.py NXCore1
python3 nxos_stig_harden_acl.py NXCore1
python3 nxos_stig_harden_aaa.py NXCore1

# IOS router hardening - same order
python3 ios_router_stig_harden_global.py R1
python3 ios_router_stig_harden_urpf.py R1     # external-facing interfaces only
python3 ios_router_stig_harden_acl.py R1
python3 ios_router_stig_harden_aaa.py R1

# Persist the result - only after re-auditing and confirming it's what you wanted.
# Until this runs, a reload reverts the device, which is the escape hatch if a
# push locked you out.
python3 save_config.py NXCore1
python3 save_config.py            # or every device in the inventory

# Tests - no framework, no device needed
python3 tests/test_capture.py
python3 tests/test_ios_xe_map.py
python3 tests/test_securecrt_script.py
python3 tests/test_switchports.py
python3 tests/test_securecrt_bulk.py
```

## Notes

- Devices are defined in `inventory.yaml` by name, host, and Netmiko `device_type` (e.g. `cisco_ios`, `cisco_nxos`).
- Backups are written to `backups/`, with dated copies in `backups/archive/`.
- STIG rules requiring external infrastructure (org-defined DoS safeguards, PKI, IOS-version tracking) or manual/topology review are reported NOT AUTOMATED rather than guessed at.
- `l2_stig_harden_ipsg.py` and `l2_stig_harden_dai.py` both only trust the DHCP snooping binding table — a statically-addressed host with no DHCP lease is invisible to either and can have its traffic dropped once they're pushed. Confirmed live. If a statically-addressed host (e.g. the automation host itself) is directly connected to a device, consider skipping one or both scripts for that device until this has a real fix.
- Scripts that push config append a JSON-line audit record (timestamp, script, device, username, commands) to `audit_logs/audit.log`. Not tracked in git.
- Several STIG-required commands don't exist or function on this lab's `vios_l2` image — see [`docs/DESIGN.md`](docs/DESIGN.md) for the list and why the scripts still push them.

