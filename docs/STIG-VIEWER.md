# Getting a report into STIG Viewer 3

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
