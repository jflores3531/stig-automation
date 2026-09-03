# Ansible replication of the STIG hardening scripts

Ansible roles/playbooks that replicate the bulk STIG hardening passes the
Python scripts perform, using `cisco.ios` and `cisco.nxos` instead of
Netmiko:

| Role | Replicates | Target group |
|---|---|---|
| `l2s_stig_harden` | `../l2_stig_harden_global.py` + `_interfaces.py` | `l2_switches` |
| `l2s_stig_harden_aaa` | `../l2_stig_harden_aaa.py` | `l2_switches` |
| `l2s_stig_harden_acl` | `../l2_stig_harden_acl.py` | `l2_switches` |
| `l2s_stig_harden_ipsg` / `_dai` | `../l2_stig_harden_ipsg.py` / `_dai.py` | `l2_switches` |
| `nxos_stig_harden` | `../nxos_stig_harden_global.py` + `_interfaces.py` | `nxos_switches` |
| `nxos_stig_harden_aaa` | `../nxos_stig_harden_aaa.py` | `nxos_switches` |
| `stig_audit` | shells out to the `*_stig_audit.py` scripts | both |

Lives alongside the Python scripts on purpose - apart from `stig_audit`,
which deliberately shells out rather than reimplementing audit logic,
nothing here touches `../netauto.py` or any of the `*_stig_harden*.py`
scripts, and the two toolchains can be run independently (built for
interview/portfolio purposes, not because this project's small lab actually
needs a second toolchain - see the "Why this exists" section below).

## Status: confirmed working live

Run successfully end-to-end against **S1** and **S3** (2026-07-24) -
`failed=0` on both, with the expected `ignored` tasks matching known
`vios_l2` platform limitations (see "Confirmed-rejected commands" below).
**S2** wasn't fully tested (it lacked `aaa new-model` at the time, which is
no longer something this role even attempts - see V-220623 below), but
should now run clean there too since that dependency was removed from
scope entirely.

Every fix here (like every fix on the Python side this session) was found
by running it live against a real device and reading the actual response,
not assumed from documentation.

`l2s_stig_harden_aaa` was confirmed live on **S1** (2026-08-12):
`ok=8 changed=0 failed=0 skipped=3`, both in `--check` and for real, and
`changed=0` on a repeat run. S1 was already fully converged from prior
`l2_stig_harden_aaa.py` runs, so what this proves is the *detection* half -
every presence gate correctly skipped, and `ios_config` found no diff on the
lines it did evaluate:

- the `enable secret` task skipped (S1 already has one), confirming the
  hash-versus-cleartext gate works rather than re-pushing forever
- the `meta: reset_connection` verification **passed against a real device** -
  a full fresh SSH login plus re-escalation with `ansible_become_pass`, which
  is the mechanism the whole role's safety argument rests on
- both `radius server RADIUS<n>` blocks skipped, confirming the same gate on
  the `key 7 <encrypted>` problem
- `aaa new-model`, both method lists, the dot1x globals and the
  `aaa common-criteria policy` block all reported no change - including
  `aaa common-criteria policy`, which is a permanent ceiling on this lab's IOS
  *Router* image but is accepted on `vios_l2`

What it does **not** prove: the push path on an unconverged switch. Nothing was
actually sent, so the ordering guarantees (RADIUS servers before the method
lists, `aaa new-model` atomic with them) have not been exercised live by the
role - only by the Python script they were ported from.

**S2 is the device to prove it on, and its state is confirmed (2026-08-12):**
`no aaa new-model`, no enable secret, no RADIUS servers, no dot1x, no password
policy. It is reachable and healthy - it simply never had this config, having
had `aaa new-model` reverted after the lockout incident that shaped this whole
role. S3 was checked at the same time and is converged, identical to S1, so it
would only repeat S1's result.

That makes S2 the only L2 switch that can exercise the push path, and the run
would be a real one: pushing the enable secret, proving it via
`meta: reset_connection`, defining both RADIUS blocks, and sending
`aaa new-model` plus the method lists atomically. Deliberately not yet done.

If/when it is: the L2S role is the safer of the two to do it with, because it
verifies **before** the risky change, so a failed verification aborts with
nothing to roll back and the device holding only a new enable secret. Have the
S2 console open anyway - that is how the original incident was recovered.

`nxos_stig_harden_aaa` was confirmed live on **NXCore1** (2026-08-12):
`ok=12 changed=0 failed=0 skipped=3`, twice consecutively, with no task
reporting changed.

Getting there took the right ordering. NXCore1 turned out **not** to be
converged - it had `aaa group server radius RADIUS_GROUP` with a single server
and no `aaa authentication login default` line at all, meaning
`nxos_stig_harden_aaa.py` had never completed against it and something older or
manual had configured what was there. So this would have been the device's
first-ever login-auth flip, which is exactly the case this README says to give
to the Python script rather than the role, because only the script holds the
pre-change session open as a rollback channel.

That is what was done: `nxos_stig_harden_aaa.py` performed the first flip
(its second-connection verify passed), and the role was then run against the
converged device. Note that dry-running the role first would **not** have
de-risked anything - in `--check` the auth change is never pushed, so the
"Verify a brand-new login succeeds" task passes against an unchanged device
and proves nothing. `--check` is close to worthless for this specific role.

The run also caught a real idempotency bug, now fixed: the RADIUS
timeout/retransmit task reported `changed` on every run because
`radius-server retransmit 1` is the NX-OS **default**, and plain
`show running-config` omits default-valued lines - so `nxos_config` could never
find it. It now diffs against `show running-config all`, the same fix the
`nxos_stig_harden` role's `global.yml` already carried for five other lines.
The lesson had been learned once in this repo and not applied here.

Left alone deliberately: `aaa group server radius RADIUS_GROUP` is still on the
device, now orphaned alongside `RADIUS_SERVERS`. Neither toolchain references
it. Worth cleaning up, but not something either was asked to do.

The `nxos_stig_harden` role's live status is also not recorded here, despite
the commit history showing a series of idempotency fixes that could only have
come from real runs against NXCore1.

## Setup notes (things that weren't obvious the first time)

- **`group_vars` must live adjacent to the inventory file**
  (`inventory/group_vars/`), not just anywhere under `ansible/`. Ansible only
  auto-discovers `group_vars`/`host_vars` next to the inventory file or next
  to the playbook - anywhere else is silently ignored, which caused every
  vault/group-var-gated task to skip on the first live run with no error at
  all, just silent empty values.
- **`ansible-core` must be the pip install, not the distro package.** This
  project needs `ansible-core 2.13.13` (`pip3 install 'ansible-core==2.13.13'`,
  the newest a Python 3.8 host takes). Ubuntu also ships `ansible 2.9.6` as an
  apt package at `/usr/bin/ansible`, and if that ends up first on `PATH`,
  **every network module fails** with:

  ```
  ConnectionError: deprecated() got an unexpected keyword argument 'date'
  ```

  `Display.deprecated()` only gained its `date` parameter in ansible-base
  2.10, and `ansible.netcommon` 2.x+ calls it. The error surfaces from the
  persistent connection process, so it reads as a role or collection bug
  rather than a version mismatch - three `cisco.nxos` versions were pinned and
  unpinned chasing it before anyone ran `ansible --version`.

  **Check the interpreter before debugging anything else:**

  ```
  ansible --version    # want: ansible [core 2.13.13], /usr/local/bin/ansible
  ```

  Two quick tells that you are on the 2.9 package: `ansible-galaxy collection
  list` errors with `invalid choice: 'list'` (that subcommand arrived in 2.10),
  and the traceback paths read `/usr/lib/python3/dist-packages/ansible` rather
  than `/usr/local/lib/python3.8/dist-packages/ansible`.
- **`pip install ansible-core` can leave `packaging` uninstalled.** pip counts
  setuptools' *vendored* copy (`.../setuptools/_vendor/packaging`) as
  satisfying the dependency, but that path never lands on `sys.path`, so
  `ansible-galaxy` fails with:

  ```
  ERROR! Failed to import packaging, check that a supported version is installed
  ```

  `pip3 install packaging` reports "already satisfied" and changes nothing.
  Force it and verify by import, not by pip:

  ```
  pip3 install --ignore-installed packaging
  python3 -c "import packaging; print(packaging.__file__)"   # must NOT say setuptools/_vendor
  ```
- **`meta/runtime.yml` is necessary but not sufficient.** `cisco.nxos:4.4.0`
  declares `requires_ansible >=2.9.10`, which looks compatible with 2.9.6 and
  is not - the real constraint came from netcommon, one layer down. Check the
  declared requirement, then actually run the playbook against a device.
- **Pin `ansible.netcommon` explicitly**, even though the platform collections
  pull it in. Left implicit, it is free to drift to a version incompatible
  with the installed core, and it takes every platform down with it when it
  does. There is no version bind that works on 2.9.6: netcommon 2.x+ needs
  >=2.10, while netcommon 1.x lacks the `plugin_utils` that `cisco.ios:4.4.0`
  imports.
- **`ios_config` treats a rejected CLI command as fatal**, unlike Netmiko's
  `send_config_set()` (which just includes the error text in its output and
  keeps sending the rest of the batch). Every command already confirmed
  rejected on this lab's `vios_l2` is split into its own
  `ignore_errors: true` task, separate from
  commands that should actually succeed and fail loud if they don't -
  bundling a known-bad command into a bigger batch silently drops every
  command after it in that same task, not just the bad one.

## What's covered

Everything in `l2_stig_harden_global.py`'s current state except V-220629/V-220641a
(below) and V-220623's global prerequisites (moved out of scope entirely,
see below):

- All global (non-interface-specific) `BASE_FIXES`/`UNNECESSARY_SERVICES_FIX`/
  `ARCHIVE_LOGGING_FIX`/`SSH_ENCRYPTION_FIX`/`VTY_SESSION_LIMIT_FIX`/
  `CONSOLE_EXEC_TIMEOUT_FIX`
- VTP password, dual syslog servers, NTP (time sync + authentication),
  SNMPv3 auth/priv
- Native/default-access VLAN database creation - uses the `cisco.ios.ios_vlans`
  **resource module** (state-based: `config: [{vlan_id, name}, ...]` +
  `state: merged`) instead of raw `ios_config` lines, as a demonstration of
  that style. Everything else in this role still uses raw `ios_config` -
  most of the bulk pass has no matching resource module at all (narrow,
  STIG-specific commands aren't general-purpose config domains Cisco built
  structured support for)
- DHCP snooping, scoped to genuinely-discovered user VLANs (mirrors
  `stig_common.discover_user_vlans()` - excludes `non_user_vlans` and the
  reserved 1002-1005 VLAN range)
- Interface-scoped access vs. trunk classification (same rule as
  `parse_switchports()`: trunk only if `switchport mode trunk` is present),
  with the matching per-bucket fixes: PortFast/UUFB/storm-control
  (speed-scaled, FastEthernet skipped)/802.1x-MAB (per-port only, see below)
  for access ports; static-trunk/DHCP-snooping-trust/DAI-trust/allowed-
  VLAN-scoping/native-VLAN for trunk ports

### Confirmed-rejected commands (ignore_errors, kept for real hardware)

Same platform limitations catalogued in the main README's Notes section:
`mls qos`, `file privilege 15`, three of the
unnecessary-services lines (`no ip dns server`/`no ip identd`/`no service
call-home`), UUFB (`switchport block unicast`), the per-port 802.1x/MAB
commands, and storm control. All rejected outright on this lab's `vios_l2`,
correct commands for real hardware.

## What's deliberately NOT covered

- **V-220629 (Root Guard)** - `l2_stig_harden_global.py` discovers this switch's
  live STP root port(s) first (`stig_common.discover_root_port_interfaces`)
  and excludes them, because pushing Root Guard to your own root port forces
  it into root-inconsistent/blocking state - a real outage, not a
  theoretical risk. Doing that safely in Ansible needs either a custom
  filter/module to parse `show spanning-tree` structurally, or accepting a
  less precise heuristic. Left out rather than guessing.
- ~~**V-220641a (disabled ports -> unused VLAN)**~~ - **now implemented**, on
  both platforms (V-220641a on L2S, V-220690 on NX-OS). See "Disabled ports"
  below.
- **V-220675/679 per-port 802.1x on NX-OS** - `nxos_stig_harden_interfaces.py`
  pushes `dot1x port-control auto`/`dot1x host-mode single-host` per access
  port (gated on IPSG being inactive, since Nexus 9000 refuses `feature dot1x`
  while IPSG is enabled). The `nxos_stig_harden` role never ported that pass.
  The *globals* now have an Ansible path via `nxos_stig_harden_aaa`, but the
  per-port half still does not - run the Python script for those. This is an
  asymmetry with the L2S role, which does push its per-port V-220623
  equivalents.

### Previously not covered, now closed

- **V-220623a/b (dot1x system-auth-control + AAA method list)** - these two
  global commands need `aaa new-model` already active to be valid syntax at
  all (confirmed live: rejected on S2, which doesn't have it, succeeded on
  S1/S3, which do from prior `l2_stig_harden_aaa.py` runs). They had no
  Ansible path at all while there was no equivalent of
  `l2_stig_harden_aaa.py` to receive them. The `l2s_stig_harden_aaa` role now
  pushes them in the same atomic task as `aaa new-model` itself, so the
  prerequisite is guaranteed active. The per-port V-220623 commands
  (`authentication port-control auto`/`dot1x pae authenticator`/`mab`) stay in
  `l2s_stig_harden`, matching `l2_stig_harden_global.py`'s scope exactly.

## The vty management ACL (V-220575/V-220581) - and why NX-OS has no role

`l2s_stig_harden_acl` pushes the vty management ACL scoped to the automation
host, with `log-input` on the trailing deny. Its own playbook, never part of the
bulk pass:

```
ansible-playbook playbooks/l2s_harden_acl.yml -e ansible_user=admin --ask-pass --limit S1
```

**`nxos_stig_harden_acl.py` (V-220479) has no Ansible counterpart, deliberately.**
Not an oversight and not "not done yet" - the mechanism that makes the L2S role
safe does not exist on NX-OS.

### The rollback problem, and what actually solves it

Both Python ACL scripts apply the access-class, verify with a *second*
connection, and revert through the still-open *primary* session if that fails.
Ansible cannot do this: `meta: reset_connection` destroys the pre-change session
in order to test a genuinely fresh login, so a `rescue` block would have to
reconnect through the very ACL that just locked it out.

For the AAA roles that weakness was tolerable - NX-OS's `fallback error local`
is on by default, and the L2S AAA role verifies *before* its risky change. **A
vty ACL has neither escape.** If the automation host's IP is not permitted, the
lockout is immediate and total, and nothing falls back.

`reload in <n>` is the mechanism Ansible *can* offer, and it is arguably
stronger than the Python's, because **it needs no connectivity to fire**. The
role arms it before applying the ACL and cancels it only after a fresh
connection proves access still works. If anything goes wrong in between -
lockout, aborted play, dead controller - the device reloads on its own and comes
back on its last saved configuration, without the ACL.

That last clause is load-bearing, and it works because of a convention this
project already holds: `../docs/DESIGN.md` deliberately never saves config
during a push, precisely so a reload is a recovery path. **Do not save the
running config on a target between applying and verifying** - the reload would
then restore the lockout rather than clear it.

NX-OS has no `reload in`. `feature scheduler` could approximate it, but that
would mean introducing an unverified mechanism into the single riskiest role in
the repo - the same trap the `nxos_logging_global` history warns about. Until
there is a device to prove it against, V-220479 stays Python-only.

### Status: confirmed live on S3 (2026-08-12)

Three consecutive runs, `ok=16 changed=2 failed=0` each. The full safety cycle
was exercised on a real device: armed, verified armed, ACL applied, fresh
connection verified, cancelled, verified disarmed - with an independent
`show reload` check after each run confirming nothing was left scheduled.

`changed=2` on every run is the arm and the cancel, which are actions rather
than configuration, so this role never reports `changed=0`. The tasks that
*should* converge - the ACL and the access-class - do.

Three bugs were found by running it, none of which offline validation would
have caught:

- **The save prompt comes first.** `reload in 5` asks
  `System configuration has been modified. Save? [yes/no]` *before*
  `Proceed with reload? [confirm]`. The first version handled only the
  confirmation and hung until the command timeout. Worse than the hang: an
  implementation that answered the first prompt with "yes" would have written
  the ACL to startup-config, so a later reload would have *restored* the lockout
  rather than cleared it - a safety net that looks armed while protecting
  nothing. It is answered `no`, always, and `check_all: true` is what allows
  both prompts to be answered.
- **The ACL line never matched.** IOS column-aligns ACL entries, storing
  `deny   ip any any log-input` with three spaces. The single-spaced form meant
  `ios_config` re-pushed on every run forever. Same class of bug as
  `storm-control broadcast level 40.00` and `spanning-tree portfast edge`.
- **`reload cancel` answers asynchronously.** Its
  `*** --- SHUTDOWN ABORTED ---` banner is unsolicited output that breaks prompt
  detection - intermittently for the cancel itself, and reliably for whatever
  ran next. The cancel now tolerates the error and the following check runs on a
  fresh connection, because the authoritative question is not "did the command
  return cleanly" but "is a reload still scheduled".

### Never run this role with --check

The role asserts against it. `ios_command` executes its commands even under
`--check`, because the module is declared read-only and Ansible believes it -
but `reload in` is not read-only. A check-mode run would arm a real reload on a
real device while every `ios_config` around it did nothing, including the task
that cancels it.

And even ignoring that, `--check` proves nothing here: the access-class is never
applied, so "verify a fresh connection works" succeeds against a device that was
never at risk. Same false-assurance property documented for the NX-OS AAA role,
and the same lesson the V-220690 bug taught - a clean `--check` on a role whose
risk *is* the push tells you nothing.

## Disabled ports (V-220641a / V-220690)

Both bulk roles now park administratively-shut ports on the designated unused
VLAN. The two platforms need genuinely different implementations, which is why
this stayed unported longest:

| | L2S (V-220641a) | NX-OS (V-220690) |
|---|---|---|
| Detection | `shutdown` in the running-config block | `disabled` in `show interface status`, minus ambiguous rows |
| Scope | access-classified ports | ports otherwise about to be trunk-converted |
| Extra round trip | none | yes, the status table |

**Why NX-OS needs the extra step, and why running-config cannot substitute.**
IOS renders `shutdown` in the interface block and that settles it. On NX-OS
`shutdown` is the **default** state of a physical port, so plain
`show running-config` omits it entirely and renders only the non-default
`no shutdown`.

This was found the hard way. The first implementation cross-checked the status
table against a `shutdown` line in running-config, on the reasoning that two
signals are safer than one. Confirmed live on NXCore1 (2026-08-12) that the
cross-check matched **zero** ports on a switch with **59** disabled ones -
`Ethernet1/5` is administratively down and its config block reads only
`switchport` / `switchport access vlan 1000`. It silently reduced V-220690 to a
permanent no-op, and the `--check` run looked completely clean while doing so.
Same default-value trap as `radius-server retransmit 1` in the AAA role.

**How false positives are handled instead.** The status table's Name column is
free text, so an interface whose *description* contains "disabled" matches - and
a false positive here parks a live port on a black-hole VLAN, an outage rather
than a failed audit. The guard uses the one source that does carry the truth: a
row misread through its description still shows its *real* status on the same
line, so any port also matching a non-disabled status (`connected`,
`suspended`, `notconnect`, `err-disabled`, …) is treated as ambiguous and
dropped. That fails safe - ambiguous ports are left alone rather than
blackholed.

Validated against NXCore1's real status output with a false-positive row
injected: 59 genuinely disabled ports detected, the injected
`spare disabled bay` / `connected` row correctly excluded, and `suspended` and
`err-disabled` ports correctly not matched.

**Why the L2S role reorders its own tasks.** `l2_stig_harden_interfaces.py`
pushes the default access VLAN to every access port and then overrides it for
the disabled subset. That is harmless with Netmiko, which never diffs, but two
Ansible tasks written that way fight each other - both report `changed` forever
and genuinely rewrite the VLAN twice per run. The role excludes disabled ports
from the default-VLAN loop instead and gives them their own task, reaching the
same end state without the churn.

**Not yet run live.** The logic was rendered and checked offline against sample
`show interface status` and running-config, including the false-positive cases
above, but neither platform's version has been applied to a device. On NXCore1
this would be a real push if any trunk-target port is shut.

## The AAA roles

`l2s_stig_harden_aaa` and `nxos_stig_harden_aaa` are separate roles with
separate playbooks, not part of the bulk hardening run. Same reason the Python
keeps `*_stig_harden_aaa.py` out of `*_stig_harden_global.py`: this is the one
pass that changes how SSH login itself is authenticated. Bundling it with the
~60-command bulk pass is what dropped a live session on S2 mid-push and left
the switch half-configured and SSH-inaccessible (recovered via console +
`no aaa new-model`).

```
ansible-playbook playbooks/l2s_harden_aaa.yml  --ask-vault-pass -e ansible_user=admin --ask-pass --limit S1
ansible-playbook playbooks/nxos_harden_aaa.yml --ask-vault-pass -e ansible_user=admin --ask-pass --limit NXCore1
```

Run one device at a time and confirm you can open a fresh SSH session to it
before moving on. Console access is the backstop.

### How the safety net compares to the Python

Neither role can fully reproduce its script's protection, and they fall short
in different places - worth understanding before a first run.

**L2S - equivalent, arguably stronger.** `l2_stig_harden_aaa.py` pushes
`enable secret` and proves it works with a `disable` -> `enable` round-trip on
the same Netmiko session before touching `aaa new-model`. Ansible has no way to
drive that round-trip, so the role uses `meta: reset_connection` instead: the
persistent connection is destroyed and the next task must complete a full fresh
SSH login *and* re-escalate with `ansible_become_pass`. That is a broader test
than the Python's, and it happens **before** any AAA task runs, so the abort
ordering is identical - a failed verification leaves the device with nothing
but the new enable secret.

For that check to mean anything, what gets pushed and what Ansible escalates
with have to be the same value, so `group_vars` binds both `enable_secret` and
`ansible_become_pass` to a single `vault_enable_secret`. They cannot drift.

**NX-OS - genuinely weaker.** `nxos_stig_harden_aaa.py` pushes the auth change,
opens a *second* Netmiko connection to prove new logins still work, and reverts
through the still-open *primary* session if it doesn't. That primary session is
the guarantee: it predates the change and survives it.

Ansible has no equivalent. `meta: reset_connection` is a real second-connection
test, but it destroys the pre-change session to perform it, so nothing is left
to revert through. The role's `rescue` block still attempts a revert and will
succeed for a transient or partial failure - but a genuine lockout fails there
too, and recovery is via console.

The risk is smaller than it sounds, for the reason the Python's own docstring
gives: DISA's V-220513 Fix Text pushes no `local` keyword in the method list,
because NX-OS has a separate `fallback error local` mechanism that Check
Content confirms is **on by default**. Neither the script nor this role ever
disables it. Still - for a first application to a device whose console you
can't reach quickly, prefer `nxos_stig_harden_aaa.py`. The role is the better
choice for re-runs against already-converged devices, where the auth change is
a no-op and the exposure window never opens.

### Idempotency: why the secret-bearing tasks are presence-gated

Both platforms store these credentials in a form that never matches what was
sent - `enable secret` as a type-5/8/9 hash, and the RADIUS key as `key 7
<encrypted>` once `service password-encryption` is active (which the L2S bulk
role turns on, so it is the normal state on every device targeted here).
`ios_config`/`nxos_config` compare literal strings, so pushing either
unconditionally reports `changed` on every run and re-sends a no-op forever.

There is no AAA resource module in `cisco.ios` 4.4.0 to sidestep this the way
`ios_vlans`/`nxos_ntp_global` do elsewhere in this project, so both roles gate
these tasks on the config line being **absent** instead. That buys idempotency
at the cost of never picking up a *changed* value, so each role exposes a flag
for deliberate rotation:

```
ansible-playbook playbooks/l2s_harden_aaa.yml -e radius_force_update=true
ansible-playbook playbooks/l2s_harden_aaa.yml -e enable_secret_force_update=true
```

(`cisco.nxos` does ship `nxos_aaa_server_host`, which compares state rather
than strings and would handle the RADIUS key properly. It is deliberately not
used yet: it is untested against this lab, and the riskiest role in the repo is
the wrong place to introduce an unverified module - the `nxos_logging_global`
schema saga in the commit history is what that costs. Worth revisiting once
there is a device to prove it against.)

### Ordering difference from the Python

Both roles define the RADIUS servers **before** flipping authentication, which
is the one place `l2s_stig_harden_aaa` does not follow
`l2_stig_harden_aaa.py`'s command order. The Python sends `aaa new-model` and
the dot1x globals first and the RADIUS blocks after - safe there because it is
all one `send_config_set()`, i.e. one config session. Splitting across Ansible
tasks means separate sessions, so the order is inverted to make sure
`group radius` is never referenced by a method list before it has members.

For the same reason, `aaa new-model` and both method lists are sent in **one**
`ios_config` task. That is not cosmetic: the S2 lockout happened because the
session dropped after `aaa new-model` took effect but before the method lists
landed. Keeping them in a single task preserves the atomicity Netmiko's
`send_config_set()` gives the Python. Do not split that task.

## Why this exists

This project's Python/Netmiko toolchain already works well on the lab these
roles were built against (7-8 devices, one person maintaining it) - this
isn't "better," it's a second, independently-working implementation of the
same STIG logic, built to demonstrate Ansible experience. The real reasons
organizations prefer Ansible are mostly about team/hiring standardization,
inventory management at much larger scale, and vendor-maintained low-level
plumbing - not because it's technically superior to a well-tested custom
toolchain for a setup this size.

Note where that argument stops. The deployment target these scripts were
written for is several hundred switches on a host that can install nothing
- no Ansible, no collections, not even netmiko or pyyaml - reached through
SecureCRT and audited from captures. Everything here needs an install host,
so none of it runs there. Scale is the usual argument for Ansible over a
custom toolchain, and on the one fleet this project actually has to cover,
scale is not what decides it.

## Prerequisites

On a fresh host (Ubuntu 20.04, Python 3.8, confirmed working sequence):

```bash
apt install -y python3-venv python3-pip sshpass
python3 -m venv .venv && source .venv/bin/activate
pip install --upgrade pip
pip install -r ../requirements.txt   # Netmiko/PyYAML, same venv as the Python scripts
pip install ansible
ansible-galaxy collection install -r requirements.yml
```

Fill in real values in `inventory/group_vars/l2_switches/vault.yml` (see the
adjacent `vault.yml.example` for the full list - the AAA roles add
`vault_radius_key`, and the L2S one also needs `vault_enable_secret`), then
encrypt it - **never commit real secrets in plaintext**:

```
ansible-vault encrypt inventory/group_vars/l2_switches/vault.yml
```

## Running it

```
ansible-playbook playbooks/l2s_harden.yml --ask-vault-pass -e ansible_user=admin --ask-pass
```

(or supply credentials however your setup prefers - `--ask-pass` prompts for
the SSH password, matching this project's "never hardcode credentials"
convention on the Python side). Add `--limit S1` (or `S2`/`S3`) to target
just one device.
