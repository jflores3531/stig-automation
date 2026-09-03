#!/usr/bin/env python
"""Shared helpers for connecting to devices in inventory.yaml: inventory loading,
device-name validation, credential prompting, and Netmiko SSH connection handling."""

import json
import os
import re
from datetime import datetime
from getpass import getpass

import yaml

# netmiko is imported inside connect(), not here. Everything else in this
# module is file/inventory handling, and the offline audit path
# (l2_stig_audit.py --from-capture) never opens a connection - deferring the
# import lets that path run on a machine with only Python installed - yaml.py
# covers the import above - which is exactly the situation on the work machine
# where captures are collected via SecureCRT and neither netmiko nor pyyaml can
# be installed at all.

# Every path below is anchored to the directory this file lives in, not the
# caller's working directory, so the scripts behave the same wherever they're
# run from (cron, an IDE run config, another checkout).
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))

INVENTORY_PATH = os.path.join(PROJECT_ROOT, 'inventory.yaml')
SECRETS_PATH = os.path.join(PROJECT_ROOT, 'secrets.yaml')
BACKUP_DIR = os.path.join(PROJECT_ROOT, 'backups')
AUDIT_LOG_PATH = os.path.join(PROJECT_ROOT, 'audit_logs', 'audit.log')


def load_inventory(path=INVENTORY_PATH):
    """Load the devices section of the YAML inventory (name -> {host, device_type})."""
    with open(path) as f:
        inventory = yaml.safe_load(f)
    return inventory['devices']


def load_services(path=INVENTORY_PATH):
    """Load the services section of the YAML inventory (ntp_servers/syslog_servers/
    radius_servers -> list of IPs). Returns an empty dict if the inventory has no
    services section, so callers can .get(...) with a default."""
    with open(path) as f:
        inventory = yaml.safe_load(f)
    return inventory.get('services', {})


def load_non_user_vlans(path=INVENTORY_PATH, device_name=None):
    """Load the non_user_vlans list from the YAML inventory - VLAN IDs to exclude
    when discovering "user VLANs" for DHCP snooping/DAI pushes (management,
    servers, unused default VLAN, etc). The same VLAN ID doesn't always mean the
    same thing on every device (e.g. VLAN 10 is a management segment on the L2S
    access switches but a real dot1x-authenticated endpoint VLAN on NXCore1) -
    if device_name is given and has an entry in non_user_vlans_by_device, that
    device-specific list is returned instead of the shared default. Returns an
    empty list if nothing is defined."""
    with open(path) as f:
        inventory = yaml.safe_load(f)
    overrides = inventory.get('non_user_vlans_by_device', {})
    if device_name and device_name in overrides:
        return overrides[device_name]
    return inventory.get('non_user_vlans', [])


def load_non_user_vlan_names(path=INVENTORY_PATH):
    """Load the non_user_vlan_names list from the YAML inventory - VLAN *names*
    to exclude when discovering user VLANs. For a fleet where the same purpose
    carries a different VLAN ID on each switch but the same name everywhere,
    which is the common case once there is more than one site: VLAN 10 is
    management here and a user VLAN there, while both are called MGMT.

    Complements non_user_vlans rather than replacing it - a VLAN is non-user if
    its ID or its name matches. Returns an empty list if nothing is defined, in
    which case discovery behaves exactly as it did before names existed."""
    with open(path) as f:
        inventory = yaml.safe_load(f)
    return inventory.get('non_user_vlan_names', [])


def load_user_vlan_names(path=INVENTORY_PATH):
    """Load the user_vlan_names list from the YAML inventory - VLAN *names* that
    are always user VLANs, whatever ID they carry on a given switch. The user
    and voice VLANs are the ones that move: each site numbers them with whatever
    was free, while calling them the same thing everywhere.

    A name here overrides the non_user_vlans ID list, which is what makes it
    useful - a switch whose user VLAN is 10 is still audited for DHCP snooping
    and DAI coverage even though 10 is the management VLAN on other switches and
    is therefore in that list. Returns an empty list if nothing is defined."""
    with open(path) as f:
        inventory = yaml.safe_load(f)
    return inventory.get('user_vlan_names', [])


def load_management_subnet(path=INVENTORY_PATH):
    """Load the management_subnet string (e.g. '10.10.50.0/24') from the YAML
    inventory, used to verify vty access-class ACLs are actually scoped to the
    management network (V-220575). Returns None if not defined."""
    with open(path) as f:
        inventory = yaml.safe_load(f)
    return inventory.get('management_subnet')


def load_automation_host(path=INVENTORY_PATH):
    """Load the automation_host IP from the YAML inventory - the sole
    permitted source for V-220575's vty ACL (l2_stig_harden_acl.py). Returns
    None if not defined."""
    with open(path) as f:
        inventory = yaml.safe_load(f)
    return inventory.get('automation_host')


def load_unused_vlan(path=INVENTORY_PATH):
    """Load the unused_vlan ID from the YAML inventory - the VLAN designated for
    disabled/unused ports (V-220641). Returns None if not defined."""
    with open(path) as f:
        inventory = yaml.safe_load(f)
    return inventory.get('unused_vlan')


def load_vtp_domain(path=INVENTORY_PATH):
    """Load the vtp_domain name from the YAML inventory - required on NX-OS
    before a VTP password can be set (V-220676); 'vtp password' is rejected
    with "Domain not set" without one first, confirmed live on NXCore1.
    Returns None if not defined."""
    with open(path) as f:
        inventory = yaml.safe_load(f)
    return inventory.get('vtp_domain')


def load_native_vlan(path=INVENTORY_PATH):
    """Load the native_vlan ID from the YAML inventory - the VLAN to assign as
    native on 802.1q trunk links (V-220646). Returns None if not defined."""
    with open(path) as f:
        inventory = yaml.safe_load(f)
    return inventory.get('native_vlan')


def load_default_access_vlan(path=INVENTORY_PATH):
    """Load the default_access_vlan ID from the YAML inventory - the VLAN
    assigned to host-facing/access ports that aren't already in trunk mode.
    Returns None if not defined."""
    with open(path) as f:
        inventory = yaml.safe_load(f)
    return inventory.get('default_access_vlan')


def load_external_interfaces(device_name, path=INVENTORY_PATH):
    """Load the list of external-facing interface names for a router from the
    YAML inventory's external_interfaces_by_device section - a security-
    boundary/topology fact (see docs/Topology.png) that can't be derived from a
    device's own config, used by ios_router_audit.py for STIG rules scoped to
    "external" vs "internal" interfaces. Returns an empty list if the device
    has no entry (all its active interfaces are treated as internal)."""
    with open(path) as f:
        inventory = yaml.safe_load(f)
    return inventory.get('external_interfaces_by_device', {}).get(device_name, [])


def load_secrets(path=SECRETS_PATH):
    """Load plaintext secrets used by the *_stig_harden.py scripts (VTP password,
    NTP auth key, etc.) from secrets.yaml - gitignored, never committed. Returns
    an empty dict if the file doesn't exist (see secrets.yaml.example)."""
    if not os.path.exists(path):
        return {}
    with open(path) as f:
        return yaml.safe_load(f) or {}


def get_credentials():
    """Prompt for the SSH username/password used to connect to devices.
    Checks SSH_USERNAME/SSH_PASSWORD env vars first - set by the Ansible
    stig_audit role via `environment:` (not CLI flags) so a fleet-wide run
    only prompts once instead of once per device. Falls back to interactive
    prompts for standalone script use."""
    username = os.environ.get('SSH_USERNAME') or input('Enter your SSH username: ')
    password = os.environ.get('SSH_PASSWORD') or getpass()
    return username, password


def require_devices(all_devices, device_names):
    """Look up device_names in all_devices, exiting with an error if any are unknown."""
    unknown = [name for name in device_names if name not in all_devices]
    if unknown:
        print(f'Device(s) not found in inventory.yaml: {", ".join(unknown)}')
        raise SystemExit(1)
    return {name: all_devices[name] for name in device_names}


def connect(device_name, device_info, username, password, purpose=None):
    """Connect to a device from the inventory, escalating to privileged EXEC
    with secrets.yaml's enable_secret if one is set. Needed now that AAA
    governs login on devices with 'aaa new-model' active - a local account's
    privilege 15 stopped being honored automatically on login once that was
    pushed, landing SSH sessions at user EXEC instead. .enable() is a no-op if
    the session is already privileged, so this is safe to call unconditionally
    against devices that don't have AAA active yet too. Returns the Netmiko
    connection, or None (after printing why) if the connection or enable
    escalation failed.

    purpose labels the connection in the console output. Several scripts open a
    second session against the same device on purpose (live discovery, or
    verifying new logins still work), and without a label the repeated
    'Connecting to device: X' reads like a failed retry."""
    # Deferred so the offline audit path works without netmiko installed -
    # see the note at the top of this file.
    from netmiko import ConnectHandler
    from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException
    from paramiko.ssh_exception import SSHException

    if purpose:
        print(f'Opening a second session to {device_name} ({purpose})')
    else:
        print('Connecting to device: ' + device_name)
    enable_secret = str(load_secrets().get('enable_secret') or '').strip()
    ios_device = {
        'device_type': device_info['device_type'],
        'ip': device_info['host'],
        'username': username,
        'password': password,
        # Netmiko's ~10s default conn_timeout is shorter than IOS's own AAA
        # login can take when a RADIUS server is unreachable (login
        # authentication falls through radius -> local *during* the SSH
        # password exchange, not after it) - confirmed live as a ~30s login
        # delay that made valid credentials look like a connection failure.
        # l2_stig_harden_aaa.py tightens RADIUS timeout/retransmit to keep
        # that fallback short, but this stays generous as a safety margin.
        'conn_timeout': 60,
        'auth_timeout': 60,
        'banner_timeout': 60,
    }
    if enable_secret:
        ios_device['secret'] = enable_secret

    try:
        net_connect = ConnectHandler(**ios_device)
    except NetmikoAuthenticationException:
        print('Authentication failure: ' + device_name)
        return None
    except NetmikoTimeoutException:
        print('Timeout to device: ' + device_name)
        return None
    except EOFError:
        print('End of file while attempting device ' + device_name)
        return None
    except SSHException:
        print('SSH Issue. Are you sure SSH is enabled? ' + device_name)
        return None
    except Exception as unknown_error:
        print('Some other error: ' + str(unknown_error))
        return None

    if enable_secret:
        try:
            net_connect.enable()
        except Exception as enable_error:
            print(f'Failed to reach privileged EXEC on {device_name}: {enable_error}')
            net_connect.disconnect()
            return None

    return net_connect


# Commands pushed by the *_stig_harden*.py scripts embed real credentials -
# the enable secret, the RADIUS shared key, SNMPv3 auth/priv passwords, the NTP
# MD5 key, the VTP password. The audit log records what ran, when, and by whom;
# it has no need for the credential itself, and audit_logs/ is plain text on
# whichever host ran the script. Each pattern captures the keyword that
# introduces a secret so only the value after it is masked.
_SECRET_PATTERNS = [
    # The optional '<n>' is the encryption type, and skipping past it matters
    # for reading config back rather than pushing it. A push sends
    # 'enable secret <plaintext>', but running-config renders
    # 'enable secret 5 $1$abc$...' - so without this the pattern masked the
    # harmless type digit and printed the hash. Type 5 is MD5-crypt and
    # crackable offline; type 8/9 are stronger but still not for publishing.
    re.compile(r'(?i)\b(enable secret\s+(?:\d+\s+)?)(\S+)'),
    re.compile(r'(?i)\b(vtp password\s+)(\S+)'),
    # Local account credentials, which only show up when reading config back -
    # no script here pushes a username line. 'show running-config' renders
    # 'username admin privilege 15 secret 5 $1$...', and that hash is the
    # password for the very account these scripts authenticate with, so it is
    # the last thing that should land in a transcript. Covers both 'secret' and
    # 'password', with or without an encryption-type digit, and tolerates the
    # optional 'privilege <n>' that sits between the name and the keyword.
    re.compile(r'(?i)\b(username\s+\S+(?:\s+privilege\s+\d+)?\s+(?:secret|password)\s+(?:\d+\s+)?)(\S+)'),
    re.compile(r'(?i)\b(md5\s+)(\S+)'),
    re.compile(r'(?i)\b(auth\s+(?:sha|md5)\s+)(\S+)'),
    re.compile(r'(?i)\b(priv\s+(?:aes|3des|des)(?:-\d+)?(?:\s+\d+)?\s+)(\S+)'),
    # The RADIUS shared key is a bare 'key <value>' inside a 'radius server'
    # block. Anchored to start-of-line, or just past a device prompt, so it
    # matches in a Netmiko echo ('S1(config-radius-server)#key ...') without
    # touching 'ntp trusted-key 1' or 'auth-port'/'acct-port'.
    re.compile(r'(?i)(?:^|(?<=#))(\s*key\s+)(\S+)\s*$'),
    # The same secret in NX-OS's classic single-line form, which the anchored
    # pattern above cannot see: the key sits mid-line with more text after it,
    # so it is neither at start-of-line nor at end-of-line.
    #
    #   radius-server host 192.168.100.10 key 7 "<secret>" authentication accounting
    #
    # This gap disclosed the real RADIUS key in a session transcript on
    # 2026-08-12, via a `show running-config | include radius` through an
    # ad-hoc show command. Note that `key 7` does NOT mean the value is safe to
    # print - NX-OS rendered the key in readable form regardless.
    #
    # Deliberately scoped to radius-server lines rather than matching any
    # 'key <value>': a general pattern also mangles 'crypto key generate rsa'
    # and similar, and over-redacting a general-purpose show command makes its
    # output untrustworthy in a different way. Optional '<n>' covers the
    # encryption-type digit; the value itself may be quoted, which \S+ keeps.
    re.compile(r'(?i)(radius-server\s+(?:host\s+\S+\s+)?key\s+(?:\d+\s+)?)(\S+)'),
    # IOS confirms a redundant VTP push by repeating the password back.
    re.compile(r'(?i)^(Password already set to\s+)(\S+)'),
]


def redact_secrets(command):
    """Mask credential values in a config command so it can be safely logged
    or printed. Keeps the command shape intact ('enable secret ****') so the
    record still shows what was configured, just not the value."""
    for pattern in _SECRET_PATTERNS:
        command = pattern.sub(lambda m: m.group(1) + '****', command)
    return command


def redact_output(text):
    """Redact a device session transcript line by line. Netmiko echoes back
    everything that was sent - including the credentials - plus the device's
    own confirmations that repeat them, so printing raw output discloses just
    as much as printing the command list did."""
    return '\n'.join(redact_secrets(line) for line in str(text).splitlines())


def log_push(script_name, device_name, username, commands):
    """Append a JSON-line audit record for a config push to audit_logs/audit.log.
    Credential values are masked - see redact_secrets()."""
    os.makedirs(os.path.dirname(AUDIT_LOG_PATH), exist_ok=True)
    record = {
        'timestamp': datetime.now().isoformat(timespec='seconds'),
        'script': script_name,
        'device': device_name,
        'username': username,
        'commands': [redact_secrets(str(c)) for c in commands],
    }
    with open(AUDIT_LOG_PATH, 'a') as f:
        f.write(json.dumps(record) + '\n')
