# $language = "Python3"
# $interface = "1.0"

"""Add TACACS+ servers to one switch, remove them from it, or take them out of
the server group, as declared in inventory.yaml's `tacacs` section. Run from
the one session that is already open (Script > Run...). tacacs_bulk.py does
the same across every saved session once this has been seen to work on one
switch.

READ THIS FIRST - THIS SCRIPT CONFIGURES THE SWITCH
It writes to running-config. It shows the TACACS+ configuration as it is now
and the exact commands it will send, with the key masked, and sends nothing
until you say Yes. It never writes startup-config: until someone saves, a
reload puts the switch back as it was.

WHAT IT DOES NOT TOUCH
`aaa new-model` and the login method lists (`aaa authentication login ...`).
Those decide how people log in, and getting them wrong is a lockout, so they
stay as they are. A switch without `aaa new-model` is skipped: a server group
cannot exist without it, and turning it on is l2_stig_harden_aaa.py's job.

WHERE THE SETTINGS COME FROM
inventory.yaml's `tacacs` section:

  group_name           the `aaa group server tacacs+ <name>` the added servers
                       join and `remove_from_group` takes servers out of.
  add                  addresses to define as `tacacs server` and put in the
                       group. One already defined (by any name, or as a legacy
                       `tacacs-server host`) is reused, its key left as it is,
                       and only joined to the group.
  remove               addresses to remove from the switch completely: out of
                       every TACACS+ group first, then the definition.
  remove_from_group    addresses to take out of group_name only. The server
                       definition stays, so it can still be used elsewhere.
  server_name_prefix   names the new servers: the prefix and the lowest number
                       not already a server name on THAT switch - TACACS1,
                       TACACS2, ... A re-run finds what the last run added by
                       its address, so it is never added twice.
  timeout              optional seconds per server; null leaves the default.

An address listed in two of add / remove / remove_from_group is refused before
anything is sent: the run cannot tell which one you meant.

The shared key is `tacacs_key` in secrets.yaml, read from beside inventory.yaml.
It is needed only when `add` lists something. It is never shown in a dialog or
written to the log, but it IS typed to the switch, so a SecureCRT session log
left on records it the same as typing it by hand would.

THE LOCKOUT GUARD
A switch where the push would leave a group that a login method list uses
with NO servers is skipped, with nothing sent. `group TACGRP local` with an
empty TACGRP falls back to local only if local accounts exist and work; that
is a decision for a person at the console, not for this run.

THE VERDICT
From the TACACS+ configuration read back after the push, not from the
commands having been accepted:

  completed   every added server is defined (new ones with a key) and in the
              group, every removed server is gone from the switch, and every
              server taken out of the group is out of it. No command rejected.
  failed      something was sent and the read-back disagrees.
  skipped     nothing was sent: no aaa new-model, or the lockout guard.

The same row is written to a CSV in OUTPUT_DIR.
"""

import ipaddress
import json
import os
import os.path
import re
import time

# `crt` is injected by SecureCRT into this script's globals, not into the
# modules it imports - so those get it handed over at the bottom of this file.
crt = globals().get('crt')

import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cklb_collect
import cklb_collect_bulk as bulk
import harden_bulk as harden
import snmp_acl as snmp

# SecureCRT keeps one Python running between script runs and imports a module
# only once - see snmp_acl.py for why each helper is reloaded here.
if crt is not None:
    import importlib
    for _module in (cklb_collect, bulk, harden, snmp):
        _module.crt = None
        importlib.reload(_module)


# Where the run log is written. Created if missing.
OUTPUT_DIR = r'C:\Documents\netauto_tacacs'

LOG_COLUMNS = ('hostname', 'ip_address', 'outcome', 'reason', 'added', 'removed',
               'removed_from_group', 'warnings', 'servers_after', 'session', 'timestamp')

COMPLETED = 'completed'
FAILED = 'failed'
SKIPPED = 'skipped'

DEFAULT_PREFIX = 'TACACS'
KEY_MASK = '********'

# The default group every defined server belongs to, used as `group tacacs+`.
DEFAULT_GROUP = 'tacacs+'


class TacacsError(Exception):
    """A setting or a switch state that makes the push wrong. `.reason` is the
    short form for a log row; str() is the full text for a dialog."""

    def __init__(self, reason, message):
        Exception.__init__(self, message)
        self.reason = reason


# ---------------------------------------------------------------------------
# Settings.
# ---------------------------------------------------------------------------

class Settings:
    def __init__(self, group, add, remove, remove_from_group, prefix=DEFAULT_PREFIX,
                 timeout=None, key=''):
        self.group = group
        self.add = list(add)
        self.remove = list(remove)
        self.remove_from_group = list(remove_from_group)
        self.prefix = prefix
        self.timeout = timeout
        self.key = key

    def next_name(self, taken):
        """The prefix and the lowest number not in `taken` - TACACS1, TACACS2.
        Compared without case: a name differing only in case is too easy to
        mistake for the existing server when reading the config."""
        used = {str(name).lower() for name in taken}
        number = 1
        while '{0}{1}'.format(self.prefix, number).lower() in used:
            number += 1
        return '{0}{1}'.format(self.prefix, number)


def _addresses(section, field):
    raw = section.get(field)
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise TacacsError(
            'tacacs.{0} not a list'.format(field),
            'inventory.yaml tacacs.{0} must be a LIST of addresses, e.g.\n'
            '  "{0}": ["192.0.2.5", "192.0.2.6"]\nA bare string would be read one character '
            'at a time.'.format(field))
    found = []
    for entry in raw:
        text = str(entry).strip()
        try:
            address = ipaddress.IPv4Address(text)
        except ValueError:
            raise TacacsError(
                'bad address in tacacs.{0}'.format(field),
                'inventory.yaml tacacs.{0} has {1!r}, which is not an IPv4 address. '
                'The placeholder x.x.x.x has to be replaced with a real one.'.format(field, text))
        if str(address) not in found:
            found.append(str(address))
    return found


def load_config(section, key=''):
    """Settings from the inventory's tacacs section and the key from secrets.
    Every bad shape stops the run before anything is sent."""
    section = section or {}
    if not isinstance(section, dict):
        raise TacacsError('tacacs not a mapping',
                          'inventory.yaml `tacacs` must be a mapping - see inventory.yaml.example.')
    add = _addresses(section, 'add')
    remove = _addresses(section, 'remove')
    remove_from_group = _addresses(section, 'remove_from_group')
    if not (add or remove or remove_from_group):
        raise TacacsError(
            'nothing declared',
            'inventory.yaml tacacs.add, tacacs.remove and tacacs.remove_from_group are all '
            'empty, so there is nothing to do.')

    for first, second, a, b in (('add', 'remove', add, remove),
                                ('add', 'remove_from_group', add, remove_from_group),
                                ('remove', 'remove_from_group', remove, remove_from_group)):
        both = [ip for ip in a if ip in b]
        if both:
            raise TacacsError(
                'address in two lists',
                '{0} is in both tacacs.{1} and tacacs.{2}. Each address belongs in one of '
                'them only.'.format(', '.join(both), first, second))

    group = str(section.get('group_name') or '').strip()
    if (add or remove_from_group) and not group:
        raise TacacsError('no tacacs.group_name',
                          'inventory.yaml needs tacacs.group_name - the `aaa group server '
                          'tacacs+` that added servers join and remove_from_group leaves.')
    if group and (not re.match(r'^[A-Za-z0-9_.-]+$', group) or group.lower() == DEFAULT_GROUP):
        raise TacacsError('bad tacacs.group_name',
                          'tacacs.group_name {0!r} must be one word of letters, digits, _ . - '
                          'and not tacacs+ itself.'.format(group))

    prefix = str(section.get('server_name_prefix') or DEFAULT_PREFIX).strip()
    if not re.match(r'^[A-Za-z][A-Za-z0-9_-]*$', prefix):
        raise TacacsError('bad tacacs.server_name_prefix',
                          'tacacs.server_name_prefix {0!r} must be one word starting with a '
                          'letter.'.format(prefix))

    timeout = section.get('timeout')
    if timeout is not None:
        bad = TacacsError('bad tacacs.timeout',
                          'tacacs.timeout must be whole seconds, 1 to 1000, or null; got {0!r}.'
                          .format(timeout))
        if isinstance(timeout, bool):
            raise bad
        try:
            timeout = int(timeout)
        except (TypeError, ValueError):
            raise bad
        if not 1 <= timeout <= 1000:
            raise bad

    key = str(key or '').strip()
    if add:
        if not key or key == 'CHANGE_ME':
            raise TacacsError(
                'no tacacs_key',
                'tacacs.add lists {0} server(s), and secrets.yaml has no tacacs_key. A server '
                'added without the shared key cannot authenticate anyone.'.format(len(add)))
        # `?` is IOS's help key - typed into a key it prints help instead.
        if '?' in key or re.search(r'\s', key):
            raise TacacsError('tacacs_key cannot be typed',
                              'secrets.yaml tacacs_key contains a space or a `?`, which the '
                              'switch CLI would not take as part of the key.')
    return Settings(group, add, remove, remove_from_group, prefix, timeout, key)


def read_secret(path, name):
    """One top-level scalar from secrets.yaml with the standard library.

    The file is YAML with comments (see secrets.yaml.example) and PyYAML cannot
    be installed where SecureCRT runs, so this reads `name: value` lines rather
    than the whole format. A JSON secrets file is read as JSON."""
    try:
        with open(path, encoding='utf-8') as handle:
            text = handle.read()
    except OSError:
        return ''
    try:
        data = json.loads(text)
        return str(data.get(name) or '') if isinstance(data, dict) else ''
    except ValueError:
        pass
    for line in text.splitlines():
        match = re.match(r'^{0}\s*:\s*(.*)$'.format(re.escape(name)), line)
        if match:
            value = match.group(1).strip()
            if value[:1] in ('"', "'"):
                quote = value[0]
                end = value.find(quote, 1)
                return value[1:end] if end > 0 else value[1:]
            return re.sub(r'\s+#.*$', '', value).strip()
    return ''


def inventory_path():
    """The repository's inventory.yaml, if this folder is still inside it."""
    return os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        'inventory.yaml')


def read_settings(path):
    try:
        with open(path, encoding='utf-8') as handle:
            inventory = json.load(handle)
    except (OSError, ValueError) as error:
        raise TacacsError('inventory not readable', 'Could not read {0}:\n{1}'.format(path, error))
    secrets = os.path.join(os.path.dirname(os.path.abspath(path)), 'secrets.yaml')
    return load_config(inventory.get('tacacs'), read_secret(secrets, 'tacacs_key'))


def settings_from_inventory():
    """The settings, asking for the inventory's path only when it is not where
    the repository keeps it. Returns None if the person cancelled."""
    path = inventory_path()
    if not os.path.exists(path):
        path = crt.Dialog.Prompt(
            'inventory.yaml was not found beside this folder:\n  {0}\n\n'
            'Path to the inventory.yaml whose `tacacs` section to push\n'
            '(its secrets.yaml is read from the same folder):'.format(inventory_path()),
            'TACACS - inventory', '', False)
        if not path:
            return None
    return read_settings(path.strip().strip('"'))


# ---------------------------------------------------------------------------
# What the switch has.
# ---------------------------------------------------------------------------

class State:
    """The TACACS+ configuration of one switch."""

    def __init__(self):
        self.servers = {}       # name -> {'address': ip or None, 'key': bool}
        self.legacy = []        # `tacacs-server host <ip>` addresses
        self.groups = {}        # name -> [('name'|'ip'|'private', value)]
        self.new_model = False
        self.method_groups = set()

    def copy(self):
        other = State()
        other.servers = {name: dict(info) for name, info in self.servers.items()}
        other.legacy = list(self.legacy)
        other.groups = {name: list(members) for name, members in self.groups.items()}
        other.new_model = self.new_model
        other.method_groups = set(self.method_groups)
        return other

    def names_for(self, ip):
        return [name for name, info in self.servers.items() if info['address'] == ip]

    def defined(self, ip):
        return bool(self.names_for(ip)) or ip in self.legacy

    def member_entries(self, group, ip):
        """The lines of `group` that point at `ip`."""
        names = self.names_for(ip)
        return [(kind, value) for kind, value in self.groups.get(group, [])
                if (kind == 'name' and value in names) or (kind != 'name' and value == ip)]

    def in_group(self, group, ip):
        return bool(self.member_entries(group, ip))

    def group_size(self, group):
        if group.lower() == DEFAULT_GROUP:
            return len([n for n, i in self.servers.items() if i['address']]) + len(self.legacy)
        return len(self.groups.get(group, []))

    def addresses(self):
        found = [info['address'] for info in self.servers.values() if info['address']]
        return sorted(set(found + self.legacy), key=lambda ip: tuple(int(p) for p in ip.split('.')))


IPV4 = r'\d{1,3}(?:\.\d{1,3}){3}'


def parse_state(tacacs_section, aaa_lines):
    """State from `show running-config | section tacacs` and
    `show running-config | include ^aaa`."""
    state = State()
    server = group = None
    for raw in str(tacacs_section or '').splitlines():
        line = raw.rstrip()
        if not line.strip():
            continue
        if not line[0].isspace():
            server = group = None
            match = re.match(r'^tacacs server (\S+)', line)
            if match:
                server = match.group(1)
                state.servers[server] = {'address': None, 'key': False}
                continue
            match = re.match(r'^tacacs-server host ({0})\b'.format(IPV4), line)
            if match:
                if match.group(1) not in state.legacy:
                    state.legacy.append(match.group(1))
                continue
            match = re.match(r'^aaa group server tacacs\+ (\S+)', line)
            if match:
                group = match.group(1)
                state.groups.setdefault(group, [])
            continue
        text = line.strip()
        if server is not None:
            match = re.match(r'^address ipv4 ({0})\b'.format(IPV4), text)
            if match:
                state.servers[server]['address'] = match.group(1)
            elif re.match(r'^key\s+\S', text):
                state.servers[server]['key'] = True
        elif group is not None:
            match = re.match(r'^server name (\S+)', text)
            if match:
                state.groups[group].append(('name', match.group(1)))
                continue
            match = re.match(r'^server-private ({0})\b'.format(IPV4), text)
            if match:
                state.groups[group].append(('private', match.group(1)))
                continue
            match = re.match(r'^server ({0})\b'.format(IPV4), text)
            if match:
                state.groups[group].append(('ip', match.group(1)))

    for line in str(aaa_lines or '').splitlines():
        line = line.strip()
        if line == 'aaa new-model':
            state.new_model = True
        if re.match(r'^aaa (authentication|authorization|accounting)\b', line):
            state.method_groups.update(re.findall(r'\bgroup (\S+)', line))
    return state


# ---------------------------------------------------------------------------
# The plan: structured operations, rendered to commands and simulated, so the
# lockout guard judges exactly what would be sent.
# ---------------------------------------------------------------------------

GROUP_LINE = {'name': 'server name {0}', 'ip': 'server {0}', 'private': 'server-private {0}'}


def plan(state, settings):
    """[operation], in the order they are sent. Raises TacacsError for a switch
    the push would be wrong on."""
    if not state.new_model:
        raise TacacsError(
            'aaa new-model is off',
            'This switch does not have `aaa new-model`, and a TACACS+ server group cannot '
            'exist without it. Turning it on changes how everyone logs in - that is '
            'l2_stig_harden_aaa.py\'s job, not this one. Nothing was sent.')

    ops = []
    # 1. Out of the groups first: a server still named in a group is not one
    #    IOS lets you delete cleanly.
    for ip in settings.remove:
        for group in sorted(state.groups):
            for kind, value in state.member_entries(group, ip):
                ops.append(('group_remove', group, kind, value))
    for ip in settings.remove_from_group:
        for kind, value in state.member_entries(settings.group, ip):
            ops.append(('group_remove', settings.group, kind, value))
    # 2. Then the definitions.
    for ip in settings.remove:
        for name in state.names_for(ip):
            ops.append(('server_remove', name))
        if ip in state.legacy:
            ops.append(('legacy_remove', ip))
    # 3. New servers, then into the group.
    joins = []
    # Every name on the switch counts as taken, including one this run removes:
    # reusing it in the same push would make the log ambiguous about which
    # server TACACS1 was.
    taken = set(state.servers)
    for ip in settings.add:
        names = state.names_for(ip)
        if names:
            member = ('name', names[0])
        elif ip in state.legacy:
            member = ('ip', ip)
        else:
            # A free number, never an existing name: `tacacs server <existing>`
            # would REPLACE that server's address silently.
            name = settings.next_name(taken)
            taken.add(name)
            ops.append(('server_add', name, ip))
            member = ('name', name)
        if not state.in_group(settings.group, ip):
            joins.append(('group_add', settings.group) + member)
    ops += joins

    after = simulate(state, ops)
    for group in sorted(state.method_groups):
        if state.group_size(group) and not after.group_size(group):
            raise TacacsError(
                'would empty a login group',
                'This would leave `{0}` with no servers, and a method list uses it:\n  {1}\n\n'
                'Logins would then depend on whatever comes after it in that list. Nothing '
                'was sent - add a replacement server in the same run, or change the method '
                'list by hand first.'.format(group, ', '.join(sorted(state.method_groups))))
    return ops


def simulate(state, ops):
    after = state.copy()
    for op in ops:
        if op[0] == 'group_remove':
            members = after.groups.get(op[1], [])
            if (op[2], op[3]) in members:
                members.remove((op[2], op[3]))
        elif op[0] == 'server_remove':
            after.servers.pop(op[1], None)
        elif op[0] == 'legacy_remove':
            after.legacy = [ip for ip in after.legacy if ip != op[1]]
        elif op[0] == 'server_add':
            after.servers[op[1]] = {'address': op[2], 'key': True}
        elif op[0] == 'group_add':
            after.groups.setdefault(op[1], []).append((op[2], op[3]))
    return after


def commands(ops, settings, mask=False):
    """The config lines for `ops`. mask=True puts KEY_MASK in place of the key,
    for anything a person or a log file will see."""
    lines = []
    open_group = None

    def close():
        if open_group is not None:
            lines.append('exit')

    for op in ops:
        if op[0] in ('group_remove', 'group_add'):
            if op[1] != open_group:
                close()
                lines.append('aaa group server tacacs+ {0}'.format(op[1]))
                open_group = op[1]
            line = GROUP_LINE[op[2]].format(op[3])
            lines.append(('no ' + line) if op[0] == 'group_remove' else line)
            continue
        close()
        open_group = None
        if op[0] == 'server_remove':
            lines.append('no tacacs server {0}'.format(op[1]))
        elif op[0] == 'legacy_remove':
            lines.append('no tacacs-server host {0}'.format(op[1]))
        elif op[0] == 'server_add':
            lines += ['tacacs server {0}'.format(op[1]),
                      'address ipv4 {0}'.format(op[2]),
                      'key {0}'.format(KEY_MASK if mask else settings.key)]
            if settings.timeout is not None:
                lines.append('timeout {0}'.format(settings.timeout))
            lines.append('exit')
    close()
    return lines


def check_applied(state, settings, added_names):
    """Problems with the read-back, [] when it matches the declaration."""
    problems = []
    for ip in settings.add:
        if not state.defined(ip):
            problems.append('{0} is not defined after the push'.format(ip))
        elif not state.in_group(settings.group, ip):
            problems.append('{0} is not in {1}'.format(ip, settings.group))
    for name in added_names:
        info = state.servers.get(name)
        if info is not None and not info['key']:
            problems.append('tacacs server {0} has no key'.format(name))
    for ip in settings.remove:
        if state.defined(ip):
            problems.append('{0} is still defined'.format(ip))
        groups = [g for g in sorted(state.groups) if state.in_group(g, ip)]
        if groups:
            problems.append('{0} is still in {1}'.format(ip, ', '.join(groups)))
    for ip in settings.remove_from_group:
        if state.in_group(settings.group, ip):
            problems.append('{0} is still in {1}'.format(ip, settings.group))
    return problems


# ---------------------------------------------------------------------------
# One switch.
# ---------------------------------------------------------------------------

SHOW_TACACS = 'show running-config | section tacacs'
SHOW_AAA = 'show running-config | include ^aaa'


def read_state(prompt):
    return parse_state(cklb_collect.run_command(SHOW_TACACS, prompt),
                       cklb_collect.run_command(SHOW_AAA, prompt))


def rejected_lines(transcript, settings):
    """The switch's complaints, with the key masked - the transcript holds the
    command as typed."""
    found = snmp.rejected_lines(transcript)
    if settings.key:
        found = [line.replace(settings.key, KEY_MASK) for line in found]
    return found


class Result:
    def __init__(self, outcome, reason='', detail='', hostname=''):
        self.outcome = outcome
        self.reason = reason
        self.detail = detail
        self.hostname = hostname
        self.before = None
        self.after = None
        self.ops = []
        self.commands = []      # masked
        self.warnings = []

    def touched(self, kind):
        if kind == 'added':
            return '; '.join('{0} {1}'.format(op[1], op[2]) for op in self.ops
                             if op[0] == 'server_add')
        if kind == 'removed':
            return '; '.join(op[1] for op in self.ops if op[0] in ('server_remove',
                                                                     'legacy_remove'))
        return '; '.join('{0}: {1}'.format(op[1], op[3]) for op in self.ops
                         if op[0] == 'group_remove')


def render_state(state, group=None):
    if state is None:
        return '  (not read)'
    lines = []
    for name in sorted(state.servers):
        info = state.servers[name]
        lines.append('  tacacs server {0}  {1}{2}'.format(
            name, info['address'] or '(no address)', '' if info['key'] else '  NO KEY'))
    for ip in state.legacy:
        lines.append('  tacacs-server host {0}'.format(ip))
    for name in sorted(state.groups):
        mark = '  <- tacacs.group_name' if name == group else ''
        members = ', '.join(value for _kind, value in state.groups[name]) or '(empty)'
        lines.append('  group {0}: {1}{2}'.format(name, members, mark))
    if state.method_groups:
        lines.append('  used by login/method lists: ' + ', '.join(sorted(state.method_groups)))
    return '\n'.join(lines) or '  (no TACACS+ configuration)'


def apply(prompt, settings, confirm=None):
    """Read, plan, push and read back on the switch behind `prompt`.

    `confirm(result)` sees the plan before anything is sent and returns whether
    to go ahead; the bulk run passes None, having been confirmed once.

    Raises cklb_collect.CollectionError for a session that is not a usable
    switch; every TACACS+ problem comes back as a Result."""
    if not prompt.endswith('#'):
        raise cklb_collect.CollectionError(
            'user EXEC mode' if prompt.endswith('>') else 'unexpected prompt',
            'This session is not in privileged EXEC ({0}). Run "enable" first.'.format(prompt),
            'Not in enable mode')
    hostname = prompt.rstrip('#').strip()
    reply = cklb_collect.run_command('terminal length 0', prompt)
    wrong_device = cklb_collect.not_a_switch(reply)
    if wrong_device:
        raise cklb_collect.CollectionError(
            'not a Cisco switch: ' + wrong_device,
            'This session does not look like a Cisco switch:\n  {0}'.format(wrong_device),
            'Not a Cisco switch')

    result = Result(COMPLETED, hostname=hostname)
    result.before = read_state(prompt)
    try:
        result.ops = plan(result.before, settings)
    except TacacsError as error:
        result.outcome, result.reason, result.detail = SKIPPED, error.reason, str(error)
        return result

    absent = [ip for ip in settings.remove + settings.remove_from_group
              if not result.before.defined(ip)]
    if absent:
        result.warnings.append('not on this switch, nothing to remove: ' + ', '.join(absent))
    kept_key = [ip for ip in settings.add if result.before.defined(ip)]
    if kept_key:
        result.warnings.append('already defined, key left as it was: ' + ', '.join(kept_key))

    if not result.ops:
        result.after = result.before
        result.reason = 'already as declared - nothing sent'
        return result

    result.commands = commands(result.ops, settings, mask=True)
    if confirm is not None and not confirm(result):
        result.outcome, result.reason = SKIPPED, 'cancelled - nothing sent'
        return result

    transcript = harden.send_config(commands(result.ops, settings), prompt)
    rejected = rejected_lines(transcript, settings)

    result.after = read_state(prompt)
    added = [op[1] for op in result.ops if op[0] == 'server_add']
    problems = check_applied(result.after, settings, added)
    if rejected:
        problems.insert(0, 'rejected: ' + '; '.join(rejected))
    if problems:
        result.outcome, result.reason = FAILED, ' | '.join(problems)
        return result
    parts = []
    if settings.add:
        parts.append('{0} server(s) in {1}'.format(len(settings.add), settings.group))
    if settings.remove:
        parts.append('{0} removed from the switch'.format(len(settings.remove)))
    if settings.remove_from_group:
        parts.append('{0} out of {1}'.format(len(settings.remove_from_group), settings.group))
    result.reason = '; '.join(parts)
    return result


# ---------------------------------------------------------------------------
# The record.
# ---------------------------------------------------------------------------

class RunLog:
    """One row per switch, the same columns for the single run and the bulk one."""

    def __init__(self, directory, stem='tacacs_log_'):
        self.path = bulk.unused_path(directory, stem + time.strftime('%Y%m%d_%H%M%S'), '.csv')
        self.counts = {}
        self.warned = 0
        with open(self.path, 'w', encoding='utf-8') as handle:
            handle.write(','.join(LOG_COLUMNS) + '\n')

    def record(self, session_path, host, outcome, reason='', hostname='', result=None):
        self.counts[outcome] = self.counts.get(outcome, 0) + 1
        added = removed = ungrouped = warnings = after = ''
        if result is not None:
            sent = result.outcome != SKIPPED
            added = result.touched('added') if sent else ''
            removed = result.touched('removed') if sent else ''
            ungrouped = result.touched('ungrouped') if sent else ''
            warnings = '; '.join(result.warnings)
            if result.after is not None:
                after = '; '.join(result.after.addresses())
            if outcome == COMPLETED and result.warnings:
                self.warned += 1
        row = (hostname or session_path, host, outcome, reason, added, removed, ungrouped,
               warnings, after, session_path, time.strftime('%Y-%m-%d %H:%M:%S'))
        with open(self.path, 'a', encoding='utf-8') as handle:
            handle.write(','.join('"{0}"'.format(str(f).replace('"', "'")) for f in row) + '\n')


def make_log(directory, stem='tacacs_log_'):
    """A RunLog, or None with the reason if the folder cannot be written."""
    try:
        if not os.path.isdir(directory):
            os.makedirs(directory)
        return RunLog(directory, stem), ''
    except OSError as error:
        return None, str(error)


def describe(settings):
    """The declaration in a few lines, for the confirmation dialogs."""
    lines = []
    if settings.add:
        lines.append('Add to {0}: {1}'.format(settings.group, ', '.join(settings.add)))
    if settings.remove:
        lines.append('Remove from the switch: ' + ', '.join(settings.remove))
    if settings.remove_from_group:
        lines.append('Take out of {0}: {1}'.format(settings.group,
                                                    ', '.join(settings.remove_from_group)))
    return '\n'.join(lines)


# ---------------------------------------------------------------------------
# The single-switch run.
# ---------------------------------------------------------------------------

def confirm_dialog(result, settings):
    lines = ['{0}: TACACS+ as it is now:'.format(result.hostname),
             render_state(result.before, settings.group), '', describe(settings)]
    if result.warnings:
        lines += [''] + ['Note: ' + w for w in result.warnings]
    lines.append('\nCommands to send (key masked):\n'
                 + '\n'.join('  ' + c for c in result.commands))
    lines.append('\nThis writes to running-config. startup-config is NOT written.\n\nSend?')
    return crt.Dialog.MessageBox('\n'.join(lines), 'TACACS - confirm',
                                 snmp.MB_YESNO | snmp.MB_ICONWARNING) == snmp.IDYES


def report(result, settings):
    title = {COMPLETED: 'TACACS - COMPLETED', FAILED: 'TACACS - FAILED'}.get(
        result.outcome, 'TACACS - not changed')
    lines = ['Verdict for {0}: {1}'.format(result.hostname or 'this switch',
                                           result.outcome.upper()), '',
             result.detail or result.reason]
    if result.after is not None:
        lines += ['', 'TACACS+ now:', render_state(result.after, settings.group)]
    if result.warnings:
        lines += ['', 'Warnings:'] + ['  ' + w for w in result.warnings]
    if result.outcome == COMPLETED and result.ops:
        lines += ['', 'Nothing was written to startup-config. Test a TACACS+ login in a NEW '
                      'session before closing this one, then save. Once this switch looks '
                      'right, tacacs_bulk.py does the rest.']
    return title, '\n'.join(lines)


def main():
    if not crt.Session.Connected:
        crt.Dialog.MessageBox('Connect and log in to the switch first, then run this script.',
                              'Not connected')
        return
    try:
        settings = settings_from_inventory()
    except TacacsError as error:
        crt.Dialog.MessageBox('{0}\n\nNothing was sent.'.format(error), 'TACACS - inventory')
        return
    if settings is None:
        return

    crt.Screen.Synchronous = True
    try:
        try:
            prompt = cklb_collect.read_prompt()
            result = apply(prompt, settings,
                           confirm=lambda planned: confirm_dialog(planned, settings))
        except cklb_collect.CollectionError as refused:
            crt.Dialog.MessageBox('{0}\n\nNothing was sent.'.format(refused), refused.title)
            return

        log, why = make_log(OUTPUT_DIR)
        session = ''
        try:
            session = crt.Session.Path
        except Exception:
            pass
        if log is not None:
            log.record(session, '', result.outcome, result.reason, result.hostname, result)
        title, text = report(result, settings)
        text += ('\n\nLogged to:\n' + log.path) if log is not None \
            else '\n\nNot logged - could not write {0}: {1}'.format(OUTPUT_DIR, why)
        crt.Dialog.MessageBox(text, title)
    except Exception as error:  # surfaced in a dialog; SecureCRT hides tracebacks
        message = str(error)
        if settings.key:
            message = message.replace(settings.key, KEY_MASK)
        crt.Dialog.MessageBox(message, 'TACACS - error')
    finally:
        crt.Screen.Synchronous = False


# SecureCRT injects `crt` before running, so this is truthy there and None on a
# plain import - which is what lets the bulk walk and the tests import this.
if crt is not None:
    cklb_collect.crt = crt
    bulk.crt = crt
    harden.crt = crt
    snmp.crt = crt
    main()
