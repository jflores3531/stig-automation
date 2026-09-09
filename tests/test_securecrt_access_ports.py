#!/usr/bin/env python
"""Verification for securecrt/harden_access_ports_bulk.py.

Run it directly: `python3 tests/test_securecrt_access_ports.py`. No framework,
no SecureCRT, no devices.

Nothing in securecrt/ may import from the wider repository - the folder is
copied to a machine that does not have it - so this script carries its own copy
of the port classifier, the template expander and the storm-control table. The
originals live in scripts/stig_common.py and
scripts/l2_stig_harden_access_ports.py.

Duplicated constants drift. Duplicated *logic* drifts silently, and the way it
would show up here is two tools disagreeing about which port is a trunk - one
auditing an uplink as an access port and the other configuring it as one. So
the first half of this suite runs both implementations over the same configs
and asserts they answer the same, rather than comparing source text.

The second half is about the thing that makes this script dangerous at all: it
sends `switchport mode access` and `spanning-tree portfast`. Sent to a trunk,
those collapse the uplink and put PortFast on a port that receives BPDUs as a
matter of course. Every check about templates below is really a check that this
cannot happen.
"""

import io
import os
import sys
import tempfile

PROJECT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(PROJECT, 'scripts'))
sys.path.insert(0, os.path.join(PROJECT, 'securecrt'))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import capture_l2s
import capture_l2s_bulk as bulk
import harden_access_ports_bulk as access
import stig_common
from fixtures import OUTPUTS

failures = []


def check(name, condition, detail=''):
    print(f'  {"ok  " if condition else "FAIL"} {name}')
    if not condition:
        if detail:
            print(f'       {detail}')
        failures.append(name)


def netmiko_access_script():
    """The helpers out of scripts/l2_stig_harden_access_ports.py, by executing
    its head - the script parses argv and connects at import."""
    path = os.path.join(PROJECT, 'scripts', 'l2_stig_harden_access_ports.py')
    source = open(path, encoding='utf-8').read().split('parser = argparse.ArgumentParser')[0]
    namespace = {'__name__': 'netmiko_access'}
    exec(compile(source, path, 'exec'), namespace)
    return namespace


# Every shape the classifier has to get right, in one config.
CONFIG = """interface GigabitEthernet1/0/1
 switchport mode access
 switchport access vlan 30
!
interface GigabitEthernet1/0/2
 source template USER-PORT
!
interface GigabitEthernet1/0/3
 switchport mode access
!
interface GigabitEthernet1/0/4
 switchport mode trunk
 switchport nonegotiate
!
interface GigabitEthernet1/0/8
 switchport mode access
 shutdown
!
interface GigabitEthernet1/0/9
 source template PARKED
!
interface GigabitEthernet1/0/10
 source template PARKED
 no shutdown
!
interface GigabitEthernet1/0/24
 source template UPLINK
!
interface FastEthernet0/1
 switchport mode access
!
interface TenGigabitEthernet1/1/1
 no switchport
 ip address 10.2.2.2 255.255.255.0
!
interface GigabitEthernet0/0
 vrf forwarding Mgmt-vrf
 ip address 10.1.1.1 255.255.255.0
!
interface Vlan10
 ip address 10.3.3.3 255.255.255.0
!
end
"""

BODIES = {
    'USER-PORT': ['switchport mode access', 'switchport access vlan 55'],
    'UPLINK': ['switchport mode trunk', 'switchport nonegotiate'],
    'PARKED': ['switchport mode access', 'shutdown'],
}

TEMPLATE_OUTPUT = {
    name: 'Template Name  : {0}\n----------------\n'.format(name)
          + '\n'.join(' ' + line for line in body) + '\nend\n'
    for name, body in BODIES.items()
}


def test_the_copies_answer_the_same_as_the_originals():
    print('the duplicated logic agrees with scripts/ on every shape')
    other = netmiko_access_script()

    check('the same ports are switchport-capable and Layer 3',
          access.switchport_names(CONFIG) == stig_common.switchport_names(CONFIG),
          (access.switchport_names(CONFIG), stig_common.switchport_names(CONFIG)))

    expanded_here = access.expand_interface_templates(CONFIG, BODIES)
    expanded_there = stig_common.expand_interface_templates(CONFIG, BODIES)
    check('template expansion produces the same config text',
          expanded_here == expanded_there)
    check('and the same classification off it',
          access.switchport_names(expanded_here) == stig_common.switchport_names(expanded_there),
          access.switchport_names(expanded_here))

    names = access.switchport_names(expanded_here)[0]
    check('the same access ports are read as shut',
          access.shutdown_access_ports(expanded_here, names)
          == other['shutdown_access_ports'](expanded_there, names),
          access.shutdown_access_ports(expanded_here, names))
    check('the same shut ports are flagged as template-overriding',
          access.templated_ports(CONFIG, names) == other['templated_ports'](CONFIG, names))

    check('the template names found in a config match',
          access.sourced_template_names(CONFIG)
          == __import__('capture').sourced_template_names(CONFIG),
          access.sourced_template_names(CONFIG))
    for name, output in TEMPLATE_OUTPUT.items():
        check(f'the {name} template body parses identically',
              access.parse_interface_template(output)
              == stig_common.parse_interface_template(output),
              access.parse_interface_template(output))

    check('the storm-control table matches, including the FastEthernet skip',
          all(access.storm_control_command(port) == other['storm_control_command'](port)
              for port in ('GigabitEthernet1/0/1', 'FastEthernet0/1', 'TenGigabitEthernet1/1/1',
                           'HundredGigE1/0/1', 'Port-channel1', 'Ethernet0/0')))
    check('the access fixes are the same three commands, in order',
          access.ACCESS_FIXES == ['switchport mode access', 'spanning-tree portfast',
                                  'switchport block unicast'],
          access.ACCESS_FIXES)


def test_a_templated_trunk_never_receives_an_access_command():
    """The whole reason this script reads templates. `switchport mode access`
    on an uplink collapses it, and PortFast there is the exact condition BPDU
    Guard exists to shut down."""
    print('\na trunk that gets its mode from a template is never configured as access')
    raw_access, raw_trunk = access.switchport_names(CONFIG)
    check('off the raw config the templated uplink IS in the access bucket - the bug',
          'GigabitEthernet1/0/24' in raw_access, raw_access)

    expanded = access.expand_interface_templates(CONFIG, BODIES)
    access_ports, trunk_ports = access.switchport_names(expanded)
    check('expanded, it is a trunk', 'GigabitEthernet1/0/24' in trunk_ports, trunk_ports)

    commands = access.port_commands(access_ports, [], None)
    check('so no command block is opened on it',
          'interface GigabitEthernet1/0/24' not in commands, commands)
    check('and the explicitly-configured trunk is untouched too',
          'interface GigabitEthernet1/0/4' not in commands, commands)
    check('no trunk command appears anywhere in the block',
          not any('trunk' in command or 'nonegotiate' in command for command in commands),
          [c for c in commands if 'trunk' in c])


def test_the_unused_vlan_lands_on_shut_ports_only():
    print('\nthe unused VLAN goes to shut access ports and nowhere else')
    expanded = access.expand_interface_templates(CONFIG, BODIES)
    access_ports, _ = access.switchport_names(expanded)
    shut = access.shutdown_access_ports(expanded, access_ports)
    check('the port shut in its own block is found', 'GigabitEthernet1/0/8' in shut, shut)
    check('so is the one shut by its template', 'GigabitEthernet1/0/9' in shut, shut)
    check('but not the one whose own block says `no shutdown`',
          'GigabitEthernet1/0/10' not in shut, shut)

    commands = access.port_commands(access_ports, shut, 999)
    blocks = {}
    current = None
    for command in commands:
        if command.startswith('interface '):
            current = command.split(' ', 1)[1]
            blocks[current] = []
        else:
            blocks[current].append(command)
    vlan_ports = [name for name, lines in blocks.items()
                  if 'switchport access vlan 999' in lines]
    check('exactly the shut ports get the VLAN line', sorted(vlan_ports) == sorted(shut),
          (vlan_ports, shut))
    check('every access port still gets the three base fixes',
          all(all(fix in lines for fix in access.ACCESS_FIXES) for lines in blocks.values()),
          blocks)
    check('FastEthernet gets no storm control',
          not any('storm-control' in line for line in blocks['FastEthernet0/1']),
          blocks['FastEthernet0/1'])
    check('a gigabit port does', any('storm-control' in line
                                     for line in blocks['GigabitEthernet1/0/1']))
    check('with no unused VLAN, no port gets a VLAN line',
          not any('switchport access vlan' in c
                  for c in access.port_commands(access_ports, shut, None)))


def test_an_unreadable_template_stops_that_switch():
    """A template the switch will not describe is a set of ports whose mode is
    unknown. Guessing means configuring an uplink as an access port, so the
    switch is skipped and logged instead."""
    print('\na template the switch will not describe skips that switch')

    class Screen:
        def __init__(self, answers):
            self.answers = answers
            self.Synchronous = False

        def Send(self, text):
            self.last = text.rstrip('\r\n')

        def ReadString(self, _terminator, _timeout=None):
            return self.last + '\r\n' + self.answers.get(self.last, '') + '\r\n'

    class Stub:
        def __init__(self, answers):
            self.Screen = Screen(answers)

    good = dict(TEMPLATE_OUTPUT)
    capture_l2s.crt = Stub({access.TEMPLATE_COMMAND_PREFIX + n: v for n, v in good.items()})
    try:
        bodies = access.read_interface_templates(CONFIG, 'SW#')
        check('all three templates are read when the switch answers',
              sorted(bodies) == ['PARKED', 'UPLINK', 'USER-PORT'], sorted(bodies))
    finally:
        capture_l2s.crt = None

    capture_l2s.crt = Stub({access.TEMPLATE_COMMAND_PREFIX + 'UPLINK': '% Template not found'})
    try:
        access.read_interface_templates(CONFIG, 'SW#')
        check('an unreadable template raises rather than being skipped past', False)
    except capture_l2s.CollectionError as refused:
        check('an unreadable template refuses the switch',
              'unreadable' in refused.reason, refused.reason)
        check('and the reason names which template',
              'USER-PORT' in refused.reason or 'UPLINK' in refused.reason
              or 'PARKED' in refused.reason, refused.reason)
    finally:
        capture_l2s.crt = None


def test_the_unused_vlan_is_read_from_inventory_when_it_is_there():
    print('\nthe unused VLAN comes off inventory.yaml when the repo is beside this')
    with tempfile.TemporaryDirectory() as tmpdir:
        good = os.path.join(tmpdir, 'good.yaml')
        io.open(good, 'w', encoding='utf-8').write('{"unused_vlan": 999, "devices": {}}')
        check('a real VLAN ID is read back', access.inventory_unused_vlan(good) == 999)

        for name, body in (('missing.yaml', None),
                           ('empty.yaml', '{"devices": {}}'),
                           ('bad.yaml', '{"unused_vlan": "x"}'),
                           ('range.yaml', '{"unused_vlan": 9999}'),
                           ('notjson.yaml', 'unused_vlan: 999\n')):
            path = os.path.join(tmpdir, name)
            if body is not None:
                io.open(path, 'w', encoding='utf-8').write(body)
            check(f'{name} yields None rather than an exception',
                  access.inventory_unused_vlan(path) is None,
                  access.inventory_unused_vlan(path))


if __name__ == '__main__':
    test_the_copies_answer_the_same_as_the_originals()
    test_a_templated_trunk_never_receives_an_access_command()
    test_the_unused_vlan_lands_on_shut_ports_only()
    test_an_unreadable_template_stops_that_switch()
    test_the_unused_vlan_is_read_from_inventory_when_it_is_there()
    print('\n' + ('ALL CHECKS PASSED' if not failures
                  else f'{len(failures)} FAILED: {", ".join(failures)}'))
    sys.exit(1 if failures else 0)
