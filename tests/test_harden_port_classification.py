#!/usr/bin/env python
"""An interface template is where a port's real configuration can live.

Run it directly: `python3 tests/test_harden_port_classification.py`.

The harden scripts classify every switchport as access or trunk and then push a
different set of commands to each. That classification reads `switchport mode
trunk` out of the interface's block - and a port configured by
`source template <name>` has no such line in its own block, because its mode
comes from the template.

Read off the raw config, a templated uplink is therefore an access port:

  * l2_stig_harden_access_ports.py would send `switchport mode access` and
    `spanning-tree portfast` to it - collapsing the trunk, and putting PortFast
    on a port that receives BPDUs as a matter of course, which is the exact
    condition BPDU Guard exists to shut down.
  * l2_stig_harden_trunk_ports.py would skip it, and report a clean run on a
    switch whose uplinks were never touched.

Both scripts expand templates before classifying. This pins that, and pins the
access-VLAN reading the same expansion fixes - a templated port's VLAN comes
from the template, so off the raw config it looks like a port with no VLAN at
all."""

import io
import os
import sys

PROJECT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(PROJECT, 'scripts'))

import stig_common

failures = []


def check(name, condition, detail=''):
    print(f'  {"ok  " if condition else "FAIL"} {name}')
    if not condition:
        if detail:
            print(f'       {detail}')
        failures.append(name)


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
interface GigabitEthernet1/0/24
 source template UPLINK
!
interface GigabitEthernet1/0/8
 switchport mode access
 switchport access vlan 30
 shutdown
!
interface GigabitEthernet1/0/9
 source template PARKED
!
interface TenGigabitEthernet1/1/1
 no switchport
 ip address 10.2.2.2 255.255.255.0
!
interface GigabitEthernet0/0
 vrf forwarding Mgmt-vrf
 ip address 10.1.1.1 255.255.255.0
!
"""

BODIES = {
    'USER-PORT': ['switchport mode access', 'switchport access vlan 55',
                  'spanning-tree portfast'],
    'UPLINK': ['switchport mode trunk', 'switchport nonegotiate'],
    # A port shut by the template it sources, not by its own block.
    'PARKED': ['switchport mode access', 'switchport access vlan 55', 'shutdown'],
}


class FakeConnection:
    """Answers the two commands the harden scripts ask for, and records them."""

    def __init__(self, bodies):
        self.bodies = bodies
        self.asked = []

    def send_command(self, command):
        self.asked.append(command)
        if command == 'show running-config':
            return CONFIG
        prefix = 'show template interface source user '
        if command.startswith(prefix):
            name = command[len(prefix):]
            if name not in self.bodies:
                return '% Template not found'
            return ('Template Name  : {0}\n----------\n'.format(name)
                    + '\n'.join(' ' + line for line in self.bodies[name]) + '\nend\n')
        raise AssertionError('unexpected command: ' + command)


def test_a_templated_trunk_is_not_an_access_port():
    print('a trunk that gets its mode from a template is still a trunk')
    raw_access, raw_trunk = stig_common.switchport_names(CONFIG)
    check('off the raw config it reads as an access port - the bug',
          'GigabitEthernet1/0/24' in raw_access and not raw_trunk,
          (raw_access, raw_trunk))

    connection = FakeConnection(BODIES)
    config = str(connection.send_command('show running-config'))
    bodies = stig_common.read_interface_templates(connection, config)
    access, trunk = stig_common.switchport_names(
        stig_common.expand_interface_templates(config, bodies))

    check('every sourced template was read off the switch, once each',
          sorted(bodies) == ['PARKED', 'UPLINK', 'USER-PORT']
          and connection.asked.count('show template interface source user UPLINK') == 1,
          connection.asked)
    check('the templated uplink is classified as a trunk',
          'GigabitEthernet1/0/24' in trunk, trunk)
    check('so the access pass never sends it `switchport mode access`',
          'GigabitEthernet1/0/24' not in access, access)
    check('the templated user port is still an access port',
          'GigabitEthernet1/0/2' in access, access)
    check('and the Layer 3 interfaces are in neither bucket',
          not {'TenGigabitEthernet1/1/1', 'GigabitEthernet0/0'} & set(access + trunk),
          (access, trunk))


def test_a_templated_ports_vlan_is_not_missing():
    """The same expansion is what stops a templated port reading as a port with
    no access VLAN. Nothing pushes an access VLAN any more, but the audit reads
    the same rule, and a port whose VLAN comes from a template has one."""
    print('\na templated port has the VLAN its template gives it')
    import re

    def vlan_of(cfg, port):
        for chunk in re.split(r'^(?=interface \S+)', cfg, flags=re.M):
            if chunk.startswith(f'interface {port}\n'):
                m = re.search(r'^\s*switchport access vlan (\d+)\s*$', chunk, re.M)
                return m.group(1) if m else None
        return None

    check('off the raw config the template\'s VLAN is invisible',
          vlan_of(CONFIG, 'GigabitEthernet1/0/2') is None)
    expanded = stig_common.expand_interface_templates(CONFIG, BODIES)
    check('expanded, it is VLAN 55', vlan_of(expanded, 'GigabitEthernet1/0/2') == '55',
          vlan_of(expanded, 'GigabitEthernet1/0/2'))
    check('a port with its own explicit VLAN keeps it',
          vlan_of(expanded, 'GigabitEthernet1/0/1') == '30')


def test_only_shut_access_ports_get_the_unused_vlan():
    """V-220641. A shut port forwards nothing whatever VLAN it is on, which is
    what makes this the one access-VLAN assignment a bulk pass can make - and
    the reason it must land on shut ports ONLY. A live port that got it would
    have whatever is plugged into it moved to a VLAN chosen for having nothing
    on it."""
    print('\nthe unused VLAN lands on shut access ports, and only those')
    src = io.open(os.path.join(PROJECT, 'scripts', 'l2_stig_harden_access_ports.py'),
                  encoding='utf-8').read().split('parser = argparse.ArgumentParser')[0]
    module = {'__name__': 'probe'}
    exec(compile(src, 'l2_stig_harden_access_ports.py', 'exec'), module)

    expanded = stig_common.expand_interface_templates(CONFIG, BODIES)
    access, trunk = stig_common.switchport_names(expanded)
    shut = module['shutdown_access_ports'](expanded, access)

    check('the port shut in its own block is found',
          'GigabitEthernet1/0/8' in shut, shut)
    check('so is the one shut by the template it sources',
          'GigabitEthernet1/0/9' in shut, shut)
    check('and no live access port is in the list',
          not {'GigabitEthernet1/0/1', 'GigabitEthernet1/0/2',
               'GigabitEthernet1/0/3'} & set(shut), shut)
    check('nor is the trunk, however it got its mode',
          'GigabitEthernet1/0/24' not in shut, shut)

    # Read off the raw config the templated shut port is invisible, which is
    # what the expansion is for.
    raw_access, _ = stig_common.switchport_names(CONFIG)
    check('off the raw config the template-shut port would have been missed',
          'GigabitEthernet1/0/9' not in module['shutdown_access_ports'](CONFIG, raw_access))

    check('a templated shut port is reported as having its template overridden',
          module['templated_ports'](CONFIG, shut) == ['GigabitEthernet1/0/9'],
          module['templated_ports'](CONFIG, shut))


def test_a_switch_with_no_templates_asks_nothing_extra():
    print('\na switch that sources no template is asked for none')
    plain = 'interface GigabitEthernet1/0/1\n switchport mode access\n!\n'
    connection = FakeConnection(BODIES)
    bodies = stig_common.read_interface_templates(connection, plain)
    check('no template command was sent', connection.asked == [], connection.asked)
    check('and there is nothing to expand', bodies == {}, bodies)
    check('expansion of a config with no templates changes nothing',
          stig_common.expand_interface_templates(plain, bodies) == plain)


if __name__ == '__main__':
    test_a_templated_trunk_is_not_an_access_port()
    test_a_templated_ports_vlan_is_not_missing()
    test_only_shut_access_ports_get_the_unused_vlan()
    test_a_switch_with_no_templates_asks_nothing_extra()
    print('\n' + ('ALL CHECKS PASSED' if not failures
                  else f'{len(failures)} FAILED: {", ".join(failures)}'))
    sys.exit(1 if failures else 0)
