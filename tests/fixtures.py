#!/usr/bin/env python
"""Synthetic device output shared by the tests.

Not taken from any real switch. Addressing is RFC 5737 documentation space and
the hostname is invented, so this file is safe to commit where a real capture
would not be - see capture.py. Shaped like a Catalyst running IOS XE, including
a TwentyFiveGigE uplink, so the interface-prefix handling is exercised too.

The version, model and release in SHOW_VERSION are consistent with the config:
a Catalyst 9300 on IOS XE 17.12.4, which is a release V-220621's table knows.

It also carries the two Layer 3 interfaces whose names look like switchports:
the out-of-band management port GigabitEthernet0/0 (in Mgmt-vrf, and never a
switchport on Catalyst hardware) and a routed uplink carrying 'no switchport'.
Both used to land in the access bucket and draw findings from every per-access-
port rule at once. Every suite that reads this config now exercises that.
"""

RUNNING_CONFIG = """Building configuration...

Current configuration : 4211 bytes
!
version 17.12
service timestamps debug datetime msec localtime show-timezone
service timestamps log datetime msec localtime show-timezone
service password-encryption
!
hostname TESTSW01
!
aaa new-model
aaa authentication login default group radius local
aaa accounting exec default start-stop group radius
!
no ip domain-lookup
ip domain name example.test
!
crypto pki trustpoint TP-self-signed-1234567890
 enrollment selfsigned
 subject-name cn=IOS-Self-Signed-Certificate-1234567890
 revocation-check none
 rsakeypair TP-self-signed-1234567890
!
crypto pki certificate chain TP-self-signed-1234567890
 certificate self-signed 01
  quit
!
vtp mode transparent
!
spanning-tree mode rapid-pvst
spanning-tree portfast bpduguard default
!
vlan 10
 name MGMT
!
vlan 20
 name USERS
!
vlan 999
 name NATIVE
!
vlan 1000
 name UNUSED
!
ip dhcp snooping vlan 20
ip dhcp snooping
ip arp inspection vlan 20
!
class-map match-all C2_VOICE
 match ip dscp 47
class-map match-all VOICE
 match ip dscp ef
class-map match-all VIDEO
 match ip dscp af41
class-map match-all PREFERRED_DATA
 match ip dscp af33
!
policy-map QOS_POLICY_SWITCHPORT
 class C2_VOICE
  priority level 1 10
 class VOICE
  priority level 2 15
 class VIDEO
  bandwidth percent 25
 class PREFERRED_DATA
  bandwidth percent 25
 class class-default
  bandwidth percent 25
!
interface GigabitEthernet1/0/1
 description user port
 switchport mode access
 switchport access vlan 20
 spanning-tree portfast
 spanning-tree bpduguard enable
 ip verify source
 service-policy output QOS_POLICY_SWITCHPORT
!
interface GigabitEthernet1/0/2
 description disabled port
 switchport mode access
 switchport access vlan 1000
 service-policy output QOS_POLICY_SWITCHPORT
 shutdown
!
interface TwentyFiveGigE1/1/1
 description uplink to core
 switchport mode trunk
 switchport trunk native vlan 999
 switchport trunk allowed vlan 10,20
 ip dhcp snooping trust
 ip arp inspection trust
 service-policy output QOS_POLICY_SWITCHPORT
!
interface GigabitEthernet0/0
 description out-of-band management
 vrf forwarding Mgmt-vrf
 ip address 198.51.100.5 255.255.255.0
 negotiation auto
!
interface TenGigabitEthernet1/0/24
 description routed uplink to the core
 no switchport
 ip address 198.51.100.9 255.255.255.252
!
interface Vlan10
 ip address 192.0.2.5 255.255.255.0
!
banner login ^C
You are accessing a U.S. Government (USG) Information System (IS) that is
provided for USG-authorized use only.
^C
!
line con 0
 exec-timeout 5 0
 logging synchronous
line vty 0 4
 exec-timeout 5 0
 transport input ssh
 session-limit 5
!
logging buffered 64000
logging host 192.0.2.20
logging host 192.0.2.21
logging trap informational
!
ntp authenticate
ntp server 192.0.2.30
ntp server 192.0.2.31
!
snmp-server group STIGGRP v3 priv
!
ip ssh version 2
ip ssh server algorithm mac hmac-sha2-256
ip ssh server algorithm encryption aes256-ctr aes192-ctr aes128-ctr
!
ip scp server enable
file prompt quiet
!
event manager applet BACKUP_CONFIG
 event syslog pattern "%SYS-5-CONFIG_I"
 action 1 cli command "enable"
 action 2 info type routername
 action 3 cli command "copy running-config scp://backup@192.0.2.40/configs/$_info_routername-running-config"
 action 4 syslog priority informational msg "Configuration backup executed for $_info_routername"
 authorization bypass
!
end"""

VLAN_BRIEF = """VLAN Name                             Status    Ports
---- -------------------------------- --------- -------------------------------
1    default                          active
10   MGMT                             active    Vl10
20   USERS                            active    Gi1/0/1
999  NATIVE                           active
1000 UNUSED                           active    Gi1/0/2
1002 fddi-default                     act/unsup
1003 trcrf-default                    act/unsup
1004 fddinet-default                  act/unsup
1005 trbrf-default                    act/unsup"""

SPANNING_TREE = """VLAN0010
  Spanning tree enabled protocol rstp
  Root ID    Priority    24586
             Address     0011.2233.4455
             Cost        4
             Port        1 (TwentyFiveGigE1/1/1)
             Hello Time  2 sec  Max Age 20 sec  Forward Delay 15 sec

VLAN0020
  Spanning tree enabled protocol rstp
  Root ID    Priority    24596
             Address     0011.2233.4455
             Cost        4
             Port        1 (TwentyFiveGigE1/1/1)
             Hello Time  2 sec  Max Age 20 sec  Forward Delay 15 sec"""

SHOW_VERSION = """Cisco IOS XE Software, Version 17.12.04
Cisco IOS Software [Dublin], Catalyst L3 Switch Software (CAT9K_IOSXE), Version 17.12.4, RELEASE SOFTWARE (fc2)
Technical Support: http://www.cisco.com/techsupport
Copyright (c) 1986-2024 by Cisco Systems, Inc.

TESTSW01 uptime is 3 weeks, 2 days, 4 hours, 11 minutes
System image file is "flash:packages.conf"
Last reload reason: Reload Command

cisco C9300-48P (X86) processor with 1419044K/6147K bytes of memory.
Processor board ID FOC0000X0XX
1 Virtual Ethernet interface
52 Gigabit Ethernet interfaces
2048K bytes of non-volatile configuration memory.

Base Ethernet MAC Address            : 00:1A:2B:3C:4D:5E
Model Number                         : C9300-48P
System Serial Number                 : FOC0000X0XX

Switch Ports Model              SW Version        SW Image              Mode
------ ----- -----              ----------        ----------            ----
*    1 52    C9300-48P          17.12.04          CAT9K_IOSXE           INSTALL

Configuration register is 0x102"""


VTP_PASSWORD = 'The VTP password is not configured.'

# Only two interfaces here carry an address, and only one of them is an SVI -
# the management VLAN's. Gi0/0 is the out-of-band port, which is a plausible
# wrong answer for the asset block and is deliberately present so the tests
# would catch it being picked.
IP_INTERFACE_BRIEF = """Interface              IP-Address      OK? Method Status                Protocol
Vlan10                 192.0.2.5       YES NVRAM  up                    up
GigabitEthernet0/0     198.51.100.5    YES manual up                    up
GigabitEthernet1/0/1   unassigned      YES unset  up                    up
GigabitEthernet1/0/2   unassigned      YES unset  administratively down down
TwentyFiveGigE1/1/1    unassigned      YES unset  up                    up"""

SNMP_USER = """User name: stigadmin
Engine ID: 800000090300AABBCCDDEEFF
storage-type: nonvolatile        active
Authentication Protocol: SHA
Privacy Protocol: AES128
Group-name: STIGGRP"""

# What a Catalyst 9300 answers when SSHv2 is running. Note what is NOT in its
# running-config: `ip ssh version 2`. SSHv1 is gone on that train, so v2-only is
# not a non-default setting and the line is never rendered - which is why
# V-220555/220556 must read this rather than grep the config for a line the
# switch will not write.
SHOW_IP_SSH = """SSH Enabled - version 2.0
Authentication methods:publickey,keyboard-interactive,password
Authentication Publickey Algorithms:x509v3-ssh-rsa,ssh-rsa
Hostkey Algorithms:x509v3-ssh-rsa,rsa-sha2-512,rsa-sha2-256,ssh-rsa
Encryption Algorithms:aes256-gcm,aes256-ctr
MAC Algorithms:hmac-sha2-512,hmac-sha2-256
Authentication timeout: 60 secs; Authentication retries: 3
Minimum expected Diffie Hellman key size : 2048 bits
IOS Keys in SECSH format(ssh-rsa, base64 encoded): SW01.example.mil"""


OUTPUTS = {
    'show running-config': RUNNING_CONFIG,
    'show vlan brief': VLAN_BRIEF,
    'show spanning-tree': SPANNING_TREE,
    'show vtp password': VTP_PASSWORD,
    'show snmp user': SNMP_USER,
    'show version': SHOW_VERSION,
    'show ip interface brief': IP_INTERFACE_BRIEF,
    'show ip ssh': SHOW_IP_SSH,
}
