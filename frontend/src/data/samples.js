/**
 * Preset Demonstration Configurations for Instant 1-Click UI Testing.
 */

export const SAMPLE_CONFIGS = {
  cisco_hardened: {
    name: 'Cisco IOS - Hardened Core Router',
    vendor: 'Cisco',
    filename: 'cisco_core_hardened.cfg',
    text: `! Cisco IOS Hardened Core Router Sample
version 15.6
service timestamps log datetime msec
service password-encryption
hostname core-rtr-01.corp
security passwords min-length 14
aaa new-model
aaa authentication login default group tacacs+ local
aaa authorization exec default group tacacs+ local
ip ssh version 2
ip ssh time-out 60
no ip http server
ip http secure-server
no service finger
no ip source-route
enable secret 9 $9$vD82kSldjfKdLs92837492
username secadmin privilege 15 algorithm-type sha256 secret 8 $8$a1s2d3f4g5JkL90
interface GigabitEthernet0/0/0
 description WAN-Uplink
 ip address 198.51.100.2 255.255.255.252
logging buffered 64000 informational
logging host 10.100.50.10
service timestamps log datetime msec
ntp authenticate
ntp server 10.100.10.1
snmp-server group SECGROUP v3 priv
snmp-server user snmpadmin SECGROUP v3 auth sha MyStr0ngAuthP@ss priv aes 128 MyStr0ngPr1vP@ss
banner motd ^C Authorized Personnel Only. Activities Monitored. ^C
line vty 0 4
 transport input ssh
 exec-timeout 10 0
ip access-list extended SECURE-FILTER
 permit tcp 198.51.100.0 0.0.0.3 host 198.51.100.2 eq 22
 deny ip any any log
end`,
  },

  cisco_vulnerable: {
    name: 'Cisco IOS - Vulnerable Perimeter (Critical Risk)',
    vendor: 'Cisco',
    filename: 'cisco_vulnerable_perimeter.cfg',
    text: `! Cisco IOS Vulnerable Configuration Sample
version 15.1
hostname perimeter-rtr-legacy
no service password-encryption
enable password plainciscopassword
username admin privilege 15 password 7 070C285F4D06
username operator privilege 1 password 7 094F471A1A0A
ip http server
ip ssh version 1
service finger
ip source-route
interface GigabitEthernet0/0
 ip address 203.0.113.1 255.255.255.0
ip access-list extended PERIMETER-IN
 permit ip any any
snmp-server community public RW
snmp-server community private RW
no logging console
line vty 0 4
 transport input telnet
 exec-timeout 0 0
line vty 5 15
 transport input all
 exec-timeout 0 0
end`,
  },

  fortinet_edge: {
    name: 'Fortinet FortiOS - Hardened Edge Firewall',
    vendor: 'Fortinet',
    filename: 'fgt_edge_secure.conf',
    text: `#config-version=FG100F-7.2.4-FW-build1390-230308:opmode=0
config system global
    set hostname "fgt-edge-fw01"
    set admintimeout 10
    set admin-ssh-port 22
    set admin-https-redirect enable
    set pre-login-banner enable
end
config system password-policy
    set status enable
    set min-length 14
end
config system interface
    edit "port1"
        set ip 198.51.100.10 255.255.255.248
        set allowaccess ping https
    next
    edit "port2"
        set ip 10.200.1.1 255.255.255.0
        set allowaccess ping https ssh
    next
end
config log syslogd setting
    set status enable
    set server "10.200.50.100"
end
config system ntp
    set ntpserver "time.cloudflare.com"
    set authentication enable
end
config system snmp user
    edit "snmpv3-nms"
        set security-level auth-priv
    next
end
config firewall policy
    edit 10
        set name "Outbound-Corp"
        set srcintf "port2"
        set dstintf "port1"
        set srcaddr "10.200.1.0/24"
        set dstaddr "all"
        set action accept
        set service "HTTPS" "DNS"
        set logtraffic all
    next
    edit 99
        set name "Default-Deny"
        set action deny
    next
end
end`,
  },

  palo_alto_secure: {
    name: 'Palo Alto PAN-OS - Secure Next-Gen Gateway',
    vendor: 'Palo Alto',
    filename: 'pa_secure_gw.txt',
    text: `# Palo Alto PAN-OS Secure Gateway Sample
set deviceconfig system hostname pa-edge-fw01
set deviceconfig system service disable-telnet yes
set deviceconfig system service disable-http yes
set deviceconfig system session idle-timeout 10
set deviceconfig system login-banner "Authorized Access Only - All Sessions Audited"
set deviceconfig system ntp-servers primary-ntp-server ntp-server-address 10.100.10.1
set shared log-settings syslog "Corp-SIEM" server 10.100.50.10
set shared admin-password-profile "Strict" min-password-length 14
set rulebase security rules "Outbound-Corporate" from trust to untrust source 10.100.0.0/16 destination any service [ service-http service-https ] action allow log-end yes
set rulebase security rules "Default-Drop" from any to any source any destination any service any action deny log-end yes`,
  },
};
