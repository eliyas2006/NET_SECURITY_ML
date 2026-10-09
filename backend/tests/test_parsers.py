"""
Tests for Vendor Identification and Parsers.
"""

import pytest
from backend.app.parsers import detect_vendor, CiscoParser, FortinetParser, PaloAltoParser


def test_detect_cisco():
    cisco_sample = """
    version 15.6
    hostname edge-rtr
    service password-encryption
    line vty 0 4
     transport input ssh
    """
    res = detect_vendor(cisco_sample)
    assert res.vendor == "Cisco"
    assert res.confidence >= 0.7
    assert res.confidence_level == "High"


def test_detect_fortinet():
    fgt_sample = """
    #config-version=FG100F-7.2.4:opmode=0
    config system global
        set hostname "fgt-core"
    end
    config firewall policy
        edit 1
            set action accept
        next
    end
    """
    res = detect_vendor(fgt_sample)
    assert res.vendor == "Fortinet"
    assert res.confidence >= 0.7


def test_detect_palo_alto():
    pa_sample = """
    set deviceconfig system hostname pa-01
    set rulebase security rules "allow-web" action allow
    set deviceconfig system service disable-telnet yes
    """
    res = detect_vendor(pa_sample)
    assert res.vendor == "Palo Alto"
    assert res.confidence >= 0.7


def test_detect_unknown():
    res = detect_vendor("some generic unformatted text without any networking commands")
    assert res.vendor == "Unknown"
    assert res.confidence_level == "Low"


def test_cisco_parser():
    sample = """
    hostname cisco-test
    version 15.2
    service password-encryption
    security passwords min-length 12
    enable secret 9 $9$someHash
    ip ssh version 2
    no ip http server
    logging host 10.1.1.50
    ntp server 1.1.1.1
    snmp-server group SECGROUP v3 priv
    line vty 0 4
     transport input ssh
     exec-timeout 10 0
    ip access-list extended TEST-ACL
     permit ip 10.0.0.0 0.255.255.255 host 10.1.1.1
     deny ip any any log
    """
    parser = CiscoParser()
    norm = parser.parse(sample)

    assert norm.vendor == "Cisco"
    assert norm.hostname == "cisco-test"
    assert norm.ssh.enabled is True
    assert norm.ssh.version == 2
    assert norm.telnet_enabled is False
    assert norm.passwords.service_encryption is True
    assert norm.passwords.min_length == 12
    assert len(norm.logging.syslog_servers) == 1
    assert len(norm.ntp.servers) == 1
    assert norm.snmp.v3_enabled is True
    assert len(norm.firewall_rules) >= 1
    assert not any(r.is_unrestricted for r in norm.firewall_rules)


def test_fortinet_parser():
    sample = """
    config system global
        set hostname "fgt-test"
        set admintimeout 15
    end
    config system interface
        edit "port1"
            set allowaccess ssh https
        next
    end
    config firewall policy
        edit 1
            set srcaddr "all"
            set dstaddr "all"
            set service "ALL"
            set action accept
        next
    end
    """
    parser = FortinetParser()
    norm = parser.parse(sample)

    assert norm.vendor == "Fortinet"
    assert norm.hostname == "fgt-test"
    assert norm.ssh.enabled is True
    assert norm.auth.exec_timeout_minutes == 15
    assert len(norm.firewall_rules) == 1
    assert norm.firewall_rules[0].is_unrestricted is True


def test_palo_alto_parser():
    sample = """
    set deviceconfig system hostname "pa-test"
    set deviceconfig system service disable-telnet yes
    set deviceconfig system session idle-timeout 10
    set rulebase security rules "Drop-All" action deny source any destination any
    """
    parser = PaloAltoParser()
    norm = parser.parse(sample)

    assert norm.vendor == "Palo Alto"
    assert norm.hostname == "pa-test"
    assert norm.telnet_enabled is False
    assert norm.auth.exec_timeout_minutes == 10
    assert len(norm.firewall_rules) == 1
    assert norm.firewall_rules[0].action == "deny"
