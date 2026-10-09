"""
Fortinet FortiOS Configuration Parser.
Transforms hierarchical FortiOS stanzas into NormalizedConfiguration.
"""

import re
from typing import List, Dict, Any, Optional
from backend.app.parsers.base import BaseParser
from backend.app.schemas.normalized import (
    NormalizedConfiguration, SSHConfig, PasswordConfig,
    AuthenticationConfig, LoggingConfig, NTPConfig, SNMPConfig,
    FirewallRule, InterfaceConfig, CryptoConfig
)


class FortinetParser(BaseParser):
    @property
    def vendor_name(self) -> str:
        return "Fortinet"

    def parse(self, content: str) -> NormalizedConfiguration:
        lines = content.splitlines()
        raw_count = len(lines)

        hostname = "fortigate-firewall"
        os_version = None

        ssh = SSHConfig(enabled=False, version=2)
        passwords = PasswordConfig(service_encryption=True)  # FortiOS encrypts secrets by default (ENC)
        auth = AuthenticationConfig()
        logging_cfg = LoggingConfig()
        ntp = NTPConfig()
        snmp = SNMPConfig()
        crypto = CryptoConfig()

        telnet_enabled = False
        http_server_enabled = False
        https_server_enabled = False
        insecure_services = []
        firewall_rules: List[FirewallRule] = []
        interfaces: List[InterfaceConfig] = []
        default_deny = False

        # State tracking
        current_config_stack = []
        current_edit = None
        current_policy_dict: Dict[str, Any] = {}
        current_interface_dict: Dict[str, Any] = {}

        # Look for header version
        for line in lines[:20]:
            if "#config-version=" in line:
                match = re.search(r'#config-version=([^\s:]+)', line)
                if match:
                    os_version = match.group(1)

        for line_num, raw_line in enumerate(lines, 1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            if line.startswith("config "):
                stanza = line.split("config ", 1)[1].strip()
                current_config_stack.append(stanza)
                continue
            elif line == "end":
                if current_config_stack:
                    current_config_stack.pop()
                continue
            elif line.startswith("edit "):
                current_edit = line.split("edit ", 1)[1].replace('"', '').strip()
                current_policy_dict = {"id": current_edit}
                current_interface_dict = {"name": current_edit}
                continue
            elif line == "next":
                active_context = current_config_stack[-1] if current_config_stack else ""
                if active_context == "firewall policy" and current_policy_dict:
                    act = current_policy_dict.get("action", "accept")
                    src = current_policy_dict.get("srcaddr", "")
                    dst = current_policy_dict.get("dstaddr", "")
                    svc = current_policy_dict.get("service", "")
                    
                    is_unres = (
                        act == "accept" and
                        src.lower() in ['"all"', "all"] and
                        dst.lower() in ['"all"', "all"] and
                        svc.lower() in ['"all"', "all", ""]
                    )
                    
                    firewall_rules.append(FirewallRule(
                        rule_id=f"policy_{current_policy_dict.get('id', len(firewall_rules)+1)}",
                        name=current_policy_dict.get("name", f"Policy {current_policy_dict.get('id')}"),
                        action="permit" if act == "accept" else "deny",
                        source_zones=[current_policy_dict.get("srcintf", "any")],
                        destination_zones=[current_policy_dict.get("dstintf", "any")],
                        source_ips=[src],
                        destination_ips=[dst],
                        services=[svc],
                        is_unrestricted=is_unres,
                        logging_enabled=("logtraffic" in current_policy_dict and current_policy_dict["logtraffic"] != "disable")
                    ))
                elif active_context == "system interface" and current_interface_dict:
                    access = current_interface_dict.get("allowaccess", "").split()
                    mgmt_protos = [p.lower() for p in access if p.lower() in ["ssh", "telnet", "http", "https", "snmp"]]
                    
                    if "ssh" in mgmt_protos:
                        ssh.enabled = True
                    if "telnet" in mgmt_protos:
                        telnet_enabled = True
                    if "http" in mgmt_protos:
                        http_server_enabled = True
                    if "https" in mgmt_protos:
                        https_server_enabled = True

                    interfaces.append(InterfaceConfig(
                        name=current_interface_dict.get("name", "unknown"),
                        ip_address=current_interface_dict.get("ip"),
                        is_management=bool(mgmt_protos),
                        management_protocols=mgmt_protos
                    ))
                current_edit = None
                continue

            active_context = current_config_stack[-1] if current_config_stack else ""

            # Global settings
            if active_context == "system global":
                if line.startswith("set hostname "):
                    hostname = line.split("set hostname ", 1)[1].replace('"', '').strip()
                elif line.startswith("set admintimeout "):
                    match = re.search(r'set\s+admintimeout\s+(\d+)', line)
                    if match:
                        auth.exec_timeout_minutes = int(match.group(1))
                elif line.startswith("set admin-ssh-port "):
                    ssh.enabled = True
                elif line.startswith("set admin-https-redirect enable"):
                    https_server_enabled = True
                elif line.startswith("set pre-login-banner enable") or line.startswith("set post-login-banner enable"):
                    auth.login_banner_present = True

            # Syslog
            elif active_context == "log syslogd setting":
                if "set status enable" in line:
                    logging_cfg.enabled = True
                elif line.startswith("set server "):
                    srv = line.split("set server ", 1)[1].replace('"', '').strip()
                    logging_cfg.syslog_servers.append(srv)

            # NTP
            elif active_context == "system ntp":
                if line.startswith("set ntpserver ") or line.startswith("set server "):
                    srv = line.split()[-1].replace('"', '')
                    ntp.servers.append(srv)
                elif "set authentication enable" in line:
                    ntp.authenticated = True

            # SNMP
            elif "snmp community" in active_context:
                snmp.v1_v2c_enabled = True
                if line.startswith("set name "):
                    name = line.split("set name ", 1)[1].replace('"', '').strip().lower()
                    snmp.communities.append(name)
                    if name in ["public", "private", "fortinet"]:
                        snmp.default_community_used = True
            elif "snmp user" in active_context:
                snmp.v3_enabled = True

            # Firewall policy attributes
            elif active_context == "firewall policy":
                if line.startswith("set srcintf "):
                    current_policy_dict["srcintf"] = line.split("set srcintf ", 1)[1].replace('"', '').strip()
                elif line.startswith("set dstintf "):
                    current_policy_dict["dstintf"] = line.split("set dstintf ", 1)[1].replace('"', '').strip()
                elif line.startswith("set srcaddr "):
                    current_policy_dict["srcaddr"] = line.split("set srcaddr ", 1)[1].replace('"', '').strip()
                elif line.startswith("set dstaddr "):
                    current_policy_dict["dstaddr"] = line.split("set dstaddr ", 1)[1].replace('"', '').strip()
                elif line.startswith("set action "):
                    current_policy_dict["action"] = line.split("set action ", 1)[1].strip()
                elif line.startswith("set service "):
                    current_policy_dict["service"] = line.split("set service ", 1)[1].replace('"', '').strip()
                elif line.startswith("set logtraffic "):
                    current_policy_dict["logtraffic"] = line.split("set logtraffic ", 1)[1].strip()

            # Interface attributes
            elif active_context == "system interface":
                if line.startswith("set ip "):
                    parts = line.split("set ip ", 1)[1].split()
                    if parts:
                        current_interface_dict["ip"] = parts[0]
                elif line.startswith("set allowaccess "):
                    current_interface_dict["allowaccess"] = line.split("set allowaccess ", 1)[1].strip()

            # Password policy
            elif "password-policy" in active_context or "system password-policy" in active_context:
                if line.startswith("set min-length ") or line.startswith("set minimum-length "):
                    match = re.search(r'set\s+min(?:imum)?-length\s+(\d+)', line)
                    if match:
                        passwords.min_length = int(match.group(1))

            # Users
            elif "user local" in active_context or "system admin" in active_context:
                if "set password" in line or "set passwd" in line:
                    if "ENC " in line:
                        passwords.strong_algorithm_count += 1
                    else:
                        passwords.weak_algorithm_count += 1

        # Fortinet implicit default deny is standard behavior on all interfaces/policies
        default_deny = True

        return NormalizedConfiguration(
            vendor=self.vendor_name,
            device_type="Next-Gen Firewall",
            hostname=hostname,
            os_version=os_version,
            raw_lines_count=raw_count,
            ssh=ssh,
            passwords=passwords,
            auth=auth,
            logging=logging_cfg,
            ntp=ntp,
            snmp=snmp,
            crypto=crypto,
            telnet_enabled=telnet_enabled,
            http_server_enabled=http_server_enabled,
            https_server_enabled=https_server_enabled,
            insecure_services=insecure_services,
            firewall_rules=firewall_rules,
            default_deny=default_deny,
            interfaces=interfaces
        )
