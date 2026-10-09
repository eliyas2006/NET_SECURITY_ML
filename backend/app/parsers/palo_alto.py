"""
Palo Alto PAN-OS Configuration Parser.
Transforms PAN-OS set-format or hierarchical configuration stanzas into NormalizedConfiguration.
"""

import re
from typing import List, Dict, Any
from backend.app.parsers.base import BaseParser
from backend.app.schemas.normalized import (
    NormalizedConfiguration, SSHConfig, PasswordConfig,
    AuthenticationConfig, LoggingConfig, NTPConfig, SNMPConfig,
    FirewallRule, InterfaceConfig, CryptoConfig
)


class PaloAltoParser(BaseParser):
    @property
    def vendor_name(self) -> str:
        return "Palo Alto"

    def parse(self, content: str) -> NormalizedConfiguration:
        lines = content.splitlines()
        raw_count = len(lines)

        hostname = "palo-alto-firewall"
        os_version = None

        ssh = SSHConfig(enabled=True, version=2)  # PAN-OS defaults to SSHv2
        passwords = PasswordConfig(service_encryption=True)
        auth = AuthenticationConfig()
        logging_cfg = LoggingConfig()
        ntp = NTPConfig()
        snmp = SNMPConfig()
        crypto = CryptoConfig()

        telnet_enabled = False
        http_server_enabled = False
        https_server_enabled = True  # PAN-OS admin UI is HTTPS
        insecure_services = []
        firewall_rules: List[FirewallRule] = []
        interfaces: List[InterfaceConfig] = []
        default_deny = False

        rules_dict: Dict[str, Dict[str, Any]] = {}

        for raw_line in lines:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            # Check hostname
            if "deviceconfig system hostname" in line:
                parts = line.split("hostname")
                if len(parts) > 1:
                    hostname = parts[1].replace('"', '').strip()

            # NTP
            if "deviceconfig system ntp-servers" in line:
                match = re.search(r'ntp-server-address\s+([^\s]+)', line)
                if match:
                    ntp.servers.append(match.group(1))
                elif "ntp-servers primary" in line:
                    tokens = line.split()
                    if len(tokens) >= 5:
                        ntp.servers.append(tokens[-1])

            # Services & Management
            if "disable-telnet no" in line or "service telnet" in line:
                telnet_enabled = True
            if "disable-http no" in line:
                http_server_enabled = True

            # Inactivity timeout
            if "idle-timeout" in line or "deviceconfig system session idle-timeout" in line:
                match = re.search(r'idle-timeout\s+(\d+)', line)
                if match:
                    auth.exec_timeout_minutes = int(match.group(1))

            # Banner
            if "deviceconfig system login-banner" in line:
                auth.login_banner_present = True
                auth.login_banner_text = line

            # Syslog
            if "log-settings syslog" in line or "syslog server" in line or "deviceconfig system syslog" in line:
                logging_cfg.enabled = True
                match = re.search(r'server\s+([^\s]+)', line)
                if match:
                    logging_cfg.syslog_servers.append(match.group(1))

            # Password profile
            if "min-password-length" in line or "minimum-length" in line:
                match = re.search(r'(?:min-password-length|minimum-length)\s+(\d+)', line)
                if match:
                    passwords.min_length = int(match.group(1))

            # SNMP
            if "deviceconfig system snmp-setting" in line or "snmp-setting" in line:
                if "version v2c" in line or "community" in line or "snmp-community-string" in line:
                    snmp.v1_v2c_enabled = True
                    match = re.search(r'(?:community|snmp-community-string)\s+([^\s]+)', line)
                    if match:
                        comm = match.group(1).lower().replace('"', '')
                        snmp.communities.append(comm)
                        if comm in ["public", "private"]:
                            snmp.default_community_used = True
                if "version v3" in line or "snmp-v3" in line:
                    snmp.v3_enabled = True

            # Security Rules
            # Format: set rulebase security rules "<name>" ...
            if "rulebase security rules" in line:
                match = re.search(r'rulebase security rules\s+["\']?([^"\'\s]+)["\']?\s+(.*)', line)
                if match:
                    rname = match.group(1)
                    prop_str = match.group(2)
                    if rname not in rules_dict:
                        rules_dict[rname] = {
                            "name": rname,
                            "action": "allow",
                            "from": [],
                            "to": [],
                            "source": [],
                            "destination": [],
                            "service": [],
                            "log_end": True
                        }
                    
                    if "action " in prop_str:
                        rules_dict[rname]["action"] = prop_str.split("action ", 1)[1].split()[0]
                    if "source " in prop_str:
                        rules_dict[rname]["source"].append(prop_str.split("source ", 1)[1].split()[0])
                    if "destination " in prop_str:
                        rules_dict[rname]["destination"].append(prop_str.split("destination ", 1)[1].split()[0])
                    if "log-end no" in prop_str:
                        rules_dict[rname]["log_end"] = False

        # Assemble rules
        for idx, (rname, rdata) in enumerate(rules_dict.items(), 1):
            act = rdata.get("action", "allow")
            srcs = rdata.get("source", [])
            dsts = rdata.get("destination", [])
            
            is_unres = (
                act == "allow" and
                "any" in srcs and
                "any" in dsts
            )

            if "deny" in act or "drop" in act or "reset" in act:
                default_deny = True

            firewall_rules.append(FirewallRule(
                rule_id=f"pan_rule_{idx}",
                name=rname,
                action="permit" if act == "allow" else "deny",
                source_zones=rdata.get("from", []),
                destination_zones=rdata.get("to", []),
                source_ips=srcs,
                destination_ips=dsts,
                is_unrestricted=is_unres,
                logging_enabled=rdata.get("log_end", True)
            ))

        # PAN-OS has default interzone deny built-in
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
