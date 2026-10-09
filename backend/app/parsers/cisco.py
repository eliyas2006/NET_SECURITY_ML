"""
Cisco IOS / IOS-XE Configuration Parser.
Transforms hierarchical Cisco CLI configuration blocks into NormalizedConfiguration.
"""

import re
from typing import List, Dict, Any
from backend.app.parsers.base import BaseParser
from backend.app.schemas.normalized import (
    NormalizedConfiguration, SSHConfig, PasswordConfig,
    AuthenticationConfig, LoggingConfig, NTPConfig, SNMPConfig,
    FirewallRule, InterfaceConfig, CryptoConfig
)


class CiscoParser(BaseParser):
    @property
    def vendor_name(self) -> str:
        return "Cisco"

    def parse(self, content: str) -> NormalizedConfiguration:
        lines = content.splitlines()
        raw_count = len(lines)

        hostname = "cisco-router"
        os_version = None

        # Config objects
        ssh = SSHConfig()
        passwords = PasswordConfig()
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

        current_block = None
        current_interface = None
        current_acl = None

        for line_num, raw_line in enumerate(lines, 1):
            line = raw_line.strip()
            if not line or line.startswith("!"):
                continue

            # Hostname & Version
            if line.startswith("hostname "):
                hostname = line.split("hostname ", 1)[1].strip()
            elif line.startswith("version "):
                os_version = line.split("version ", 1)[1].strip()

            # Passwords & Encryption
            if line == "service password-encryption":
                passwords.service_encryption = True
            elif "security passwords min-length" in line:
                match = re.search(r'security\s+passwords\s+min-length\s+(\d+)', line)
                if match:
                    passwords.min_length = int(match.group(1))

            if line.startswith("enable secret "):
                passwords.enable_secret_present = True
                # Check algorithm: type 5 (MD5), type 8 (PBKDF2-SHA256), type 9 (scrypt)
                parts = line.split()
                if len(parts) >= 4 and parts[2] in ["8", "9"]:
                    passwords.enable_secret_strong = True
                    passwords.strong_algorithm_count += 1
                elif len(parts) >= 4 and parts[2] in ["5"]:
                    passwords.strong_algorithm_count += 1  # Standard hash
                else:
                    passwords.weak_algorithm_count += 1
            elif line.startswith("enable password "):
                passwords.weak_algorithm_count += 1

            if line.startswith("username "):
                parts = line.split()
                uname = parts[1] if len(parts) > 1 else f"user_{line_num}"
                if "secret" in line:
                    if " 8 " in line or " 9 " in line:
                        passwords.strong_algorithm_count += 1
                    else:
                        passwords.strong_algorithm_count += 1
                    passwords.user_accounts.append({"username": uname, "type": "secret"})
                elif "password" in line:
                    if " 7 " in line or " 0 " in line:
                        passwords.weak_algorithm_count += 1
                    passwords.user_accounts.append({"username": uname, "type": "password"})

            # SSH
            if line.startswith("ip ssh version "):
                ver_str = line.split("ip ssh version ", 1)[1].strip()
                if ver_str == "2":
                    ssh.version = 2
                    ssh.enabled = True
                elif ver_str == "1":
                    ssh.version = 1
                    ssh.enabled = True
            elif line.startswith("ip ssh time-out "):
                match = re.search(r'ip\s+ssh\s+time-out\s+(\d+)', line)
                if match:
                    ssh.timeout_seconds = int(match.group(1))
            elif line.startswith("ip ssh authentication-retries "):
                match = re.search(r'ip\s+ssh\s+authentication-retries\s+(\d+)', line)
                if match:
                    ssh.authentication_retries = int(match.group(1))

            # AAA
            if line == "aaa new-model":
                auth.aaa_enabled = True
            if line.startswith("radius-server host ") or line.startswith("radius server "):
                match = re.search(r'radius(-server\s+host|\s+server)\s+([^\s]+)', line)
                if match:
                    auth.radius_servers.append(match.group(2))
            if line.startswith("tacacs-server host ") or line.startswith("tacacs server "):
                match = re.search(r'tacacs(-server\s+host|\s+server)\s+([^\s]+)', line)
                if match:
                    auth.tacacs_servers.append(match.group(2))

            # Banner
            if line.startswith("banner motd") or line.startswith("banner login"):
                auth.login_banner_present = True
                auth.login_banner_text = line

            # Line configuration block detection
            if line.startswith("line vty ") or line.startswith("line con "):
                current_block = line
            elif not raw_line.startswith(" ") and not raw_line.startswith("\t"):
                if not (line.startswith("line vty") or line.startswith("line con") or line.startswith("interface")):
                    current_block = None

            if current_block and (line.startswith("transport input ") or "transport input" in line):
                if "ssh" in line:
                    ssh.enabled = True
                if "telnet" in line or "all" in line:
                    telnet_enabled = True
            if current_block and line.startswith("exec-timeout "):
                match = re.search(r'exec-timeout\s+(\d+)', line)
                if match:
                    auth.exec_timeout_minutes = int(match.group(1))

            # Logging
            if line.startswith("logging host ") or line.startswith("logging server "):
                logging_cfg.enabled = True
                srv = line.split()[-1]
                logging_cfg.syslog_servers.append(srv)
            elif line.startswith("logging buffered"):
                logging_cfg.enabled = True
                parts = line.split()
                # e.g., logging buffered 64000 informational (or numeric level)
                for p in parts:
                    if p.isdigit() and int(p) <= 7:
                        logging_cfg.buffered_level = int(p)
                    elif p in ["emergencies", "alerts", "critical", "errors", "warnings", "notifications", "informational", "debugging"]:
                        mapping = {"emergencies": 0, "alerts": 1, "critical": 2, "errors": 3, "warnings": 4, "notifications": 5, "informational": 6, "debugging": 7}
                        logging_cfg.buffered_level = mapping.get(p, 6)
            elif line.startswith("logging console"):
                logging_cfg.enabled = True
                logging_cfg.console_logging = True
            elif line.startswith("service timestamps log"):
                logging_cfg.timestamp_enabled = True

            # NTP
            if line.startswith("ntp server "):
                srv = line.split("ntp server ", 1)[1].split()[0]
                ntp.servers.append(srv)
            elif line == "ntp authenticate":
                ntp.authenticated = True

            # SNMP
            if line.startswith("snmp-server community "):
                snmp.v1_v2c_enabled = True
                parts = line.split()
                if len(parts) >= 3:
                    comm = parts[2].lower()
                    snmp.communities.append(comm)
                    if comm in ["public", "private", "cisco", "monitor", "manager", "admin"]:
                        snmp.default_community_used = True
            elif "snmp-server group" in line and "v3" in line:
                snmp.v3_enabled = True
            elif line.startswith("snmp-server user "):
                snmp.v3_enabled = True
                snmp.v3_users.append(line.split()[2])

            # Insecure / legacy services
            if line == "ip http server":
                http_server_enabled = True
            elif line == "ip http secure-server":
                https_server_enabled = True
            if line in ["service finger", "ip finger"]:
                insecure_services.append("finger")
            if "ip source-route" in line and not line.startswith("no "):
                insecure_services.append("ip source-route")
            if "ip bootp server" in line and not line.startswith("no "):
                insecure_services.append("bootp")
            if "service tcp-small-servers" in line and not line.startswith("no "):
                insecure_services.append("tcp-small-servers")
            if "service udp-small-servers" in line and not line.startswith("no "):
                insecure_services.append("udp-small-servers")

            # Interfaces
            if line.startswith("interface "):
                current_interface = InterfaceConfig(name=line.split("interface ", 1)[1].strip())
                interfaces.append(current_interface)
            elif current_interface and line.startswith("ip address "):
                parts = line.split()
                if len(parts) >= 3 and parts[2] != "negotiated":
                    current_interface.ip_address = parts[2]
            elif current_interface and line == "shutdown":
                current_interface.is_shutdown = True

            # Access Lists (ACLs / Firewall)
            if line.startswith("ip access-list extended ") or line.startswith("ip access-list standard "):
                current_acl = line.split()[-1]
            elif line.startswith("access-list ") or (current_acl and (line.startswith("permit ") or line.startswith("deny "))):
                rule_line = line
                action = "permit" if "permit" in rule_line else ("deny" if "deny" in rule_line else "unknown")
                rule_id = f"acl_{len(firewall_rules) + 1}"
                
                # Check unrestricted: permit ip any any or permit any any
                is_unrestricted = False
                tokens = rule_line.split()
                if "permit" in tokens:
                    p_idx = tokens.index("permit")
                    rem = tokens[p_idx+1:]
                    if len(rem) >= 2 and (rem[0] in ["ip", "tcp", "udp", "any"]) and (rem[-1] == "any" and rem[-2] == "any"):
                        is_unrestricted = True
                    elif "any" in rem and rem.count("any") >= 2:
                        is_unrestricted = True

                firewall_rules.append(FirewallRule(
                    rule_id=rule_id,
                    name=current_acl or "standard_acl",
                    action=action,
                    is_unrestricted=is_unrestricted,
                    logging_enabled=("log" in tokens)
                ))

            # Crypto
            if line.startswith("crypto isakmp policy") or line.startswith("crypto ipsec transform-set"):
                crypto.vpn_configured = True
                if "3des" in line or "des" in line or "md5" in line:
                    crypto.legacy_ciphers_detected.append(line)
                if "aes" in line or "sha256" in line or "sha384" in line or "group 14" in line:
                    crypto.modern_ciphers = True

        # Check default deny: Cisco ACLs have implicit deny all at end, but explicit deny log is best practice
        if any(r.action == "deny" and ("any" in r.rule_id or "deny" in r.name.lower()) for r in firewall_rules) or len(firewall_rules) > 0:
            default_deny = True

        return NormalizedConfiguration(
            vendor=self.vendor_name,
            device_type="Router/Switch",
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
            insecure_services=list(set(insecure_services)),
            firewall_rules=firewall_rules,
            default_deny=default_deny,
            interfaces=interfaces
        )
