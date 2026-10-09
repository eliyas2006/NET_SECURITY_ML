"""
Deterministic Compliance Rules.
Implements 16 Project Security Controls (PSC) informed by CIS Benchmarks, NIST SP 800-53 Rev. 5, and PCI-DSS.
Controls are documented with their foundational external reference standards.
"""

from typing import List
from backend.app.schemas.normalized import NormalizedConfiguration
from backend.app.schemas.compliance import ComplianceFinding


def evaluate_psc_1_1_ssh(cfg: NormalizedConfiguration) -> ComplianceFinding:
    """PSC-1.1: Ensure SSH is enabled and version 2 is enforced."""
    if cfg.ssh.enabled and cfg.ssh.version == 2:
        return ComplianceFinding(
            control_id="PSC-1.1",
            title="Ensure SSH is Enabled and Version 2 is Enforced",
            standard="Project Security Control [Informed by CIS Cisco IOS Benchmark 15.x v4.1.0 Sec 1.2.2 / NIST SP 800-53 Rev. 5 SC-13, AC-17]",
            status="PASS",
            severity="HIGH",
            evidence=f"SSH is enabled with Version {cfg.ssh.version}.",
            recommendation="Maintain SSHv2 as the mandatory encrypted management protocol.",
            affected_component="SSH"
        )
    elif cfg.ssh.enabled and cfg.ssh.version == 1:
        remed = "ip ssh version 2" if cfg.vendor == "Cisco" else "set ssh-enc-algo chacha20,aes-gcm"
        return ComplianceFinding(
            control_id="PSC-1.1",
            title="Ensure SSH is Enabled and Version 2 is Enforced",
            standard="Project Security Control [Informed by CIS Cisco IOS Benchmark 15.x v4.1.0 Sec 1.2.2 / NIST SP 800-53 Rev. 5 SC-13, AC-17]",
            status="FAIL",
            severity="HIGH",
            evidence="SSH is active but running deprecated SSHv1.",
            recommendation="Upgrade to SSHv2 immediately. SSHv1 is susceptible to CRC32 compensation attacks.",
            remediation_cli=remed,
            affected_component="SSH"
        )
    else:
        remed = "crypto key generate rsa modulus 2048\nip ssh version 2" if cfg.vendor == "Cisco" else "set allowaccess ssh"
        return ComplianceFinding(
            control_id="PSC-1.1",
            title="Ensure SSH is Enabled and Version 2 is Enforced",
            standard="Project Security Control [Informed by CIS Cisco IOS Benchmark 15.x v4.1.0 Sec 1.2.2 / NIST SP 800-53 Rev. 5 SC-13, AC-17]",
            status="FAIL",
            severity="HIGH",
            evidence="SSH is not configured or disabled.",
            recommendation="Generate RSA host keys and enable SSH version 2 for encrypted management.",
            remediation_cli=remed,
            affected_component="SSH"
        )


def evaluate_psc_1_2_telnet(cfg: NormalizedConfiguration) -> ComplianceFinding:
    """PSC-1.2: Ensure Telnet service is disabled."""
    if cfg.telnet_enabled:
        remed = "line vty 0 15\n transport input ssh" if cfg.vendor == "Cisco" else "config system interface\n set allowaccess ssh https\nend"
        return ComplianceFinding(
            control_id="PSC-1.2",
            title="Ensure Telnet Service is Disabled",
            standard="Project Security Control [Informed by CIS Cisco IOS Benchmark 15.x v4.1.0 Sec 1.2.1 / NIST SP 800-53 Rev. 5 AC-17, CM-7]",
            status="FAIL",
            severity="HIGH",
            evidence="Telnet is enabled on administrative line or interface.",
            recommendation="Disable Telnet completely to prevent plaintext credentials from traversing the network.",
            remediation_cli=remed,
            affected_component="Remote Management"
        )
    return ComplianceFinding(
        control_id="PSC-1.2",
        title="Ensure Telnet Service is Disabled",
        standard="Project Security Control [Informed by CIS Cisco IOS Benchmark 15.x v4.1.0 Sec 1.2.1 / NIST SP 800-53 Rev. 5 AC-17, CM-7]",
        status="PASS",
        severity="HIGH",
        evidence="Telnet service is disabled or disallowed on management transports.",
        recommendation="Continue enforcing SSH and disallowing unencrypted Telnet sessions.",
        affected_component="Remote Management"
    )


def evaluate_psc_1_3_http(cfg: NormalizedConfiguration) -> ComplianceFinding:
    """PSC-1.3: Ensure Plaintext HTTP server is disabled."""
    if cfg.http_server_enabled:
        remed = "no ip http server" if cfg.vendor == "Cisco" else "set admin-https-redirect enable"
        return ComplianceFinding(
            control_id="PSC-1.3",
            title="Ensure Plaintext HTTP Server is Disabled",
            standard="Project Security Control [Informed by CIS Cisco IOS Benchmark Sec 1.2.4 / NIST SP 800-53 Rev. 5 SC-8, AC-17]",
            status="FAIL",
            severity="MEDIUM",
            evidence="Unencrypted HTTP server is enabled for administrative access.",
            recommendation="Disable HTTP and enforce HTTPS/TLS for web-based device management.",
            remediation_cli=remed,
            affected_component="Web Management"
        )
    return ComplianceFinding(
        control_id="PSC-1.3",
        title="Ensure Plaintext HTTP Server is Disabled",
        standard="Project Security Control [Informed by CIS Cisco IOS Benchmark Sec 1.2.4 / NIST SP 800-53 Rev. 5 SC-8, AC-17]",
        status="PASS",
        severity="MEDIUM",
        evidence="Plaintext HTTP administration server is not enabled.",
        recommendation="Keep HTTP service disabled; require HTTPS.",
        affected_component="Web Management"
    )


def evaluate_psc_1_4_password_encryption(cfg: NormalizedConfiguration) -> ComplianceFinding:
    """PSC-1.4: Ensure Password Encryption is enabled globally."""
    if cfg.passwords.service_encryption:
        return ComplianceFinding(
            control_id="PSC-1.4",
            title="Ensure Global Password Encryption is Enabled",
            standard="Project Security Control [Informed by CIS Cisco IOS Benchmark Sec 1.1.2 / NIST SP 800-53 Rev. 5 IA-5]",
            status="PASS",
            severity="MEDIUM",
            evidence="Reversible password encryption service is active.",
            recommendation="Maintain global password encryption.",
            affected_component="Authentication"
        )
    remed = "service password-encryption" if cfg.vendor == "Cisco" else "N/A (FortiOS/PAN-OS enforces encryption by default)"
    return ComplianceFinding(
        control_id="PSC-1.4",
        title="Ensure Global Password Encryption is Enabled",
        standard="Project Security Control [Informed by CIS Cisco IOS Benchmark Sec 1.1.2 / NIST SP 800-53 Rev. 5 IA-5]",
        status="FAIL",
        severity="MEDIUM",
        evidence="Password encryption service is disabled; passwords may appear as plain text in configuration backups.",
        recommendation="Enable service password-encryption to obfuscate cleartext passwords in configuration files.",
        remediation_cli=remed,
        affected_component="Authentication"
    )


def evaluate_psc_1_5_strong_passwords(cfg: NormalizedConfiguration) -> ComplianceFinding:
    """PSC-1.5: Ensure Strong Password algorithms are used (no Type 7 or plaintext)."""
    if cfg.passwords.weak_algorithm_count > 0:
        remed = "enable algorithm-type sha256 secret <secret>\nusername <user> algorithm-type sha256 secret <secret>" if cfg.vendor == "Cisco" else "config user local\n edit <user>\n set passwd <strong_pwd>\n next\nend"
        return ComplianceFinding(
            control_id="PSC-1.5",
            title="Ensure Strong Password Hashing Algorithms are Enforced",
            standard="Project Security Control [Informed by CIS Cisco IOS Benchmark Sec 1.1.1 / NIST SP 800-53 Rev. 5 IA-5]",
            status="FAIL",
            severity="HIGH",
            evidence=f"Detected {cfg.passwords.weak_algorithm_count} password(s) using weak/reversible algorithms (Type 7 or plain MD5).",
            recommendation="Replace legacy passwords with strong salted hashes (Type 8 PBKDF2-SHA256 or Type 9 scrypt).",
            remediation_cli=remed,
            affected_component="Authentication"
        )
    return ComplianceFinding(
        control_id="PSC-1.5",
        title="Ensure Strong Password Hashing Algorithms are Enforced",
        standard="Project Security Control [Informed by CIS Cisco IOS Benchmark Sec 1.1.1 / NIST SP 800-53 Rev. 5 IA-5]",
        status="PASS",
        severity="HIGH",
        evidence="No weak Type 7 or plain text passwords found. Strong hashing in place.",
        recommendation="Continue enforcing salted PBKDF2/SHA256 or scrypt hashes.",
        affected_component="Authentication"
    )


def evaluate_psc_1_6_min_password_length(cfg: NormalizedConfiguration) -> ComplianceFinding:
    """PSC-1.6: Ensure Minimum Password Length is at least 12 characters."""
    if cfg.passwords.min_length >= 12:
        return ComplianceFinding(
            control_id="PSC-1.6",
            title="Ensure Minimum Password Length is at Least 12 Characters",
            standard="Project Security Control [Informed by CIS Cisco IOS Benchmark Sec 1.1.3 / NIST SP 800-53 Rev. 5 IA-5]",
            status="PASS",
            severity="MEDIUM",
            evidence=f"Minimum password length is enforced at {cfg.passwords.min_length} characters.",
            recommendation="Maintain minimum password length policy >= 12.",
            affected_component="Authentication"
        )
    remed = "security passwords min-length 14" if cfg.vendor == "Cisco" else "config system password-policy\n set min-length 14\n set status enable\nend"
    return ComplianceFinding(
        control_id="PSC-1.6",
        title="Ensure Minimum Password Length is at Least 12 Characters",
        standard="Project Security Control [Informed by CIS Cisco IOS Benchmark Sec 1.1.3 / NIST SP 800-53 Rev. 5 IA-5]",
        status="FAIL" if cfg.passwords.min_length < 8 else "WARN",
        severity="MEDIUM",
        evidence=f"Configured minimum password length is {cfg.passwords.min_length} (Threshold: 12).",
        recommendation="Enforce a minimum password length of at least 12 characters to deter brute-force attacks.",
        remediation_cli=remed,
        affected_component="Authentication"
    )


def evaluate_psc_1_7_session_timeout(cfg: NormalizedConfiguration) -> ComplianceFinding:
    """PSC-1.7: Ensure Inactivity Session Timeout is configured (<= 15 minutes)."""
    timeout = cfg.auth.exec_timeout_minutes
    if 1 <= timeout <= 15:
        return ComplianceFinding(
            control_id="PSC-1.7",
            title="Ensure Inactivity Session Timeout is Configured",
            standard="Project Security Control [Informed by CIS Cisco IOS Benchmark Sec 1.3.1 / NIST SP 800-53 Rev. 5 AC-12]",
            status="PASS",
            severity="LOW",
            evidence=f"Inactivity timeout configured to {timeout} minute(s).",
            recommendation="Maintain timeout <= 15 minutes.",
            affected_component="Session Management"
        )
    remed = "line con 0\n exec-timeout 10 0\nline vty 0 15\n exec-timeout 10 0" if cfg.vendor == "Cisco" else "config system global\n set admintimeout 10\nend"
    return ComplianceFinding(
        control_id="PSC-1.7",
        title="Ensure Inactivity Session Timeout is Configured",
        standard="Project Security Control [Informed by CIS Cisco IOS Benchmark Sec 1.3.1 / NIST SP 800-53 Rev. 5 AC-12]",
        status="FAIL" if timeout == 0 else "WARN",
        severity="LOW",
        evidence=f"Inactivity timeout is {timeout} minutes (0 indicates no timeout).",
        recommendation="Configure CLI/Web session inactivity timeout to 10-15 minutes to prevent unattended session takeover.",
        remediation_cli=remed,
        affected_component="Session Management"
    )


def evaluate_psc_1_8_login_banner(cfg: NormalizedConfiguration) -> ComplianceFinding:
    """PSC-1.8: Ensure Legal Login Banner is configured."""
    if cfg.auth.login_banner_present:
        return ComplianceFinding(
            control_id="PSC-1.8",
            title="Ensure Warning Login Banner is Configured",
            standard="Project Security Control [Informed by CIS Cisco IOS Benchmark Sec 1.4.1 / NIST SP 800-53 Rev. 5 AC-8]",
            status="PASS",
            severity="LOW",
            evidence="Authorized access legal warning banner is present.",
            recommendation="Maintain login banner forbidding unauthorized access.",
            affected_component="Access Notice"
        )
    remed = "banner motd ^C Authorized Access Only. All activities are monitored and logged. ^C" if cfg.vendor == "Cisco" else "config system global\n set pre-login-banner enable\nend"
    return ComplianceFinding(
        control_id="PSC-1.8",
        title="Ensure Warning Login Banner is Configured",
        standard="Project Security Control [Informed by CIS Cisco IOS Benchmark Sec 1.4.1 / NIST SP 800-53 Rev. 5 AC-8]",
        status="FAIL",
        severity="LOW",
        evidence="No MOTD or login warning banner detected.",
        recommendation="Deploy a legal warning banner stating unauthorized access is strictly prohibited and subject to prosecution.",
        remediation_cli=remed,
        affected_component="Access Notice"
    )


def evaluate_psc_2_1_aaa(cfg: NormalizedConfiguration) -> ComplianceFinding:
    """PSC-2.1: Ensure Centralized AAA authentication is configured."""
    if cfg.auth.aaa_enabled or (len(cfg.auth.radius_servers) > 0 or len(cfg.auth.tacacs_servers) > 0):
        return ComplianceFinding(
            control_id="PSC-2.1",
            title="Ensure Centralized AAA Framework is Configured",
            standard="Project Security Control [Informed by CIS Cisco IOS Benchmark Sec 1.1.4 / NIST SP 800-53 Rev. 5 IA-2, AC-2]",
            status="PASS",
            severity="MEDIUM",
            evidence="Centralized AAA authentication (RADIUS/TACACS+) framework is active.",
            recommendation="Continue authenticating administrative users via enterprise directory services.",
            affected_component="Authentication"
        )
    remed = "aaa new-model\naaa authentication login default group tacacs+ local\naaa authorization exec default group tacacs+ local" if cfg.vendor == "Cisco" else "config system admin\n edit <admin>\n set accprofile-override enable\n next\nend"
    return ComplianceFinding(
        control_id="PSC-2.1",
        title="Ensure Centralized AAA Framework is Configured",
        standard="Project Security Control [Informed by CIS Cisco IOS Benchmark Sec 1.1.4 / NIST SP 800-53 Rev. 5 IA-2, AC-2]",
        status="FAIL",
        severity="MEDIUM",
        evidence="AAA new-model is not configured; device relies on local static accounts.",
        recommendation="Implement centralized AAA (TACACS+ or RADIUS) for granular role-based access and auditable accounting.",
        remediation_cli=remed,
        affected_component="Authentication"
    )


def evaluate_psc_2_2_logging(cfg: NormalizedConfiguration) -> ComplianceFinding:
    """PSC-2.2: Ensure Logging is enabled and remote syslog server is configured."""
    if cfg.logging.enabled and len(cfg.logging.syslog_servers) > 0:
        return ComplianceFinding(
            control_id="PSC-2.2",
            title="Ensure Logging to Remote Syslog/SIEM is Active",
            standard="Project Security Control [Informed by CIS Cisco IOS Benchmark Sec 2.1.1 / NIST SP 800-53 Rev. 5 AU-2, AU-6]",
            status="PASS",
            severity="HIGH",
            evidence=f"Logging enabled with {len(cfg.logging.syslog_servers)} remote syslog destination(s): {', '.join(cfg.logging.syslog_servers)}.",
            recommendation="Maintain log forwarding to SIEM and ensure log timestamps are synchronized.",
            affected_component="Auditing & Logging"
        )
    elif cfg.logging.enabled:
        remed = "logging host 10.10.10.50\nservice timestamps log datetime msec" if cfg.vendor == "Cisco" else "config log syslogd setting\n set status enable\n set server 10.10.10.50\nend"
        return ComplianceFinding(
            control_id="PSC-2.2",
            title="Ensure Logging to Remote Syslog/SIEM is Active",
            standard="Project Security Control [Informed by CIS Cisco IOS Benchmark Sec 2.1.1 / NIST SP 800-53 Rev. 5 AU-2, AU-6]",
            status="WARN",
            severity="HIGH",
            evidence="Logging is enabled locally, but no remote syslog/SIEM server is defined.",
            recommendation="Forward audit logs to an external SIEM to prevent attackers from purging local log buffers.",
            remediation_cli=remed,
            affected_component="Auditing & Logging"
        )
    else:
        remed = "logging buffered 64000 informational\nlogging host 10.10.10.50\nservice timestamps log datetime msec" if cfg.vendor == "Cisco" else "config log syslogd setting\n set status enable\n set server 10.10.10.50\nend"
        return ComplianceFinding(
            control_id="PSC-2.2",
            title="Ensure Logging to Remote Syslog/SIEM is Active",
            standard="Project Security Control [Informed by CIS Cisco IOS Benchmark Sec 2.1.1 / NIST SP 800-53 Rev. 5 AU-2, AU-6]",
            status="FAIL",
            severity="HIGH",
            evidence="System logging is disabled. Security events are not recorded.",
            recommendation="Enable system logging and configure forwarding to centralized SIEM collector.",
            remediation_cli=remed,
            affected_component="Auditing & Logging"
        )


def evaluate_psc_2_3_ntp(cfg: NormalizedConfiguration) -> ComplianceFinding:
    """PSC-2.3: Ensure NTP time synchronization is configured."""
    if len(cfg.ntp.servers) > 0:
        return ComplianceFinding(
            control_id="PSC-2.3",
            title="Ensure NTP Time Synchronization is Configured",
            standard="Project Security Control [Informed by CIS Cisco IOS Benchmark Sec 2.2.1 / NIST SP 800-53 Rev. 5 AU-8]",
            status="PASS",
            severity="MEDIUM",
            evidence=f"NTP configured with {len(cfg.ntp.servers)} server(s): {', '.join(cfg.ntp.servers)}.",
            recommendation="Maintain NTP synchronization across enterprise infrastructure.",
            affected_component="Time Synchronization"
        )
    remed = "ntp server 10.10.10.1\nntp server 10.10.10.2" if cfg.vendor == "Cisco" else "config system ntp\n set ntpserver 10.10.10.1\nend"
    return ComplianceFinding(
        control_id="PSC-2.3",
        title="Ensure NTP Time Synchronization is Configured",
        standard="Project Security Control [Informed by CIS Cisco IOS Benchmark Sec 2.2.1 / NIST SP 800-53 Rev. 5 AU-8]",
        status="FAIL",
        severity="MEDIUM",
        evidence="No NTP servers are configured. System clock may drift.",
        recommendation="Configure authoritative internal NTP servers for forensic log correlation.",
        remediation_cli=remed,
        affected_component="Time Synchronization"
    )


def evaluate_psc_2_4_snmp_default_community(cfg: NormalizedConfiguration) -> ComplianceFinding:
    """PSC-2.4: Ensure SNMP default community strings are removed."""
    if cfg.snmp.default_community_used:
        remed = "no snmp-server community public\nno snmp-server community private" if cfg.vendor == "Cisco" else "config system snmp community\n delete 1\nend"
        return ComplianceFinding(
            control_id="PSC-2.4",
            title="Ensure Default SNMP Community Strings are Removed",
            standard="Project Security Control [Informed by CIS Cisco IOS Benchmark Sec 2.3.1 / NIST SP 800-53 Rev. 5 CM-6, IA-5]",
            status="FAIL",
            severity="HIGH",
            evidence="Detected well-known default SNMP community string ('public', 'private', or vendor default).",
            recommendation="Remove default community strings immediately. Adversaries use these to scan network device state.",
            remediation_cli=remed,
            affected_component="SNMP"
        )
    return ComplianceFinding(
        control_id="PSC-2.4",
        title="Ensure Default SNMP Community Strings are Removed",
        standard="Project Security Control [Informed by CIS Cisco IOS Benchmark Sec 2.3.1 / NIST SP 800-53 Rev. 5 CM-6, IA-5]",
        status="PASS",
        severity="HIGH",
        evidence="No default SNMP community strings detected.",
        recommendation="Continue prohibiting default SNMP community strings.",
        affected_component="SNMP"
    )


def evaluate_psc_2_5_snmpv3(cfg: NormalizedConfiguration) -> ComplianceFinding:
    """PSC-2.5: Ensure SNMPv3 is configured for encrypted network management."""
    if cfg.snmp.v3_enabled:
        return ComplianceFinding(
            control_id="PSC-2.5",
            title="Ensure SNMPv3 is Configured for Management",
            standard="Project Security Control [Informed by CIS Cisco IOS Benchmark Sec 2.3.2 / NIST SP 800-53 Rev. 5 SC-13, AC-17]",
            status="PASS",
            severity="MEDIUM",
            evidence="SNMPv3 encrypted user or group configuration is present.",
            recommendation="Enforce SNMPv3 authPriv for all polling queries.",
            affected_component="SNMP"
        )
    elif cfg.snmp.v1_v2c_enabled:
        remed = "snmp-server group SECGROUP v3 priv\nsnmp-server user secuser SECGROUP v3 auth sha StrongAuthPassword priv aes 128 StrongPrivPassword" if cfg.vendor == "Cisco" else "config system snmp user\n edit snmpv3-user\n set security-level auth-priv\n next\nend"
        return ComplianceFinding(
            control_id="PSC-2.5",
            title="Ensure SNMPv3 is Configured for Management",
            standard="Project Security Control [Informed by CIS Cisco IOS Benchmark Sec 2.3.2 / NIST SP 800-53 Rev. 5 SC-13, AC-17]",
            status="FAIL",
            severity="MEDIUM",
            evidence="SNMPv1/v2c is enabled without SNMPv3 encryption.",
            recommendation="Migrate from plaintext SNMPv1/v2c to SNMPv3 with authPriv encryption.",
            remediation_cli=remed,
            affected_component="SNMP"
        )
    else:
        return ComplianceFinding(
            control_id="PSC-2.5",
            title="Ensure SNMPv3 is Configured for Management",
            standard="Project Security Control [Informed by CIS Cisco IOS Benchmark Sec 2.3.2 / NIST SP 800-53 Rev. 5 SC-13, AC-17]",
            status="PASS",
            severity="MEDIUM",
            evidence="SNMP is disabled; no plaintext SNMP vulnerability exists.",
            recommendation="If SNMP is required in the future, deploy SNMPv3 authPriv.",
            affected_component="SNMP"
        )


def evaluate_psc_3_1_insecure_services(cfg: NormalizedConfiguration) -> ComplianceFinding:
    """PSC-3.1: Ensure Insecure / Legacy Services are disabled."""
    if len(cfg.insecure_services) > 0:
        bad = ", ".join(cfg.insecure_services)
        remed = "\n".join([f"no service {s}" if not s.startswith("ip ") else f"no {s}" for s in cfg.insecure_services])
        return ComplianceFinding(
            control_id="PSC-3.1",
            title="Ensure Insecure Legacy Services are Disabled",
            standard="Project Security Control [Informed by CIS Cisco IOS Benchmark Sec 3.1 / NIST SP 800-53 Rev. 5 CM-7]",
            status="FAIL",
            severity="MEDIUM",
            evidence=f"Detected enabled legacy services: {bad}.",
            recommendation="Disable obsolete and diagnostic services that expand attack surface (finger, bootp, source-route).",
            remediation_cli=remed,
            affected_component="Network Services"
        )
    return ComplianceFinding(
        control_id="PSC-3.1",
        title="Ensure Insecure Legacy Services are Disabled",
        standard="Project Security Control [Informed by CIS Cisco IOS Benchmark Sec 3.1 / NIST SP 800-53 Rev. 5 CM-7]",
        status="PASS",
        severity="MEDIUM",
        evidence="No insecure legacy services (finger, source-route, bootp, small-servers) enabled.",
        recommendation="Continue disabling unnecessary legacy network services.",
        affected_component="Network Services"
    )


def evaluate_psc_4_1_unrestricted_rules(cfg: NormalizedConfiguration) -> ComplianceFinding:
    """PSC-4.1: Ensure Firewall does not contain unrestricted any-to-any permit rules."""
    unrestricted = [r for r in cfg.firewall_rules if r.is_unrestricted]
    if len(unrestricted) > 0:
        rule_names = ", ".join([r.name or r.rule_id for r in unrestricted[:3]])
        remed = "no permit any any" if cfg.vendor == "Cisco" else "config firewall policy\n delete <id>\nend"
        return ComplianceFinding(
            control_id="PSC-4.1",
            title="Ensure Firewall Has No Unrestricted Any-to-Any Permit Rules",
            standard="Project Security Control [Informed by PCI-DSS v4.0 Req 1.3 / NIST SP 800-53 Rev. 5 SC-7]",
            status="FAIL",
            severity="CRITICAL",
            evidence=f"Found {len(unrestricted)} unrestricted permit rule(s) (e.g. {rule_names}) allowing all traffic between any source and destination.",
            recommendation="Eliminate wildcard permit rules. Define least-privilege source, destination, port, and application filters.",
            remediation_cli=remed,
            affected_component="Firewall & ACL"
        )
    return ComplianceFinding(
        control_id="PSC-4.1",
        title="Ensure Firewall Has No Unrestricted Any-to-Any Permit Rules",
        standard="Project Security Control [Informed by PCI-DSS v4.0 Req 1.3 / NIST SP 800-53 Rev. 5 SC-7]",
        status="PASS",
        severity="CRITICAL",
        evidence="No unrestricted any-to-any permit policies found in firewall access rules.",
        recommendation="Maintain strict least-privilege policy definitions.",
        affected_component="Firewall & ACL"
    )


def evaluate_psc_4_2_default_deny(cfg: NormalizedConfiguration) -> ComplianceFinding:
    """PSC-4.2: Ensure Default Deny policy is enforced."""
    if cfg.default_deny or len(cfg.firewall_rules) == 0:
        return ComplianceFinding(
            control_id="PSC-4.2",
            title="Ensure Default Deny Stance is Enforced",
            standard="Project Security Control [Informed by CIS Firewall Benchmark v1.0 / NIST SP 800-53 Rev. 5 SC-7]",
            status="PASS",
            severity="HIGH",
            evidence="Explicit or architectural default deny is active for unpermitted ingress/egress traffic.",
            recommendation="Continue logging dropped packets at policy chain termination.",
            affected_component="Firewall & ACL"
        )
    return ComplianceFinding(
        control_id="PSC-4.2",
        title="Ensure Default Deny Stance is Enforced",
        standard="Project Security Control [Informed by CIS Firewall Benchmark v1.0 / NIST SP 800-53 Rev. 5 SC-7]",
        status="FAIL",
        severity="HIGH",
        evidence="Default deny drop stance is not explicitly declared on policy chains.",
        recommendation="Append an explicit deny-all logging rule to the end of all access lists and security rulebases.",
        remediation_cli="deny ip any any log" if cfg.vendor == "Cisco" else "set action deny",
        affected_component="Firewall & ACL"
    )


ALL_RULES = [
    evaluate_psc_1_1_ssh,
    evaluate_psc_1_2_telnet,
    evaluate_psc_1_3_http,
    evaluate_psc_1_4_password_encryption,
    evaluate_psc_1_5_strong_passwords,
    evaluate_psc_1_6_min_password_length,
    evaluate_psc_1_7_session_timeout,
    evaluate_psc_1_8_login_banner,
    evaluate_psc_2_1_aaa,
    evaluate_psc_2_2_logging,
    evaluate_psc_2_3_ntp,
    evaluate_psc_2_4_snmp_default_community,
    evaluate_psc_2_5_snmpv3,
    evaluate_psc_3_1_insecure_services,
    evaluate_psc_4_1_unrestricted_rules,
    evaluate_psc_4_2_default_deny,
]
