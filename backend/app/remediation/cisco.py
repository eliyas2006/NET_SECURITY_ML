"""
Cisco IOS / IOS-XE Remediation Engine.
Generates syntactically validated Cisco CLI commands for failed Project Security Controls.

TARGET SOFTWARE VERSIONS:
- Cisco IOS 15.x
- Cisco IOS-XE 16.12+ / 17.x

OPERATIONAL SAFETY NOTICE:
Generated remediation is a reviewable configuration artifact and is not automatically deployed.
Always evaluate proposed commands in a staging or sandbox topology before executing on production devices.
"""

from typing import Optional, List
from backend.app.schemas.compliance import ComplianceFinding
from backend.app.schemas.normalized import NormalizedConfiguration
from backend.app.remediation.base import BaseRemediator
from backend.app.remediation.models import RemediationAction, SafetyClassification


class CiscoRemediator(BaseRemediator):
    @property
    def vendor_name(self) -> str:
        return "Cisco"

    @property
    def file_extension(self) -> str:
        return ".cfg"

    @property
    def comment_prefix(self) -> str:
        return "!"

    def generate_action(
        self,
        finding: ComplianceFinding,
        cfg: Optional[NormalizedConfiguration] = None
    ) -> Optional[RemediationAction]:
        cid = finding.control_id

        # -------------------------------------------------------------
        # PSC-1.1: SSH Enforcement
        # -------------------------------------------------------------
        if cid == "PSC-1.1":
            return RemediationAction(
                control_id=cid,
                control_title=finding.title,
                vendor=self.vendor_name,
                severity=finding.severity,
                problem_description="SSH is disabled, unconfigured, or using deprecated SSHv1.",
                evidence=finding.evidence,
                remediation_description="Generate a 2048-bit RSA key pair and enforce SSH version 2 with a 60-second authentication timeout.",
                commands=[
                    "crypto key generate rsa modulus 2048",
                    "ip ssh version 2",
                    "ip ssh timeout 60"
                ],
                validation_commands=[
                    "show ip ssh",
                    "show crypto key mypubkey rsa"
                ],
                rollback_commands=[
                    "no ip ssh",
                    "crypto key zeroize rsa"
                ],
                safety_classification=SafetyClassification.REVIEW_REQUIRED,
                warning="Generating RSA keys requires an existing non-empty domain-name ('ip domain-name <DOMAIN>'). Verify domain name exists before applying.",
                placeholders=["<DOMAIN> (if 'ip domain-name' is not configured)"],
                affected_component="SSH"
            )

        # -------------------------------------------------------------
        # PSC-1.2: Telnet Disablement
        # -------------------------------------------------------------
        elif cid == "PSC-1.2":
            return RemediationAction(
                control_id=cid,
                control_title=finding.title,
                vendor=self.vendor_name,
                severity=finding.severity,
                problem_description="Telnet remote management is enabled on terminal lines, exposing credentials in plaintext.",
                evidence=finding.evidence,
                remediation_description="Restrict VTY line transport input exclusively to encrypted SSH sessions.",
                commands=[
                    "line vty 0 15",
                    " transport input ssh",
                    "exit"
                ],
                validation_commands=[
                    "show running-config | section line vty"
                ],
                rollback_commands=[
                    "line vty 0 15",
                    " transport input all",
                    "exit"
                ],
                safety_classification=SafetyClassification.REVIEW_REQUIRED,
                warning="CRITICAL: Existing Telnet sessions will be terminated immediately. Confirm that SSH access is tested and fully operational before applying to prevent management lockout.",
                affected_component="Remote Management"
            )

        # -------------------------------------------------------------
        # PSC-1.3: Plaintext HTTP Server
        # -------------------------------------------------------------
        elif cid == "PSC-1.3":
            return RemediationAction(
                control_id=cid,
                control_title=finding.title,
                vendor=self.vendor_name,
                severity=finding.severity,
                problem_description="Unencrypted administrative HTTP server is active.",
                evidence=finding.evidence,
                remediation_description="Disable plaintext HTTP daemon and ensure secure HTTPS server is active.",
                commands=[
                    "no ip http server",
                    "ip http secure-server"
                ],
                validation_commands=[
                    "show running-config | include ip http"
                ],
                rollback_commands=[
                    "ip http server"
                ],
                safety_classification=SafetyClassification.SAFE_AUTOMATIC,
                affected_component="Web Management"
            )

        # -------------------------------------------------------------
        # PSC-1.4: Service Password Encryption
        # -------------------------------------------------------------
        elif cid == "PSC-1.4":
            return RemediationAction(
                control_id=cid,
                control_title=finding.title,
                vendor=self.vendor_name,
                severity=finding.severity,
                problem_description="Global password encryption service is disabled; credentials may appear cleartext in show running-config.",
                evidence=finding.evidence,
                remediation_description="Enable service password-encryption to obfuscate cleartext passwords in configuration backups.",
                commands=[
                    "service password-encryption"
                ],
                validation_commands=[
                    "show running-config | include service password-encryption"
                ],
                rollback_commands=[
                    "no service password-encryption"
                ],
                safety_classification=SafetyClassification.SAFE_AUTOMATIC,
                affected_component="Authentication"
            )

        # -------------------------------------------------------------
        # PSC-1.5: Strong Password Hashes
        # -------------------------------------------------------------
        elif cid == "PSC-1.5":
            return RemediationAction(
                control_id=cid,
                control_title=finding.title,
                vendor=self.vendor_name,
                severity=finding.severity,
                problem_description="Reversible Cisco Type 7 or legacy MD5 passwords detected in configuration.",
                evidence=finding.evidence,
                remediation_description="Replace weak enable secret and user credentials with SHA-256 (Type 8) or scrypt (Type 9) salted hashes.",
                commands=[
                    "enable algorithm-type sha256 secret <NEW_ENABLE_SECRET_VALUE>",
                    "username admin algorithm-type sha256 secret <NEW_ADMIN_SECRET_VALUE>"
                ],
                validation_commands=[
                    "show running-config | include (enable secret|username.*secret)"
                ],
                rollback_commands=[
                    "! Rollback requires knowing previous valid secret or emergency console recovery."
                ],
                safety_classification=SafetyClassification.REVIEW_REQUIRED,
                warning="DO NOT deploy placeholder credentials to production. The operator must specify high-entropy administrative passwords.",
                placeholders=["<NEW_ENABLE_SECRET_VALUE>", "<NEW_ADMIN_SECRET_VALUE>"],
                affected_component="Authentication"
            )

        # -------------------------------------------------------------
        # PSC-1.6: Minimum Password Length
        # -------------------------------------------------------------
        elif cid == "PSC-1.6":
            return RemediationAction(
                control_id=cid,
                control_title=finding.title,
                vendor=self.vendor_name,
                severity=finding.severity,
                problem_description="Minimum password length threshold is either unconfigured or set below 12 characters.",
                evidence=finding.evidence,
                remediation_description="Configure global minimum password length of at least 14 characters to prevent trivial dictionary guessing.",
                commands=[
                    "security passwords min-length 14"
                ],
                validation_commands=[
                    "show running-config | include security passwords min-length"
                ],
                rollback_commands=[
                    "no security passwords min-length"
                ],
                safety_classification=SafetyClassification.SAFE_AUTOMATIC,
                affected_component="Authentication"
            )

        # -------------------------------------------------------------
        # PSC-1.7: Inactivity Session Timeout
        # -------------------------------------------------------------
        elif cid == "PSC-1.7":
            return RemediationAction(
                control_id=cid,
                control_title=finding.title,
                vendor=self.vendor_name,
                severity=finding.severity,
                problem_description="Terminal line session timeout is absent (0) or exceeds security threshold (>15 min).",
                evidence=finding.evidence,
                remediation_description="Enforce a 10-minute inactivity session timeout on console and VTY lines.",
                commands=[
                    "line con 0",
                    " exec-timeout 10 0",
                    "exit",
                    "line vty 0 15",
                    " exec-timeout 10 0",
                    "exit"
                ],
                validation_commands=[
                    "show running-config | section line"
                ],
                rollback_commands=[
                    "line con 0",
                    " exec-timeout 0 0",
                    "exit",
                    "line vty 0 15",
                    " exec-timeout 0 0",
                    "exit"
                ],
                safety_classification=SafetyClassification.SAFE_AUTOMATIC,
                affected_component="Session Management"
            )

        # -------------------------------------------------------------
        # PSC-1.8: Legal Login Banner
        # -------------------------------------------------------------
        elif cid == "PSC-1.8":
            return RemediationAction(
                control_id=cid,
                control_title=finding.title,
                vendor=self.vendor_name,
                severity=finding.severity,
                problem_description="Legal warning banner MOTD is missing from terminal access.",
                evidence=finding.evidence,
                remediation_description="Deploy standardized MOTD warning banner prohibiting unauthorized access and advising of active monitoring.",
                commands=[
                    "banner motd ^C Authorized Personnel Only. All activities are monitored and logged. Unauthorized access will be prosecuted. ^C"
                ],
                validation_commands=[
                    "show banner motd"
                ],
                rollback_commands=[
                    "no banner motd"
                ],
                safety_classification=SafetyClassification.SAFE_AUTOMATIC,
                affected_component="Access Notice"
            )

        # -------------------------------------------------------------
        # PSC-2.1: Centralized AAA Framework
        # -------------------------------------------------------------
        elif cid == "PSC-2.1":
            return RemediationAction(
                control_id=cid,
                control_title=finding.title,
                vendor=self.vendor_name,
                severity=finding.severity,
                problem_description="Centralized AAA (TACACS+/RADIUS) framework is not enabled; device relies solely on local static credentials.",
                evidence=finding.evidence,
                remediation_description="Enable AAA new-model with TACACS+ server group and local fallback authentication.",
                commands=[
                    "aaa new-model",
                    "aaa group server tacacs+ TACACS_GROUP",
                    " server-private <TACACS_SERVER_IP> key <TACACS_KEY>",
                    "exit",
                    "aaa authentication login default group TACACS_GROUP local",
                    "aaa authorization exec default group TACACS_GROUP local"
                ],
                validation_commands=[
                    "show running-config | include aaa"
                ],
                rollback_commands=[
                    "no aaa new-model"
                ],
                safety_classification=SafetyClassification.REVIEW_REQUIRED,
                warning="CRITICAL: Ensure an active local administrator account exists ('username <user> secret <pwd>') BEFORE applying AAA commands to avoid complete device lockout.",
                placeholders=["<TACACS_SERVER_IP>", "<TACACS_KEY>"],
                affected_component="Authentication"
            )

        # -------------------------------------------------------------
        # PSC-2.2: Remote Syslog / SIEM Forwarding
        # -------------------------------------------------------------
        elif cid == "PSC-2.2":
            return RemediationAction(
                control_id=cid,
                control_title=finding.title,
                vendor=self.vendor_name,
                severity=finding.severity,
                problem_description="System logging is disabled or remote SIEM log forwarding is absent.",
                evidence=finding.evidence,
                remediation_description="Enable informational buffered logging and configure remote syslog forwarding to enterprise SIEM.",
                commands=[
                    "logging buffered 64000 informational",
                    "service timestamps log datetime msec",
                    "logging host <SIEM_OR_SYSLOG_SERVER_IP>"
                ],
                validation_commands=[
                    "show logging"
                ],
                rollback_commands=[
                    "no logging host <SIEM_OR_SYSLOG_SERVER_IP>"
                ],
                safety_classification=SafetyClassification.REVIEW_REQUIRED,
                placeholders=["<SIEM_OR_SYSLOG_SERVER_IP>"],
                affected_component="Auditing & Logging"
            )

        # -------------------------------------------------------------
        # PSC-2.3: NTP Synchronization & Authentication
        # -------------------------------------------------------------
        elif cid == "PSC-2.3":
            return RemediationAction(
                control_id=cid,
                control_title=finding.title,
                vendor=self.vendor_name,
                severity=finding.severity,
                problem_description="NTP time synchronization is not configured or lacks authentication.",
                evidence=finding.evidence,
                remediation_description="Configure synchronized time sources with NTP authentication enabled.",
                commands=[
                    "ntp authenticate",
                    "ntp authentication-key 1 md5 <NTP_MD5_KEY>",
                    "ntp trusted-key 1",
                    "ntp server <PRIMARY_NTP_IP> key 1",
                    "ntp server <SECONDARY_NTP_IP> key 1"
                ],
                validation_commands=[
                    "show ntp status",
                    "show ntp associations"
                ],
                rollback_commands=[
                    "no ntp server <PRIMARY_NTP_IP>",
                    "no ntp server <SECONDARY_NTP_IP>"
                ],
                safety_classification=SafetyClassification.REVIEW_REQUIRED,
                placeholders=["<NTP_MD5_KEY>", "<PRIMARY_NTP_IP>", "<SECONDARY_NTP_IP>"],
                affected_component="Time Synchronization"
            )

        # -------------------------------------------------------------
        # PSC-2.4: Default SNMP Communities
        # -------------------------------------------------------------
        elif cid == "PSC-2.4":
            return RemediationAction(
                control_id=cid,
                control_title=finding.title,
                vendor=self.vendor_name,
                severity=finding.severity,
                problem_description="Factory default SNMP community string ('public' or 'private') detected in configuration.",
                evidence=finding.evidence,
                remediation_description="Remove well-known default community strings immediately to prevent reconnaissance.",
                commands=[
                    "no snmp-server community public",
                    "no snmp-server community private"
                ],
                validation_commands=[
                    "show snmp community"
                ],
                rollback_commands=[
                    "! Do not re-enable default SNMP communities. Deploy SNMPv3 instead."
                ],
                safety_classification=SafetyClassification.REVIEW_REQUIRED,
                warning="Removing default SNMP communities will immediately terminate polling from NMS systems using these strings. Coordinate with monitoring administrators before executing.",
                affected_component="SNMP"
            )

        # -------------------------------------------------------------
        # PSC-2.5: SNMPv3 authPriv Encryption
        # -------------------------------------------------------------
        elif cid == "PSC-2.5":
            return RemediationAction(
                control_id=cid,
                control_title=finding.title,
                vendor=self.vendor_name,
                severity=finding.severity,
                problem_description="SNMP is using unencrypted v1/v2c or lacks modern SNMPv3 authPriv encryption.",
                evidence=finding.evidence,
                remediation_description="Configure SNMPv3 security group and user with SHA authentication and AES-128 encryption.",
                commands=[
                    "snmp-server group SECGROUP v3 priv",
                    "snmp-server user <SNMPV3_USERNAME> SECGROUP v3 auth sha <AUTH_PASSPHRASE> priv aes 128 <PRIV_PASSPHRASE>"
                ],
                validation_commands=[
                    "show snmp group",
                    "show snmp user"
                ],
                rollback_commands=[
                    "no snmp-server user <SNMPV3_USERNAME>"
                ],
                safety_classification=SafetyClassification.REVIEW_REQUIRED,
                placeholders=["<SNMPV3_USERNAME>", "<AUTH_PASSPHRASE>", "<PRIV_PASSPHRASE>"],
                affected_component="SNMP"
            )

        # -------------------------------------------------------------
        # PSC-3.1: Insecure Legacy Diagnostic Services
        # -------------------------------------------------------------
        elif cid == "PSC-3.1":
            return RemediationAction(
                control_id=cid,
                control_title=finding.title,
                vendor=self.vendor_name,
                severity=finding.severity,
                problem_description="Obsolete or diagnostic legacy services (finger, source-route, small-servers) are enabled.",
                evidence=finding.evidence,
                remediation_description="Disable legacy auxiliary services that needlessly expand device attack surface.",
                commands=[
                    "no ip finger",
                    "no service finger",
                    "no ip source-route",
                    "no service tcp-small-servers",
                    "no service udp-small-servers"
                ],
                validation_commands=[
                    "show running-config | include (finger|source-route|small-servers)"
                ],
                rollback_commands=[
                    "service finger"
                ],
                safety_classification=SafetyClassification.SAFE_AUTOMATIC,
                affected_component="Network Services"
            )

        # -------------------------------------------------------------
        # PSC-4.1: Unrestricted Any-Any Firewall Permit Rules
        # -------------------------------------------------------------
        elif cid == "PSC-4.1":
            return RemediationAction(
                control_id=cid,
                control_title=finding.title,
                vendor=self.vendor_name,
                severity=finding.severity,
                problem_description="Firewall access list contains wildcard 'permit ip any any' rule, eliminating network segmentation.",
                evidence=finding.evidence,
                remediation_description="MANUAL REVIEW REQUIRED: Wildcard permit rules must be replaced by least-privilege specific rule declarations (source, destination, port, protocol).",
                commands=[
                    "! MANUAL REVIEW REQUIRED: Inspect rulebase and define specific policy rules.",
                    "! Step 1: Identify required flows in the ACL.",
                    "! Step 2: Remove wildcard rule: no permit ip any any",
                    "! Step 3: Insert least-privilege flow rule: permit <protocol> <source> <destination> eq <port>"
                ],
                validation_commands=[
                    "show access-lists"
                ],
                rollback_commands=[
                    "! Retain existing ACL until new rules are verified."
                ],
                safety_classification=SafetyClassification.MANUAL_ONLY,
                warning="CRITICAL: Deleting an any-any rule without establishing prior specific permit rules will cause immediate production outages for legitimate traffic flows.",
                affected_component="Firewall & ACL"
            )

        # -------------------------------------------------------------
        # PSC-4.2: Default Deny Stance Enforcement
        # -------------------------------------------------------------
        elif cid == "PSC-4.2":
            return RemediationAction(
                control_id=cid,
                control_title=finding.title,
                vendor=self.vendor_name,
                severity=finding.severity,
                problem_description="Explicit default deny log stance is absent at the termination of access lists.",
                evidence=finding.evidence,
                remediation_description="Append explicit deny-all logging entry to terminate extended access lists and log dropped traffic.",
                commands=[
                    "ip access-list extended <ACL_NAME>",
                    " deny ip any any log",
                    "exit"
                ],
                validation_commands=[
                    "show access-lists <ACL_NAME>"
                ],
                rollback_commands=[
                    "! Rollback involves removing explicit deny rule."
                ],
                safety_classification=SafetyClassification.REVIEW_REQUIRED,
                placeholders=["<ACL_NAME>"],
                affected_component="Firewall & ACL"
            )

        return None
