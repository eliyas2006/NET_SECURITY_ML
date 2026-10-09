"""
Palo Alto PAN-OS Remediation Engine.
Generates syntactically validated PAN-OS set configuration commands for failed Project Security Controls.

TARGET SOFTWARE VERSIONS:
- Palo Alto PAN-OS 10.1 / 11.0 / 11.1

OPERATIONAL SAFETY NOTICE:
Generated remediation is a reviewable configuration artifact and is not automatically deployed.
Always evaluate proposed commands in a staging or sandbox topology before executing on production devices.
Remember that PAN-OS configuration changes require explicit 'commit' execution to become active in running-config.
"""

from typing import Optional, List
from backend.app.schemas.compliance import ComplianceFinding
from backend.app.schemas.normalized import NormalizedConfiguration
from backend.app.remediation.base import BaseRemediator
from backend.app.remediation.models import RemediationAction, SafetyClassification


class PaloAltoRemediator(BaseRemediator):
    @property
    def vendor_name(self) -> str:
        return "Palo Alto"

    @property
    def file_extension(self) -> str:
        return ".set"

    @property
    def comment_prefix(self) -> str:
        return "#"

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
                problem_description="SSH management cipher suite is unhardened or permits legacy algorithms.",
                evidence=finding.evidence,
                remediation_description="Restrict SSH management to modern authenticated encryption ciphers (AES-GCM/CTR).",
                commands=[
                    "set deviceconfig system ssh ciphers mgmt aes256-gcm",
                    "set deviceconfig system ssh ciphers mgmt aes256-ctr",
                    "commit"
                ],
                validation_commands=[
                    "show deviceconfig system ssh"
                ],
                rollback_commands=[
                    "delete deviceconfig system ssh ciphers mgmt",
                    "commit"
                ],
                safety_classification=SafetyClassification.REVIEW_REQUIRED,
                warning="Restricting SSH management ciphers may terminate sessions using legacy or unsupported ciphers. Ensure console access is available prior to committing.",
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
                problem_description="Telnet remote management service is permitted on device.",
                evidence=finding.evidence,
                remediation_description="Disable Telnet administrative service explicitly in device configuration.",
                commands=[
                    "set deviceconfig system service disable-telnet yes",
                    "commit"
                ],
                validation_commands=[
                    "show deviceconfig system service"
                ],
                rollback_commands=[
                    "set deviceconfig system service disable-telnet no",
                    "commit"
                ],
                safety_classification=SafetyClassification.REVIEW_REQUIRED,
                warning="CRITICAL: Disables Telnet management service. Ensure SSH or Web management access is operational prior to committing.",
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
                problem_description="Plaintext HTTP administration is enabled without SSL/TLS requirement.",
                evidence=finding.evidence,
                remediation_description="Disable unencrypted HTTP web management interface.",
                commands=[
                    "set deviceconfig system service disable-http yes",
                    "commit"
                ],
                validation_commands=[
                    "show deviceconfig system service"
                ],
                rollback_commands=[
                    "set deviceconfig system service disable-http no",
                    "commit"
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
                problem_description="Password encryption verification.",
                evidence=finding.evidence,
                remediation_description="PAN-OS natively protects all administrative credentials and pre-shared keys via master key encryption.",
                commands=[
                    "# PAN-OS protects credentials by default using AES-256-CBC master key store."
                ],
                validation_commands=[
                    "show system masterkey-properties"
                ],
                rollback_commands=[
                    "# Not applicable."
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
                problem_description="Password complexity enforcement is inactive.",
                evidence=finding.evidence,
                remediation_description="Enable administrative password complexity profiles requiring mixed character sets.",
                commands=[
                    "set mgt-config password-complexity enabled yes",
                    "commit"
                ],
                validation_commands=[
                    "show mgt-config password-complexity"
                ],
                rollback_commands=[
                    "set mgt-config password-complexity enabled no",
                    "commit"
                ],
                safety_classification=SafetyClassification.SAFE_AUTOMATIC,
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
                problem_description="Minimum password length is below the enterprise requirement of 14 characters.",
                evidence=finding.evidence,
                remediation_description="Enforce a minimum length of 14 characters in the management password complexity profile.",
                commands=[
                    "set mgt-config password-complexity enabled yes",
                    "set mgt-config password-complexity minimum-length 14",
                    "commit"
                ],
                validation_commands=[
                    "show mgt-config password-complexity"
                ],
                rollback_commands=[
                    "set mgt-config password-complexity minimum-length 8",
                    "commit"
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
                problem_description="Administrative session idle timeout exceeds 15 minutes.",
                evidence=finding.evidence,
                remediation_description="Set CLI and Web session idle timeout to 10 minutes.",
                commands=[
                    "set deviceconfig setting management idle-timeout 10",
                    "commit"
                ],
                validation_commands=[
                    "show cli idle-timeout"
                ],
                rollback_commands=[
                    "set deviceconfig setting management idle-timeout 30",
                    "commit"
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
                problem_description="System login legal warning banner is not configured.",
                evidence=finding.evidence,
                remediation_description="Configure corporate warning banner for all administrative logins.",
                commands=[
                    'set deviceconfig system login-banner "Authorized Access Only. All network activities are logged and monitored. Unauthorized access is prohibited."',
                    "commit"
                ],
                validation_commands=[
                    "show deviceconfig system login-banner"
                ],
                rollback_commands=[
                    "delete deviceconfig system login-banner",
                    "commit"
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
                problem_description="Centralized AAA authentication profile (RADIUS/TACACS+) is not defined.",
                evidence=finding.evidence,
                remediation_description="Define centralized authentication profile referencing enterprise RADIUS/TACACS+ servers.",
                commands=[
                    'set shared authentication-profile "ENTERPRISE_RADIUS" method radius server-profile "<SERVER_PROFILE_NAME>"',
                    "commit"
                ],
                validation_commands=[
                    "show shared authentication-profile"
                ],
                rollback_commands=[
                    'delete shared authentication-profile "ENTERPRISE_RADIUS"',
                    "commit"
                ],
                safety_classification=SafetyClassification.REVIEW_REQUIRED,
                placeholders=["<SERVER_PROFILE_NAME>"],
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
                problem_description="Syslog forwarding profile to central SIEM is absent.",
                evidence=finding.evidence,
                remediation_description="Configure syslog server profile directing traffic, threat, and system logs to external SIEM.",
                commands=[
                    'set shared log-settings syslog "Central-SIEM" server "SIEM-Collector" server "<SIEM_SERVER_IP>"',
                    'set shared log-settings syslog "Central-SIEM" server "SIEM-Collector" transport UDP',
                    'set shared log-settings syslog "Central-SIEM" server "SIEM-Collector" port 514',
                    'set shared log-settings syslog "Central-SIEM" server "SIEM-Collector" format BSD',
                    'set shared log-settings syslog "Central-SIEM" server "SIEM-Collector" facility LOG_USER',
                    "commit"
                ],
                validation_commands=[
                    "show shared log-settings syslog"
                ],
                rollback_commands=[
                    'delete shared log-settings syslog "Central-SIEM"',
                    "commit"
                ],
                safety_classification=SafetyClassification.REVIEW_REQUIRED,
                placeholders=["<SIEM_SERVER_IP>"],
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
                problem_description="NTP time servers are unconfigured in system deviceconfig.",
                evidence=finding.evidence,
                remediation_description="Configure authoritative primary and secondary NTP time servers.",
                commands=[
                    'set deviceconfig system ntp-servers primary-ntp-server ntp-server-address "<PRIMARY_NTP_IP>"',
                    'set deviceconfig system ntp-servers secondary-ntp-server ntp-server-address "<SECONDARY_NTP_IP>"',
                    "commit"
                ],
                validation_commands=[
                    "show system ntp"
                ],
                rollback_commands=[
                    "delete deviceconfig system ntp-servers",
                    "commit"
                ],
                safety_classification=SafetyClassification.REVIEW_REQUIRED,
                placeholders=["<PRIMARY_NTP_IP>", "<SECONDARY_NTP_IP>"],
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
                problem_description="Default SNMP community string ('public' / 'private') detected in SNMP settings.",
                evidence=finding.evidence,
                remediation_description="Remove public community string from SNMP agent settings.",
                commands=[
                    "delete deviceconfig system snmp-setting access-setting version v2c snmp-community-string",
                    "commit"
                ],
                validation_commands=[
                    "show deviceconfig system snmp-setting"
                ],
                rollback_commands=[
                    "# Do not re-enable default SNMP communities."
                ],
                safety_classification=SafetyClassification.REVIEW_REQUIRED,
                warning="Removing SNMP community strings terminates polling from external monitoring systems until reconfigured.",
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
                problem_description="SNMPv3 encrypted user is not configured.",
                evidence=finding.evidence,
                remediation_description="Configure SNMPv3 user profile with SHA authentication and AES encryption.",
                commands=[
                    'set deviceconfig system snmp-setting access-setting version v3 users "<SNMPV3_USERNAME>" authproto SHA privproto AES authpwd "<AUTH_PASSWORD>" privpwd "<PRIV_PASSWORD>"',
                    "commit"
                ],
                validation_commands=[
                    "show deviceconfig system snmp-setting"
                ],
                rollback_commands=[
                    'delete deviceconfig system snmp-setting access-setting version v3 users "<SNMPV3_USERNAME>"',
                    "commit"
                ],
                safety_classification=SafetyClassification.REVIEW_REQUIRED,
                placeholders=["<SNMPV3_USERNAME>", "<AUTH_PASSWORD>", "<PRIV_PASSWORD>"],
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
                problem_description="Legacy services check.",
                evidence=finding.evidence,
                remediation_description="PAN-OS does not contain legacy Berkeley small-servers (finger/bootp).",
                commands=[
                    "# PAN-OS architecture does not run legacy diagnostic daemons."
                ],
                validation_commands=[
                    "show system state"
                ],
                rollback_commands=[
                    "# Not applicable."
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
                problem_description="Security rulebase contains an unrestricted any-any permit rule.",
                evidence=finding.evidence,
                remediation_description="MANUAL REVIEW REQUIRED: Delete wildcard allow policy and replace with specific App-ID security policies.",
                commands=[
                    "# MANUAL REVIEW REQUIRED: Inspect rulebase and define specific App-ID rules:",
                    "# Step 1: show rulebase security rules",
                    "# Step 2: delete rulebase security rules <UNRESTRICTED_RULE_NAME>",
                    "# Step 3: commit"
                ],
                validation_commands=[
                    "show rulebase security rules"
                ],
                rollback_commands=[
                    "# Verify application dependencies before altering security rules."
                ],
                safety_classification=SafetyClassification.MANUAL_ONLY,
                warning="CRITICAL: Deleting access rules without traffic profiling will disrupt business applications.",
                placeholders=["<UNRESTRICTED_RULE_NAME>"],
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
                problem_description="Default deny drop stance requires explicit session logging.",
                evidence=finding.evidence,
                remediation_description="Override pre-defined interzone-default security rule to enable session-end logging for all dropped cross-zone traffic.",
                commands=[
                    "set rulebase default-security-rules rules interzone-default log-end yes",
                    "commit"
                ],
                validation_commands=[
                    "show rulebase default-security-rules rules interzone-default"
                ],
                rollback_commands=[
                    "delete rulebase default-security-rules rules interzone-default log-end",
                    "commit"
                ],
                safety_classification=SafetyClassification.REVIEW_REQUIRED,
                warning="Logging all default dropped interzone traffic can substantially increase firewall and SIEM log ingestion rates. Verify logging capacity before committing.",
                affected_component="Firewall & ACL"
            )

        return None
