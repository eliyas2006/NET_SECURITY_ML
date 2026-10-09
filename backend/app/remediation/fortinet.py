"""
Fortinet FortiOS Remediation Engine.
Generates syntactically validated FortiOS CLI configuration stanzas for failed Project Security Controls.

TARGET SOFTWARE VERSIONS:
- Fortinet FortiOS 7.0 / 7.2 / 7.4

OPERATIONAL SAFETY NOTICE:
Generated remediation is a reviewable configuration artifact and is not automatically deployed.
Always evaluate proposed commands in a staging or sandbox topology before executing on production devices.
"""

from typing import Optional, List
from backend.app.schemas.compliance import ComplianceFinding
from backend.app.schemas.normalized import NormalizedConfiguration
from backend.app.remediation.base import BaseRemediator
from backend.app.remediation.models import RemediationAction, SafetyClassification


class FortinetRemediator(BaseRemediator):
    @property
    def vendor_name(self) -> str:
        return "Fortinet"

    @property
    def file_extension(self) -> str:
        return ".conf"

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
                problem_description="Administrative SSH access is disabled or using weak cipher suites.",
                evidence=finding.evidence,
                remediation_description="Ensure administrative SSH port is enabled on default port 22 and restricted to strong ciphers.",
                commands=[
                    "config system global",
                    "    set admin-ssh-port 22",
                    "    set strong-crypto enable",
                    "end"
                ],
                validation_commands=[
                    "get system status",
                    "show system global | grep -E 'admin-ssh-port|strong-crypto'"
                ],
                rollback_commands=[
                    "config system global",
                    "    set strong-crypto disable",
                    "end"
                ],
                safety_classification=SafetyClassification.SAFE_AUTOMATIC,
                affected_component="SSH"
            )

        # -------------------------------------------------------------
        # PSC-1.2: Telnet Disablement
        # -------------------------------------------------------------
        elif cid == "PSC-1.2":
            iface_hint = "<INTERFACE_NAME>"
            if cfg and cfg.interfaces:
                # Find an interface with telnet if available
                for iface in cfg.interfaces:
                    if "telnet" in iface.management_protocols:
                        iface_hint = iface.name
                        break

            telnet_cmds = [
                "config system global",
                "    set admin-telnet disable",
                "end"
            ]
            telnet_rollback = [
                "config system global",
                "    set admin-telnet enable",
                "end"
            ]
            if iface_hint != "<INTERFACE_NAME>":
                telnet_cmds.extend([
                    "config system interface",
                    f'    edit "{iface_hint}"',
                    "        unselect allowaccess telnet",
                    "    next",
                    "end"
                ])
                telnet_rollback.extend([
                    "config system interface",
                    f'    edit "{iface_hint}"',
                    "        append allowaccess telnet",
                    "    next",
                    "end"
                ])

            return RemediationAction(
                control_id=cid,
                control_title=finding.title,
                vendor=self.vendor_name,
                severity=finding.severity,
                problem_description="Telnet service is enabled in allowaccess on management interface.",
                evidence=finding.evidence,
                remediation_description="Disable Telnet globally and remove telnet from interface allowaccess settings.",
                commands=telnet_cmds,
                validation_commands=[
                    "show system global | grep admin-telnet",
                    f'show system interface "{iface_hint}"' if iface_hint != "<INTERFACE_NAME>" else "show system interface"
                ],
                rollback_commands=telnet_rollback,
                safety_classification=SafetyClassification.REVIEW_REQUIRED,
                warning="CRITICAL: Existing Telnet sessions will be terminated immediately. Confirm that SSH or HTTPS access is tested and operational before applying to prevent management lockout.",
                placeholders=[] if iface_hint != "<INTERFACE_NAME>" else ["<INTERFACE_NAME> (optional interface scope)"],
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
                problem_description="Plaintext HTTP administration is enabled without automatic HTTPS redirection.",
                evidence=finding.evidence,
                remediation_description="Enable global HTTP-to-HTTPS redirect to force all web management traffic onto encrypted TLS.",
                commands=[
                    "config system global",
                    "    set admin-https-redirect enable",
                    "end"
                ],
                validation_commands=[
                    "show system global | grep admin-https-redirect"
                ],
                rollback_commands=[
                    "config system global",
                    "    set admin-https-redirect disable",
                    "end"
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
                problem_description="Verify that global configuration password encryption is active.",
                evidence=finding.evidence,
                remediation_description="FortiOS enforces default proprietary reversible encryption ('ENC ...') for all stored secrets in configuration files.",
                commands=[
                    "# FortiOS enforces encryption by default; no explicit CLI toggle is required."
                ],
                validation_commands=[
                    "show system admin"
                ],
                rollback_commands=[
                    "# Not applicable for FortiOS default encryption architecture."
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
                problem_description="Weak password policy detected; admin credentials lack complexity enforcement.",
                evidence=finding.evidence,
                remediation_description="Activate global password policy enforcement applying to administrator accounts.",
                commands=[
                    "config system password-policy",
                    "    set status enable",
                    "    set apply-to admin-password",
                    "end"
                ],
                validation_commands=[
                    "show system password-policy"
                ],
                rollback_commands=[
                    "config system password-policy",
                    "    set status disable",
                    "end"
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
                problem_description="Minimum password length is below the enterprise compliance threshold of 14 characters.",
                evidence=finding.evidence,
                remediation_description="Configure FortiOS password policy to mandate minimum length of 14 characters.",
                commands=[
                    "config system password-policy",
                    "    set status enable",
                    "    set minimum-length 14",
                    "end"
                ],
                validation_commands=[
                    "show system password-policy"
                ],
                rollback_commands=[
                    "config system password-policy",
                    "    set minimum-length 8",
                    "end"
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
                problem_description="Administrative session inactivity timeout exceeds 15 minutes or is set to 0.",
                evidence=finding.evidence,
                remediation_description="Set administrative session inactivity timeout to 10 minutes.",
                commands=[
                    "config system global",
                    "    set admintimeout 10",
                    "end"
                ],
                validation_commands=[
                    "show system global | grep admintimeout"
                ],
                rollback_commands=[
                    "config system global",
                    "    set admintimeout 30",
                    "end"
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
                problem_description="Pre-login legal warning banner is disabled.",
                evidence=finding.evidence,
                remediation_description="Enable pre-login legal warning banner.",
                commands=[
                    "config system global",
                    "    set pre-login-banner enable",
                    "end"
                ],
                validation_commands=[
                    "show system global | grep pre-login-banner"
                ],
                rollback_commands=[
                    "config system global",
                    "    set pre-login-banner disable",
                    "end"
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
                problem_description="Centralized AAA authentication (TACACS+ or RADIUS) is not configured.",
                evidence=finding.evidence,
                remediation_description="Configure centralized TACACS+ server entry for administrative authentication.",
                commands=[
                    "config user tacacs+",
                    '    edit "ENTERPRISE_TACACS"',
                    '        set server "<TACACS_SERVER_IP>"',
                    '        set key "<SHARED_SECRET_KEY>"',
                    "        set authen-type pap",
                    "        set authorization enable",
                    "    next",
                    "end"
                ],
                validation_commands=[
                    "show user tacacs+"
                ],
                rollback_commands=[
                    "config user tacacs+",
                    '    delete "ENTERPRISE_TACACS"',
                    "end"
                ],
                safety_classification=SafetyClassification.REVIEW_REQUIRED,
                warning="Verify TACACS server IP and shared key. Maintain local administrator access as secondary fallback.",
                placeholders=["<TACACS_SERVER_IP>", "<SHARED_SECRET_KEY>"],
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
                problem_description="Remote syslog forwarding to enterprise SIEM is disabled.",
                evidence=finding.evidence,
                remediation_description="Enable remote syslog daemon setting and configure target SIEM collector address.",
                commands=[
                    "config log syslogd setting",
                    "    set status enable",
                    '    set server "<SIEM_SYSLOG_SERVER_IP>"',
                    "    set mode udp",
                    "    set port 514",
                    "end"
                ],
                validation_commands=[
                    "get log syslogd setting"
                ],
                rollback_commands=[
                    "config log syslogd setting",
                    "    set status disable",
                    "end"
                ],
                safety_classification=SafetyClassification.REVIEW_REQUIRED,
                placeholders=["<SIEM_SYSLOG_SERVER_IP>"],
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
                problem_description="NTP time synchronization is unconfigured or not pointing to authoritative internal time sources.",
                evidence=finding.evidence,
                remediation_description="Configure authoritative NTP server with periodic synchronization.",
                commands=[
                    "config system ntp",
                    "    set ntpsync enable",
                    "    set type custom",
                    "    set syncinterval 60",
                    "    config ntpserver",
                    "        edit 1",
                    '            set server "<NTP_SERVER_IP>"',
                    "        next",
                    "    end",
                    "end"
                ],
                validation_commands=[
                    "diagnose sys ntp status"
                ],
                rollback_commands=[
                    "config system ntp",
                    "    set ntpsync disable",
                    "end"
                ],
                safety_classification=SafetyClassification.REVIEW_REQUIRED,
                placeholders=["<NTP_SERVER_IP>"],
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
                problem_description="Well-known default community string ('public' / 'private') detected in SNMP configuration.",
                evidence=finding.evidence,
                remediation_description="Delete default SNMP community table entry.",
                commands=[
                    "config system snmp community",
                    '    delete "<DEFAULT_COMMUNITY_ID>"',
                    "end"
                ],
                validation_commands=[
                    "show system snmp community"
                ],
                rollback_commands=[
                    "# Do not re-enable default SNMP communities."
                ],
                safety_classification=SafetyClassification.REVIEW_REQUIRED,
                warning="Query 'show system snmp community' to determine the exact numeric index of the default community table entry before deletion.",
                placeholders=["<DEFAULT_COMMUNITY_ID>"],
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
                remediation_description="Configure SNMPv3 user enforcing SHA authentication and AES encryption (auth-priv).",
                commands=[
                    "config system snmp user",
                    '    edit "<SNMPV3_USERNAME>"',
                    "        set security-level auth-priv",
                    "        set auth-proto sha",
                    '        set auth-pwd "<AUTH_PASSPHRASE>"',
                    "        set priv-proto aes",
                    '        set priv-pwd "<PRIV_PASSPHRASE>"',
                    "        set status enable",
                    "    next",
                    "end"
                ],
                validation_commands=[
                    "show system snmp user"
                ],
                rollback_commands=[
                    "config system snmp user",
                    '    delete "<SNMPV3_USERNAME>"',
                    "end"
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
                problem_description="Insecure diagnostic services check.",
                evidence=finding.evidence,
                remediation_description="FortiOS does not incorporate legacy Berkeley small-servers (finger/bootp).",
                commands=[
                    "# FortiOS does not operate legacy diagnostic daemons."
                ],
                validation_commands=[
                    "get system status"
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
                problem_description="Firewall policy table contains wildcard any-any permit rule (srcaddr=all, dstaddr=all, action=accept).",
                evidence=finding.evidence,
                remediation_description="MANUAL REVIEW REQUIRED: Delete or restrict wildcard firewall policy. Define explicit zone, address, and service objects.",
                commands=[
                    "# MANUAL REVIEW REQUIRED: Inspect policy table and remove wildcard permit:",
                    "# Step 1: show firewall policy",
                    "# Step 2: config firewall policy",
                    "# Step 3:     delete <POLICY_ID>",
                    "# Step 4: end"
                ],
                validation_commands=[
                    "show firewall policy"
                ],
                rollback_commands=[
                    "# Verify policy requirements in staging before modification."
                ],
                safety_classification=SafetyClassification.MANUAL_ONLY,
                warning="CRITICAL: Deleting firewall policies without traffic profiling will disrupt business communications.",
                placeholders=["<POLICY_ID>"],
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
                problem_description="Default deny stance requires explicit logging of dropped traffic.",
                evidence=finding.evidence,
                remediation_description="FortiOS enforces an implicit deny policy at rulebase termination; enable fwpolicy-implicit-log to log all dropped traffic.",
                commands=[
                    "config log setting",
                    "    set fwpolicy-implicit-log enable",
                    "end"
                ],
                validation_commands=[
                    "get log setting",
                    "show log setting | grep fwpolicy-implicit-log"
                ],
                rollback_commands=[
                    "config log setting",
                    "    set fwpolicy-implicit-log disable",
                    "end"
                ],
                safety_classification=SafetyClassification.SAFE_AUTOMATIC,
                warning="Enabling implicit deny logging on high-traffic firewalls increases log volume. Verify external syslog or FortiAnalyzer logging capacity.",
                affected_component="Firewall & ACL"
            )

        return None
