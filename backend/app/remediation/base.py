"""
Base Remediator Interface.
Provides common contract and script rendering abstractions across network device vendors.
"""

from abc import ABC, abstractmethod
from typing import List, Optional
from datetime import datetime, timezone
from backend.app.schemas.compliance import ComplianceFinding
from backend.app.schemas.normalized import NormalizedConfiguration
from backend.app.remediation.models import RemediationAction, SafetyClassification


class BaseRemediator(ABC):
    @property
    @abstractmethod
    def vendor_name(self) -> str:
        """The canonical vendor name (e.g. Cisco, Fortinet, Palo Alto)."""
        pass

    @property
    @abstractmethod
    def file_extension(self) -> str:
        """The canonical file extension (.cfg, .conf, .set)."""
        pass

    @property
    @abstractmethod
    def comment_prefix(self) -> str:
        """Prefix character used for comment lines in vendor CLI (! or #)."""
        pass

    @abstractmethod
    def generate_action(
        self,
        finding: ComplianceFinding,
        cfg: Optional[NormalizedConfiguration] = None
    ) -> Optional[RemediationAction]:
        """Maps a single failed or warning compliance finding to a vendor remediation action."""
        pass

    def format_script(
        self,
        audit_id: str,
        hostname: str,
        actions: List[RemediationAction]
    ) -> str:
        """Formats all generated actions into a cohesive, ready-to-download CLI script."""
        c = self.comment_prefix
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        lines = [
            f"{c} ==============================================================================",
            f"{c} AUTOMATED NETWORK SECURITY COMPLIANCE REMEDIATION SCRIPT",
            f"{c} AI-Driven Multi-Vendor Network Security Compliance Auditor",
            f"{c} ==============================================================================",
            f"{c} Target Vendor:     {self.vendor_name}",
            f"{c} Target Hostname:   {hostname}",
            f"{c} Audit ID:          {audit_id}",
            f"{c} Generated At:      {ts}",
            f"{c} Total Controls:    {len(actions)} Action(s)",
            f"{c} ------------------------------------------------------------------------------",
            f"{c} MANDATORY SAFETY DISCLAIMER:",
            f"{c} - DO NOT blindly execute this script on production networking hardware.",
            f"{c} - Review all proposed commands and dependencies in a lab or staging sandbox.",
            f"{c} - Replace any placeholder values formatted as <PLACEHOLDER> prior to execution.",
            f"{c} - Take an authorized configuration backup and verify rollback procedures.",
            f"{c} ==============================================================================",
            ""
        ]

        if not actions:
            lines.append(f"{c} All evaluated controls passed. No remediation actions required.")
            return "\n".join(lines)

        for idx, act in enumerate(actions, 1):
            lines.append(f"{c} ------------------------------------------------------------------------------")
            lines.append(f"{c} [{idx}/{len(actions)}] Control: {act.control_id} - {act.control_title}")
            lines.append(f"{c} Severity: {act.severity} | Safety: {act.safety_classification.value}")
            lines.append(f"{c} Problem:  {act.problem_description}")
            if act.warning:
                lines.append(f"{c} WARNING:  {act.warning}")
            if act.placeholders:
                lines.append(f"{c} REQUIRED PLACEHOLDERS: {', '.join(act.placeholders)}")
            lines.append(f"{c} ------------------------------------------------------------------------------")

            if act.safety_classification == SafetyClassification.MANUAL_ONLY:
                lines.append(f"{c} [MANUAL ACTION REQUIRED] Automated command generation is disabled for this control.")
                lines.append(f"{c} Recommended Action: {act.remediation_description}")
                for cmd in act.commands:
                    lines.append(f"{c} {cmd}")
            else:
                for cmd in act.commands:
                    lines.append(cmd)

            if act.validation_commands:
                lines.append("")
                lines.append(f"{c} Verification Commands:")
                for vcmd in act.validation_commands:
                    lines.append(f"{c}   {vcmd}")

            lines.append("")

        lines.append(f"{c} ==============================================================================")
        lines.append(f"{c} END OF REMEDIATION SCRIPT - SAVE AND COMMIT CONFIGURATION")
        lines.append(f"{c} ==============================================================================")

        return "\n".join(lines)
