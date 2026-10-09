"""
Remediation Orchestration Engine.
Coordinates mapping compliance violations into vendor remediation plans and compiled script files.
"""

from typing import List, Optional
from datetime import datetime, timezone
from backend.app.schemas.compliance import ComplianceFinding
from backend.app.schemas.normalized import NormalizedConfiguration
from backend.app.remediation.models import RemediationAction, RemediationPlan, SafetyClassification
from backend.app.remediation.registry import get_remediator


class RemediationEngine:
    @staticmethod
    def generate_plan(
        audit_id: str,
        vendor: str,
        hostname: str,
        findings: List[ComplianceFinding],
        cfg: Optional[NormalizedConfiguration] = None
    ) -> RemediationPlan:
        """
        Generates a comprehensive RemediationPlan for all failed or warning findings.
        """
        remediator = get_remediator(vendor)

        # Filter for non-passing findings (FAIL and WARN)
        non_passing = [f for f in findings if f.status.upper() in ["FAIL", "WARN"]]

        actions: List[RemediationAction] = []
        safe_count = 0
        review_count = 0
        manual_count = 0

        for f in non_passing:
            act = remediator.generate_action(f, cfg)
            if act:
                actions.append(act)
                if act.safety_classification == SafetyClassification.SAFE_AUTOMATIC:
                    safe_count += 1
                elif act.safety_classification == SafetyClassification.REVIEW_REQUIRED:
                    review_count += 1
                else:
                    manual_count += 1

        full_script = remediator.format_script(audit_id, hostname, actions)

        return RemediationPlan(
            audit_id=audit_id,
            vendor=remediator.vendor_name,
            hostname=hostname or "network-node",
            generated_at=datetime.now(timezone.utc),
            total_failed_controls=len(non_passing),
            remediated_controls_count=len(actions),
            safe_automatic_count=safe_count,
            review_required_count=review_count,
            manual_only_count=manual_count,
            actions=actions,
            full_script=full_script,
            file_extension=remediator.file_extension
        )
