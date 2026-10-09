"""
Deterministic Compliance Engine.
Evaluates normalized device configurations against all benchmark rules.
"""

from typing import List, Tuple
from backend.app.schemas.normalized import NormalizedConfiguration
from backend.app.schemas.compliance import ComplianceFinding, ComplianceSummary
from backend.app.compliance.rules import ALL_RULES


class ComplianceEngine:
    def __init__(self, rules=None):
        self.rules = rules or ALL_RULES

    def evaluate(self, cfg: NormalizedConfiguration) -> Tuple[List[ComplianceFinding], ComplianceSummary]:
        findings: List[ComplianceFinding] = []
        
        passed_count = 0
        failed_count = 0
        warn_count = 0
        critical_violations = 0
        high_violations = 0
        medium_violations = 0
        low_violations = 0

        for rule in self.rules:
            res = rule(cfg)
            findings.append(res)

            if res.status == "PASS":
                passed_count += 1
            elif res.status == "WARN":
                warn_count += 1
                if res.severity == "CRITICAL":
                    critical_violations += 1
                elif res.severity == "HIGH":
                    high_violations += 1
                elif res.severity == "MEDIUM":
                    medium_violations += 1
                elif res.severity == "LOW":
                    low_violations += 1
            else:  # FAIL
                failed_count += 1
                if res.severity == "CRITICAL":
                    critical_violations += 1
                elif res.severity == "HIGH":
                    high_violations += 1
                elif res.severity == "MEDIUM":
                    medium_violations += 1
                elif res.severity == "LOW":
                    low_violations += 1

        total = len(self.rules)
        # Score calculation: PASS gives full credit (1.0), WARN gives half credit (0.5), FAIL gives 0.0
        earned = (passed_count * 1.0) + (warn_count * 0.5)
        compliance_score = round((earned / total) * 100.0, 1) if total > 0 else 0.0

        summary = ComplianceSummary(
            total_controls=total,
            passed_count=passed_count,
            failed_count=failed_count,
            warn_count=warn_count,
            critical_violations=critical_violations,
            high_violations=high_violations,
            medium_violations=medium_violations,
            low_violations=low_violations,
            compliance_score=compliance_score
        )

        return findings, summary
