"""
Schemas for Compliance Findings and Audit Outcomes.
"""

from typing import List, Optional
from pydantic import BaseModel, Field


class ComplianceFinding(BaseModel):
    control_id: str
    title: str
    standard: str  # CIS Benchmark, NIST SP 800-53, PCI-DSS
    status: str  # PASS, FAIL, WARN
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    evidence: str
    recommendation: str
    remediation_cli: Optional[str] = None
    affected_component: str = "General"


class ComplianceSummary(BaseModel):
    total_controls: int
    passed_count: int
    failed_count: int
    warn_count: int
    critical_violations: int
    high_violations: int
    medium_violations: int
    low_violations: int
    compliance_score: float  # 0.0 to 100.0%
