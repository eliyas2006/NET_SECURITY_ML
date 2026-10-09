"""
API Request and Response Pydantic Schemas.
"""

from typing import List, Dict, Optional, Any
from datetime import datetime
from pydantic import BaseModel, Field
from backend.app.schemas.compliance import ComplianceFinding, ComplianceSummary
from backend.app.schemas.risk import MLInferenceResult, RiskAssessment
from backend.app.schemas.normalized import NormalizedConfiguration


class AnalyzeTextRequest(BaseModel):
    content: str
    filename: Optional[str] = "manual_configuration.txt"
    vendor_override: Optional[str] = None


class VendorDetectionResponse(BaseModel):
    vendor: str
    confidence: float
    confidence_level: str
    reason: str
    detected_syntax: Optional[str] = None
    suggested_device_type: str = "Firewall/Router"


class AuditListItem(BaseModel):
    id: str
    filename: str
    vendor: str
    device_type: str
    hostname: str
    raw_lines_count: int
    compliance_score: float
    final_risk_level: str
    composite_risk_score: float
    critical_violations: int
    high_violations: int
    created_at: datetime


class AuditDetailResponse(BaseModel):
    id: str
    filename: str
    vendor: str
    vendor_confidence: float
    device_type: str
    hostname: str
    raw_lines_count: int
    compliance_score: float
    final_risk_level: str
    composite_risk_score: float
    created_at: datetime

    compliance_summary: ComplianceSummary
    risk_assessment: RiskAssessment
    ml_result: MLInferenceResult
    findings: List[ComplianceFinding]
    raw_config_preview: Optional[str] = None


class DashboardSummary(BaseModel):
    total_audits: int
    total_devices: int
    compliant_devices: int
    non_compliant_devices: int
    high_risk_devices: int
    critical_findings: int
    risk_distribution: Dict[str, int]
    vendor_distribution: Dict[str, int]
    recent_audits: List[AuditListItem]
