"""
Data Models for Automated Remediation Script Generation.
Defines vendor-neutral remediation actions, safety classifications, and compiled remediation plans.
"""

from enum import Enum
from typing import List, Optional
from datetime import datetime, timezone
from pydantic import BaseModel, Field


class SafetyClassification(str, Enum):
    SAFE_AUTOMATIC = "SAFE_AUTOMATIC"      # Exact fix can be generated deterministically without guessing values
    REVIEW_REQUIRED = "REVIEW_REQUIRED"    # Suggested command provided, but engineer must supply environment values/IPs
    MANUAL_ONLY = "MANUAL_ONLY"            # Action requires manual topology/policy review; commands cannot be safely automated


class RemediationAction(BaseModel):
    control_id: str = Field(..., description="Project Security Control identifier (e.g. PSC-1.1)")
    control_title: str = Field(..., description="Human-readable title of the control")
    vendor: str = Field(..., description="Target vendor (Cisco, Fortinet, Palo Alto)")
    severity: str = Field(..., description="Severity of the violation (LOW, MEDIUM, HIGH, CRITICAL)")
    problem_description: str = Field(..., description="Detailed description of the security deficiency")
    evidence: str = Field(..., description="BEFORE: Insecure configuration evidence extracted from device")
    remediation_description: str = Field(..., description="EXPLANATION: Why the change improves posture")
    commands: List[str] = Field(default_factory=list, description="AFTER: Recommended vendor CLI commands")
    validation_commands: List[str] = Field(default_factory=list, description="VALIDATION: Commands to verify the change")
    rollback_commands: List[str] = Field(default_factory=list, description="ROLLBACK: Commands to revert change if needed")
    safety_classification: SafetyClassification = Field(..., description="Safety categorization")
    warning: Optional[str] = Field(None, description="Operational warnings or dependency cautions")
    reversible: bool = Field(True, description="Whether the change has a deterministic rollback path")
    placeholders: List[str] = Field(default_factory=list, description="Placeholders that must be populated by the engineer")
    affected_component: str = Field("General", description="Component name (SSH, SNMP, Firewall, etc.)")


class RemediationPlan(BaseModel):
    audit_id: str = Field(..., description="Identifier of the associated audit")
    vendor: str = Field(..., description="Target device vendor")
    hostname: str = Field("network-node", description="Device hostname")
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Timestamp of generation")
    total_failed_controls: int = Field(0, description="Total non-passing findings evaluated")
    remediated_controls_count: int = Field(0, description="Number of controls with generated remediation")
    safe_automatic_count: int = Field(0, description="Count of SAFE_AUTOMATIC actions")
    review_required_count: int = Field(0, description="Count of REVIEW_REQUIRED actions")
    manual_only_count: int = Field(0, description="Count of MANUAL_ONLY actions")
    actions: List[RemediationAction] = Field(default_factory=list, description="List of discrete remediation actions")
    full_script: str = Field("", description="Compiled, ready-to-download CLI script text")
    file_extension: str = Field(".txt", description="Native vendor file extension (.cfg, .conf, .set)")
    deployment_warning: str = Field(
        "CRITICAL: Do NOT deploy generated configurations directly to production without prior review in a staging environment. "
        "Populate all <PLACEHOLDER> parameters before executing commands.",
        description="Mandatory operator safety disclaimer"
    )
