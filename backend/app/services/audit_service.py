"""
Core Audit Pipeline Orchestration Service.
Executes Detection -> Parsing -> Normalization -> Compliance Rules -> Feature Extraction -> ML Inference -> Risk Scoring -> Database Persistence.
"""

import uuid
import json
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from sqlalchemy.orm import Session

from backend.app.parsers import detect_vendor, get_parser, VendorIdentificationResult
from backend.app.compliance.engine import ComplianceEngine
from backend.app.features.extractor import extract_features
from backend.app.ml.inference import get_ml_service
from backend.app.risk.engine import RiskEngine
from backend.app.database.models import AuditRecord, FindingRecord
from backend.app.schemas.api import AuditDetailResponse, AuditListItem, DashboardSummary
from backend.app.schemas.compliance import ComplianceSummary, ComplianceFinding
from backend.app.schemas.risk import RiskAssessment, MLInferenceResult
from backend.app.remediation.models import RemediationPlan
from backend.app.remediation.engine import RemediationEngine


import re

def sanitize_config_text(text: str) -> str:
    """
    Redacts sensitive credentials, passwords, cryptographic keys, and community strings
    from configuration text prior to logging or database preview storage.
    """
    # Cisco passwords and secrets
    text = re.sub(r'(enable secret(?:\s+\d+)?\s+)\S+', r'\1[REDACTED_HASH]', text, flags=re.IGNORECASE)
    text = re.sub(r'(enable password(?:\s+\d+)?\s+)\S+', r'\1[REDACTED_PASSWORD]', text, flags=re.IGNORECASE)
    text = re.sub(r'(username \S+ (?:secret|password)(?:\s+\d+)?\s+)\S+', r'\1[REDACTED_CREDENTIAL]', text, flags=re.IGNORECASE)
    text = re.sub(r'(\bpassword(?:\s+\d+)?\s+)\S+', r'\1[REDACTED_PASSWORD]', text, flags=re.IGNORECASE)
    # SNMP community strings
    text = re.sub(r'(snmp-server community )\S+', r'\1[REDACTED_COMMUNITY]', text, flags=re.IGNORECASE)
    text = re.sub(r'(community ")\S+(")', r'\1[REDACTED_COMMUNITY]\2', text, flags=re.IGNORECASE)
    # Pre-shared keys and encryption phrases
    text = re.sub(r'(set password ENC )\S+', r'\1[REDACTED_HASH]', text, flags=re.IGNORECASE)
    text = re.sub(r'(set (?:pre-shared-key|preshared-key|secret) )\S+', r'\1[REDACTED_SECRET]', text, flags=re.IGNORECASE)
    text = re.sub(r'(pre-shared-key \d* )\S+', r'\1[REDACTED_KEY]', text, flags=re.IGNORECASE)
    text = re.sub(r'(key-string \d* )\S+', r'\1[REDACTED_KEY]', text, flags=re.IGNORECASE)
    text = re.sub(r'(auth sha )\S+( priv aes \d+ )\S+', r'\1[REDACTED_KEY]\2[REDACTED_KEY]', text, flags=re.IGNORECASE)
    return text


class AuditService:
    def __init__(self, db: Session):
        self.db = db
        self.compliance_engine = ComplianceEngine()
        self.ml_service = get_ml_service()

    def process_configuration(
        self,
        content: str,
        filename: str = "uploaded_config.txt",
        vendor_override: Optional[str] = None
    ) -> AuditDetailResponse:
        if not content or not content.strip():
            raise ValueError("Configuration content cannot be empty.")

        # 1. Vendor Identification
        if vendor_override and vendor_override.strip() and vendor_override.lower() != "auto":
            vendor = vendor_override.strip()
            confidence = 1.0
            device_type = "Firewall/Router"
        else:
            detect_res = detect_vendor(content)
            if detect_res.vendor == "Unknown":
                raise ValueError("Unable to automatically detect vendor. Please select vendor manually.")
            vendor = detect_res.vendor
            confidence = detect_res.confidence
            device_type = detect_res.suggested_device_type

        # 2. Vendor Parsing & Normalization
        parser = get_parser(vendor)
        normalized_cfg = parser.parse(content)

        # 3. Deterministic Compliance Rule Evaluation
        findings, compliance_summary = self.compliance_engine.evaluate(normalized_cfg)

        # 4. Feature Extraction
        features = extract_features(normalized_cfg, compliance_summary)

        # 5. ML Inference (Risk Classification & Anomaly Detection)
        ml_result = self.ml_service.predict(features)

        # 6. Combined Risk Engine Assessment
        risk_assessment = RiskEngine.calculate_risk(normalized_cfg, compliance_summary, ml_result)

        # 7. Safe preview (first 50 lines, with all credentials and secrets redacted)
        preview_lines = content.splitlines()[:50]
        preview = sanitize_config_text("\n".join(preview_lines))

        audit_id = f"AUD-{uuid.uuid4().hex[:10].upper()}"

        # 8. Database Persistence
        audit_record = AuditRecord(
            id=audit_id,
            filename=filename,
            vendor=vendor,
            vendor_confidence=confidence,
            device_type=device_type,
            hostname=normalized_cfg.hostname,
            raw_lines_count=normalized_cfg.raw_lines_count,
            compliance_score=compliance_summary.compliance_score,
            total_controls=compliance_summary.total_controls,
            passed_count=compliance_summary.passed_count,
            failed_count=compliance_summary.failed_count,
            warn_count=compliance_summary.warn_count,
            critical_violations=compliance_summary.critical_violations,
            high_violations=compliance_summary.high_violations,
            medium_violations=compliance_summary.medium_violations,
            low_violations=compliance_summary.low_violations,
            final_risk_level=risk_assessment.final_risk_level,
            composite_risk_score=risk_assessment.composite_risk_score,
            rule_risk_score=risk_assessment.rule_risk_score,
            ml_risk_score=risk_assessment.ml_risk_score,
            ml_predicted_class=ml_result.predicted_risk_class,
            ml_confidence=ml_result.confidence,
            anomaly_score=ml_result.anomaly_score,
            is_anomaly=ml_result.is_anomaly,
            raw_config_preview=preview,
            normalized_json=normalized_cfg.model_dump_json(),
            risk_assessment_json=risk_assessment.model_dump_json(),
            ml_result_json=ml_result.model_dump_json(),
            created_at=datetime.now(timezone.utc)
        )
        self.db.add(audit_record)

        # Add findings
        for f in findings:
            f_record = FindingRecord(
                audit_id=audit_id,
                control_id=f.control_id,
                title=f.title,
                standard=f.standard,
                status=f.status,
                severity=f.severity,
                evidence=f.evidence,
                recommendation=f.recommendation,
                remediation_cli=f.remediation_cli,
                affected_component=f.affected_component
            )
            self.db.add(f_record)

        self.db.commit()
        self.db.refresh(audit_record)

        return AuditDetailResponse(
            id=audit_record.id,
            filename=audit_record.filename,
            vendor=audit_record.vendor,
            vendor_confidence=audit_record.vendor_confidence,
            device_type=audit_record.device_type,
            hostname=audit_record.hostname,
            raw_lines_count=audit_record.raw_lines_count,
            compliance_score=audit_record.compliance_score,
            final_risk_level=audit_record.final_risk_level,
            composite_risk_score=audit_record.composite_risk_score,
            created_at=audit_record.created_at,
            compliance_summary=compliance_summary,
            risk_assessment=risk_assessment,
            ml_result=ml_result,
            findings=findings,
            raw_config_preview=preview
        )

    def get_audit(self, audit_id: str) -> Optional[AuditDetailResponse]:
        record = self.db.query(AuditRecord).filter(AuditRecord.id == audit_id).first()
        if not record:
            return None

        # Reconstruct models
        compliance_summary = ComplianceSummary(
            total_controls=record.total_controls,
            passed_count=record.passed_count,
            failed_count=record.failed_count,
            warn_count=record.warn_count,
            critical_violations=record.critical_violations,
            high_violations=record.high_violations,
            medium_violations=record.medium_violations,
            low_violations=record.low_violations,
            compliance_score=record.compliance_score
        )

        risk_assessment = RiskAssessment.model_validate_json(record.risk_assessment_json)
        ml_result = MLInferenceResult.model_validate_json(record.ml_result_json)

        findings = [
            ComplianceFinding(
                control_id=f.control_id,
                title=f.title,
                standard=f.standard,
                status=f.status,
                severity=f.severity,
                evidence=f.evidence,
                recommendation=f.recommendation,
                remediation_cli=f.remediation_cli,
                affected_component=f.affected_component
            )
            for f in record.findings
        ]

        return AuditDetailResponse(
            id=record.id,
            filename=record.filename,
            vendor=record.vendor,
            vendor_confidence=record.vendor_confidence,
            device_type=record.device_type,
            hostname=record.hostname,
            raw_lines_count=record.raw_lines_count,
            compliance_score=record.compliance_score,
            final_risk_level=record.final_risk_level,
            composite_risk_score=record.composite_risk_score,
            created_at=record.created_at,
            compliance_summary=compliance_summary,
            risk_assessment=risk_assessment,
            ml_result=ml_result,
            findings=findings,
            raw_config_preview=record.raw_config_preview
        )

    def list_audits(self, limit: int = 50) -> List[AuditListItem]:
        records = self.db.query(AuditRecord).order_by(AuditRecord.created_at.desc()).limit(limit).all()
        return [
            AuditListItem(
                id=r.id,
                filename=r.filename,
                vendor=r.vendor,
                device_type=r.device_type,
                hostname=r.hostname,
                raw_lines_count=r.raw_lines_count,
                compliance_score=r.compliance_score,
                final_risk_level=r.final_risk_level,
                composite_risk_score=r.composite_risk_score,
                critical_violations=r.critical_violations,
                high_violations=r.high_violations,
                created_at=r.created_at
            )
            for r in records
        ]

    def get_dashboard_summary(self) -> DashboardSummary:
        total_audits = self.db.query(AuditRecord).count()
        recent = self.list_audits(limit=10)

        records = self.db.query(AuditRecord).all()
        compliant = sum(1 for r in records if r.compliance_score >= 80.0)
        non_compliant = total_audits - compliant
        high_risk = sum(1 for r in records if r.final_risk_level in ["HIGH", "CRITICAL"])
        critical_findings = sum(r.critical_violations for r in records)

        risk_dist = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
        for r in records:
            if r.final_risk_level in risk_dist:
                risk_dist[r.final_risk_level] += 1

        vendor_dist: Dict[str, int] = {}
        for r in records:
            vendor_dist[r.vendor] = vendor_dist.get(r.vendor, 0) + 1

        return DashboardSummary(
            total_audits=total_audits,
            total_devices=total_audits,
            compliant_devices=compliant,
            non_compliant_devices=non_compliant,
            high_risk_devices=high_risk,
            critical_findings=critical_findings,
            risk_distribution=risk_dist,
            vendor_distribution=vendor_dist,
            recent_audits=recent
        )

    def get_remediation_plan(self, audit_id: str) -> Optional[RemediationPlan]:
        """
        Retrieves audit record and generates full vendor remediation plan.
        """
        record = self.db.query(AuditRecord).filter(AuditRecord.id == audit_id).first()
        if not record:
            return None

        cfg = None
        if record.normalized_json:
            try:
                from backend.app.schemas.normalized import NormalizedConfiguration
                cfg = NormalizedConfiguration.model_validate_json(record.normalized_json)
            except Exception:
                cfg = None

        findings = [
            ComplianceFinding(
                control_id=f.control_id,
                title=f.title,
                standard=f.standard,
                status=f.status,
                severity=f.severity,
                evidence=f.evidence,
                recommendation=f.recommendation,
                remediation_cli=f.remediation_cli,
                affected_component=f.affected_component
            )
            for f in record.findings
        ]

        return RemediationEngine.generate_plan(
            audit_id=record.id,
            vendor=record.vendor,
            hostname=record.hostname,
            findings=findings,
            cfg=cfg
        )

