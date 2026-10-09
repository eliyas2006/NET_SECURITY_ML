"""
SQLAlchemy Relational ORM Models.
"""

from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, Float, Boolean, DateTime, Text, ForeignKey
from sqlalchemy.orm import relationship
from backend.app.database.connection import Base


class AuditRecord(Base):
    __tablename__ = "audits"

    id = Column(String(64), primary_key=True, index=True)
    filename = Column(String(255), nullable=False)
    vendor = Column(String(64), nullable=False)
    vendor_confidence = Column(Float, default=1.0)
    device_type = Column(String(64), default="Firewall/Router")
    hostname = Column(String(128), default="unknown-device")
    raw_lines_count = Column(Integer, default=0)

    # Compliance summary metrics
    compliance_score = Column(Float, default=0.0)
    total_controls = Column(Integer, default=0)
    passed_count = Column(Integer, default=0)
    failed_count = Column(Integer, default=0)
    warn_count = Column(Integer, default=0)
    critical_violations = Column(Integer, default=0)
    high_violations = Column(Integer, default=0)
    medium_violations = Column(Integer, default=0)
    low_violations = Column(Integer, default=0)

    # Risk summary metrics
    final_risk_level = Column(String(32), default="LOW")
    composite_risk_score = Column(Float, default=0.0)
    rule_risk_score = Column(Float, default=0.0)
    ml_risk_score = Column(Float, default=0.0)

    # ML classification metrics
    ml_predicted_class = Column(String(32), default="LOW")
    ml_confidence = Column(Float, default=0.0)
    anomaly_score = Column(Float, default=0.0)
    is_anomaly = Column(Boolean, default=False)

    # Serialized JSON blobs for rich inspection without storing secrets
    raw_config_preview = Column(Text, nullable=True)
    normalized_json = Column(Text, nullable=True)
    risk_assessment_json = Column(Text, nullable=True)
    ml_result_json = Column(Text, nullable=True)

    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)

    # Relationships
    findings = relationship("FindingRecord", back_populates="audit", cascade="all, delete-orphan")


class FindingRecord(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    audit_id = Column(String(64), ForeignKey("audits.id", ondelete="CASCADE"), nullable=False, index=True)
    control_id = Column(String(32), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    standard = Column(String(128), nullable=False)
    status = Column(String(16), nullable=False, index=True)  # PASS, FAIL, WARN
    severity = Column(String(16), nullable=False, index=True)  # LOW, MEDIUM, HIGH, CRITICAL
    evidence = Column(Text, nullable=False)
    recommendation = Column(Text, nullable=False)
    remediation_cli = Column(Text, nullable=True)
    affected_component = Column(String(64), default="General")

    audit = relationship("AuditRecord", back_populates="findings")
