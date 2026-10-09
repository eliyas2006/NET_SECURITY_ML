"""
Tests for Compliance Engine, Feature Extraction, ML Inference, and Risk Aggregation.
"""

import pytest
from backend.app.parsers.cisco import CiscoParser
from backend.app.compliance.engine import ComplianceEngine
from backend.app.features.extractor import extract_features, FEATURE_NAMES
from backend.app.ml.inference import get_ml_service
from backend.app.risk.engine import RiskEngine


def test_compliance_and_ml_pipeline():
    sample_hardened = """
    version 15.6
    hostname test-hardened
    service password-encryption
    security passwords min-length 14
    enable secret 9 $9$secureHash
    username admin algorithm-type sha256 secret 8 $8$adminHash
    aaa new-model
    ip ssh version 2
    no ip http server
    logging host 10.10.1.1
    ntp server 1.1.1.1
    snmp-server group SECGROUP v3 priv
    banner motd ^C Authorized only ^C
    line vty 0 4
     transport input ssh
     exec-timeout 10 0
    ip access-list extended CLEAN-ACL
     deny ip any any log
    """
    parser = CiscoParser()
    norm = parser.parse(sample_hardened)

    # 1. Compliance Engine
    engine = ComplianceEngine()
    findings, summary = engine.evaluate(norm)

    assert len(findings) == 16
    assert summary.compliance_score >= 80.0
    assert summary.critical_violations == 0

    # 2. Feature Extractor
    features = extract_features(norm, summary)
    assert len(features) == len(FEATURE_NAMES)
    assert features["ssh_version"] == 2.0
    assert features["telnet_enabled"] == 0.0
    assert features["unrestricted_rules_count"] == 0.0

    # 3. ML Service
    ml_svc = get_ml_service()
    ml_res = ml_svc.predict(features)
    assert ml_res.predicted_risk_class in ["LOW", "MEDIUM"]
    assert 0.0 <= ml_res.confidence <= 1.0

    # 4. Risk Engine
    risk = RiskEngine.calculate_risk(norm, summary, ml_res)
    assert risk.final_risk_level in ["LOW", "MEDIUM"]
    assert risk.composite_risk_score <= 50.0
    assert "Composite" in risk.calculation_breakdown


def test_critical_risk_safety_floor():
    sample_critical = """
    hostname risky-node
    no service password-encryption
    enable password plainpass
    ip ssh version 1
    ip http server
    snmp-server community public RW
    line vty 0 4
     transport input telnet
     exec-timeout 0 0
    ip access-list extended WIDE-ACL
     permit ip any any
    """
    parser = CiscoParser()
    norm = parser.parse(sample_critical)

    engine = ComplianceEngine()
    findings, summary = engine.evaluate(norm)
    assert summary.critical_violations >= 1  # Unrestricted permit rule

    features = extract_features(norm, summary)
    ml_svc = get_ml_service()
    ml_res = ml_svc.predict(features)

    risk = RiskEngine.calculate_risk(norm, summary, ml_res)
    # Must enforce at least HIGH tier safety floor
    assert risk.final_risk_level in ["HIGH", "CRITICAL"]
    assert risk.composite_risk_score >= 70.0
