"""
End-to-End Integration and Edge Case Tests.
Tests all real sample files in sample_data/ across Cisco, Fortinet, and Palo Alto.
Verifies vendor detection, parsing, compliance, ML inference, DB persistence,
report generation, remediation download, sensitive value redaction, cascading deletion,
and all edge-case error scenarios.
"""

import os
import io
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.app.main import app
from backend.app.database.connection import get_db, SessionLocal
from backend.app.database.models import AuditRecord, FindingRecord


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


@pytest.fixture
def db_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def test_e2e_cisco_samples(client, db_session: Session):
    """Test full pipeline with real Cisco sample configurations."""
    # 1. Hardened Core
    hardened_path = "sample_data/cisco/cisco_hardened_core.cfg"
    assert os.path.exists(hardened_path)
    with open(hardened_path, "r", encoding="utf-8") as f:
        content_hard = f.read()

    res_hard = client.post("/api/audits/analyze", json={
        "content": content_hard,
        "filename": "cisco_hardened_core.cfg"
    })
    assert res_hard.status_code == 200
    data_hard = res_hard.json()
    audit_id_hard = data_hard["id"]

    assert data_hard["vendor"] == "Cisco"
    assert data_hard["compliance_score"] >= 80.0
    assert data_hard["final_risk_level"] in ["LOW", "MEDIUM"]
    assert len(data_hard["findings"]) == 16
    assert data_hard["ml_result"]["predicted_risk_class"] in ["LOW", "MEDIUM"]

    # Verify report endpoint
    rep_res = client.get(f"/api/audits/{audit_id_hard}/report")
    assert rep_res.status_code == 200
    assert "text/html" in rep_res.headers["content-type"]
    assert "Network Security Compliance Audit Report" in rep_res.text
    assert "Operational Safety Disclaimers" in rep_res.text

    # 2. Vulnerable Perimeter
    vuln_path = "sample_data/cisco/cisco_vulnerable_perimeter.cfg"
    assert os.path.exists(vuln_path)
    with open(vuln_path, "r", encoding="utf-8") as f:
        content_vuln = f.read()

    res_vuln = client.post("/api/audits/analyze", json={
        "content": content_vuln,
        "filename": "cisco_vulnerable_perimeter.cfg"
    })
    assert res_vuln.status_code == 200
    data_vuln = res_vuln.json()
    audit_id_vuln = data_vuln["id"]

    assert data_vuln["vendor"] == "Cisco"
    assert data_vuln["compliance_score"] < 50.0
    assert data_vuln["final_risk_level"] in ["HIGH", "CRITICAL"]

    # Verify remediation plan
    rem_res = client.get(f"/api/audits/{audit_id_vuln}/remediation")
    assert rem_res.status_code == 200
    rem_data = rem_res.json()
    assert rem_data["vendor"] == "Cisco"
    assert rem_data["file_extension"] == ".cfg"
    assert rem_data["remediated_controls_count"] > 0

    # Verify remediation download
    dl_res = client.get(f"/api/audits/{audit_id_vuln}/remediation/download")
    assert dl_res.status_code == 200
    assert "attachment" in dl_res.headers["content-disposition"]
    assert ".cfg" in dl_res.headers["content-disposition"]
    assert "! AUTOMATED NETWORK SECURITY COMPLIANCE REMEDIATION SCRIPT" in dl_res.text
    assert "! Target Vendor:     Cisco" in dl_res.text


def test_e2e_fortinet_samples(client, db_session: Session):
    """Test full pipeline with real Fortinet sample configurations."""
    # 1. Hardened Edge
    hardened_path = "sample_data/fortinet/fortinet_hardened_edge.conf"
    assert os.path.exists(hardened_path)
    with open(hardened_path, "r", encoding="utf-8") as f:
        content_hard = f.read()

    res_hard = client.post("/api/audits/analyze", json={
        "content": content_hard,
        "filename": "fortinet_hardened_edge.conf"
    })
    assert res_hard.status_code == 200
    data_hard = res_hard.json()
    assert data_hard["vendor"] == "Fortinet"
    assert data_hard["compliance_score"] >= 75.0

    # 2. Permissive DMZ
    vuln_path = "sample_data/fortinet/fortinet_permissive_dmz.conf"
    assert os.path.exists(vuln_path)
    with open(vuln_path, "r", encoding="utf-8") as f:
        content_vuln = f.read()

    res_vuln = client.post("/api/audits/analyze", json={
        "content": content_vuln,
        "filename": "fortinet_permissive_dmz.conf"
    })
    assert res_vuln.status_code == 200
    data_vuln = res_vuln.json()
    audit_id_vuln = data_vuln["id"]

    assert data_vuln["vendor"] == "Fortinet"
    assert data_vuln["final_risk_level"] in ["HIGH", "CRITICAL"]

    # Verify remediation download
    dl_res = client.get(f"/api/audits/{audit_id_vuln}/remediation/download")
    assert dl_res.status_code == 200
    assert ".conf" in dl_res.headers["content-disposition"]
    assert "# AUTOMATED NETWORK SECURITY COMPLIANCE REMEDIATION SCRIPT" in dl_res.text
    assert "# Target Vendor:     Fortinet" in dl_res.text


def test_e2e_palo_alto_samples(client, db_session: Session):
    """Test full pipeline with real Palo Alto sample configurations."""
    # 1. Secure Gateway
    sec_path = "sample_data/palo_alto/palo_alto_secure_gw.txt"
    assert os.path.exists(sec_path)
    with open(sec_path, "r", encoding="utf-8") as f:
        content_sec = f.read()

    res_sec = client.post("/api/audits/analyze", json={
        "content": content_sec,
        "filename": "palo_alto_secure_gw.txt"
    })
    assert res_sec.status_code == 200
    data_sec = res_sec.json()
    assert data_sec["vendor"] == "Palo Alto"
    assert data_sec["compliance_score"] >= 75.0

    # 2. Misconfigured
    misc_path = "sample_data/palo_alto/palo_alto_misconfigured.txt"
    assert os.path.exists(misc_path)
    with open(misc_path, "r", encoding="utf-8") as f:
        content_misc = f.read()

    res_misc = client.post("/api/audits/analyze", json={
        "content": content_misc,
        "filename": "palo_alto_misconfigured.txt"
    })
    assert res_misc.status_code == 200
    data_misc = res_misc.json()
    audit_id_misc = data_misc["id"]

    assert data_misc["vendor"] == "Palo Alto"
    assert data_misc["final_risk_level"] in ["HIGH", "CRITICAL"]

    # Verify remediation download
    dl_res = client.get(f"/api/audits/{audit_id_misc}/remediation/download")
    assert dl_res.status_code == 200
    assert ".set" in dl_res.headers["content-disposition"]
    assert "# AUTOMATED NETWORK SECURITY COMPLIANCE REMEDIATION SCRIPT" in dl_res.text
    assert "# Target Vendor:     Palo Alto" in dl_res.text


def test_sensitive_value_redaction_in_preview(client, db_session: Session):
    """Verify that credentials and secrets are redacted in preview before DB storage."""
    sensitive_cisco = (
        "version 15.6\n"
        "hostname rtr-sensitive\n"
        "enable password 7 070C285F4D06\n"
        "username admin secret 5 $1$superSecretHash\n"
        "snmp-server community secretCommunityStr RW\n"
        "line vty 0 4\n"
        " password cleartextPass123\n"
    )
    res = client.post("/api/audits/analyze", json={
        "content": sensitive_cisco,
        "filename": "sensitive_test.cfg"
    })
    assert res.status_code == 200
    audit_id = res.json()["id"]

    rec = db_session.query(AuditRecord).filter(AuditRecord.id == audit_id).first()
    assert rec is not None
    preview = rec.raw_config_preview

    # Assert cleartext secrets are NOT in preview
    assert "070C285F4D06" not in preview
    assert "$1$superSecretHash" not in preview
    assert "secretCommunityStr" not in preview
    assert "cleartextPass123" not in preview

    # Assert redaction tags are present
    assert "[REDACTED" in preview


def test_audit_deletion_and_cascading(client, db_session: Session):
    """Verify deleting an audit completely removes it and its findings from the DB."""
    cfg = "version 15.6\nhostname del-test\nip ssh version 2\n"
    res = client.post("/api/audits/analyze", json={"content": cfg, "filename": "del.cfg"})
    audit_id = res.json()["id"]

    # Verify record and findings exist
    assert db_session.query(AuditRecord).filter(AuditRecord.id == audit_id).count() == 1
    assert db_session.query(FindingRecord).filter(FindingRecord.audit_id == audit_id).count() > 0

    # Delete
    del_res = client.delete(f"/api/audits/{audit_id}")
    assert del_res.status_code == 200

    # Verify cascades
    assert db_session.query(AuditRecord).filter(AuditRecord.id == audit_id).count() == 0
    assert db_session.query(FindingRecord).filter(FindingRecord.audit_id == audit_id).count() == 0


def test_nonexistent_audit_endpoints(client):
    """Verify 404 for invalid audit ID across all endpoints."""
    bad_id = "AUD-NONEXISTENT999"
    assert client.get(f"/api/audits/{bad_id}").status_code == 404
    assert client.get(f"/api/audits/{bad_id}/report").status_code == 404
    assert client.get(f"/api/audits/{bad_id}/remediation").status_code == 404
    assert client.get(f"/api/audits/{bad_id}/remediation/download").status_code == 404
    assert client.delete(f"/api/audits/{bad_id}").status_code == 404


def test_oversized_payload_rejection(client):
    """Verify that uploads exceeding 10MB are rejected with 400 Bad Request."""
    huge_text = "!" * (11 * 1024 * 1024)
    res = client.post("/api/audits/analyze", json={"content": huge_text})
    assert res.status_code == 400
    assert "limit" in res.json()["detail"].lower()


def test_dashboard_summary_metrics(client):
    """Verify dashboard summary metrics return valid non-null calculations."""
    res = client.get("/api/dashboard/summary")
    assert res.status_code == 200
    summary = res.json()
    assert "total_audits" in summary
    assert "compliant_devices" in summary
    assert "non_compliant_devices" in summary
    assert "risk_distribution" in summary
    assert "vendor_distribution" in summary
    assert isinstance(summary["recent_audits"], list)
