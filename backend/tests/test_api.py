"""
Tests for FastAPI REST Endpoints.
"""

import io
import pytest


def test_health_check(client):
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "healthy"
    assert "Cisco" in data["supported_vendors"]


def test_detect_vendor_endpoint(client):
    sample = "version 15.2\nhostname edge-rtr\nline vty 0 4\n transport input ssh"
    res = client.post("/api/audits/detect-vendor", json={"content": sample})
    assert res.status_code == 200
    data = res.json()
    assert data["vendor"] == "Cisco"
    assert data["confidence"] > 0.5


def test_analyze_raw_text(client):
    sample = """
    hostname api-rtr-01
    version 15.6
    service password-encryption
    security passwords min-length 14
    enable secret 9 $9$someStrongHash
    ip ssh version 2
    no ip http server
    logging host 10.10.1.1
    ntp server 10.10.1.2
    line vty 0 4
     transport input ssh
     exec-timeout 10 0
    ip access-list extended SEC-ACL
     deny ip any any log
    """
    res = client.post(
        "/api/audits/analyze",
        json={"content": sample, "filename": "test_api_rtr.cfg"}
    )
    assert res.status_code == 200
    data = res.json()
    assert data["id"].startswith("AUD-")
    assert data["vendor"] == "Cisco"
    assert data["hostname"] == "api-rtr-01"
    assert data["compliance_score"] > 60.0
    assert len(data["findings"]) == 16
    assert "ml_result" in data
    assert "risk_assessment" in data

    audit_id = data["id"]

    # Verify GET audit by ID
    get_res = client.get(f"/api/audits/{audit_id}")
    assert get_res.status_code == 200
    assert get_res.json()["id"] == audit_id

    # Verify GET audit report (HTML)
    rep_res = client.get(f"/api/audits/{audit_id}/report")
    assert rep_res.status_code == 200
    assert "text/html" in rep_res.headers["content-type"]
    assert "Network Security Compliance Audit Report" in rep_res.text

    # Verify Dashboard summary
    dash_res = client.get("/api/dashboard/summary")
    assert dash_res.status_code == 200
    d_data = dash_res.json()
    assert d_data["total_audits"] >= 1
    assert "Cisco" in d_data["vendor_distribution"]


def test_upload_file_endpoint(client):
    sample_fortinet = b"""#config-version=FG-7.2.0:opmode=0
config system global
    set hostname "fgt-upload-test"
    set admintimeout 10
end
config firewall policy
    edit 1
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set service "ALL"
    next
end
"""
    files = {"file": ("test_fgt.conf", io.BytesIO(sample_fortinet), "text/plain")}
    res = client.post("/api/audits/upload", files=files)
    assert res.status_code == 200
    data = res.json()
    assert data["vendor"] == "Fortinet"
    assert data["hostname"] == "fgt-upload-test"
    assert data["compliance_summary"]["critical_violations"] >= 1


def test_empty_configuration_error(client):
    res = client.post("/api/audits/analyze", json={"content": ""})
    assert res.status_code == 422


def test_unknown_vendor_error(client):
    res = client.post("/api/audits/analyze", json={"content": "random gibberish with no network commands"})
    assert res.status_code == 422
