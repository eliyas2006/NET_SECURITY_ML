"""
Unit and Integration Tests for Stage 3A Automated Remediation Script Generation.
Covers Cisco IOS, Fortinet FortiOS, and Palo Alto PAN-OS remediators, safety classifications,
placeholders, and REST API download endpoints.
"""

import pytest
from backend.app.schemas.compliance import ComplianceFinding
from backend.app.remediation.models import SafetyClassification, RemediationPlan
from backend.app.remediation.registry import get_remediator, list_supported_vendors
from backend.app.remediation.engine import RemediationEngine

ALL_CONTROLS = {
    "PSC-1.1": {"title": "Ensure SSH is Enabled and Version 2 is Enforced", "severity": "HIGH"},
    "PSC-1.2": {"title": "Ensure Telnet Service is Disabled", "severity": "HIGH"},
    "PSC-1.3": {"title": "Ensure Insecure HTTP Server is Disabled", "severity": "MEDIUM"},
    "PSC-1.4": {"title": "Ensure Service Password Encryption is Enabled", "severity": "MEDIUM"},
    "PSC-1.5": {"title": "Ensure Strong Password Hashing Algorithms Are Used", "severity": "HIGH"},
    "PSC-1.6": {"title": "Ensure Minimum Password Length is Enforced", "severity": "LOW"},
    "PSC-1.7": {"title": "Ensure Inactive Management Session Timeout is Configured", "severity": "MEDIUM"},
    "PSC-1.8": {"title": "Ensure Legal Warning Banner is Configured", "severity": "LOW"},
    "PSC-2.1": {"title": "Ensure Centralized AAA Authentication is Enforced", "severity": "HIGH"},
    "PSC-2.2": {"title": "Ensure Centralized Remote Logging (Syslog) is Configured", "severity": "HIGH"},
    "PSC-2.3": {"title": "Ensure Network Time Protocol (NTP) Synchronization is Configured", "severity": "MEDIUM"},
    "PSC-2.4": {"title": "Ensure Default SNMP Community Strings are Disabled", "severity": "CRITICAL"},
    "PSC-2.5": {"title": "Ensure SNMPv3 with Authentication and Encryption is Enforced", "severity": "HIGH"},
    "PSC-3.1": {"title": "Ensure Insecure and Legacy Network Services are Disabled", "severity": "MEDIUM"},
    "PSC-4.1": {"title": "Ensure Firewall Has No Unrestricted Any-to-Any Permit Rules", "severity": "CRITICAL"},
    "PSC-4.2": {"title": "Ensure Default Deny Stance is Enforced", "severity": "HIGH"},
}
ALL_CONTROL_IDS = list(ALL_CONTROLS.keys())


def make_failed_finding(control_id: str) -> ComplianceFinding:
    ctrl = ALL_CONTROLS[control_id]
    return ComplianceFinding(
        control_id=control_id,
        title=ctrl["title"],
        standard="Project Security Control",
        severity=ctrl["severity"],
        status="FAIL",
        evidence=f"Insecure configuration detected for {control_id}",
        recommendation=f"Remediate {control_id} according to security standard"
    )



# ==============================================================================
# 1. Registry & Factory Tests
# ==============================================================================

def test_registry_supported_vendors():
    vendors = list_supported_vendors()
    assert "Cisco" in vendors
    assert "Fortinet" in vendors
    assert "Palo Alto" in vendors


@pytest.mark.parametrize("vendor_str,expected_vendor", [
    ("cisco", "Cisco"),
    ("Cisco IOS", "Cisco"),
    ("fortinet", "Fortinet"),
    ("FortiOS", "Fortinet"),
    ("palo alto", "Palo Alto"),
    ("pan-os", "Palo Alto"),
    ("Palo Alto Networks", "Palo Alto"),
])
def test_registry_lookup_success(vendor_str, expected_vendor):
    remediator = get_remediator(vendor_str)
    assert remediator.vendor_name == expected_vendor


def test_registry_lookup_unsupported():
    with pytest.raises(ValueError, match="Unsupported vendor"):
        get_remediator("Juniper")


# ==============================================================================
# 2. Control Coverage Across All 3 Vendors (All 16 PSC Controls)
# ==============================================================================

@pytest.mark.parametrize("vendor", ["Cisco", "Fortinet", "Palo Alto"])
def test_all_16_controls_covered(vendor):
    remediator = get_remediator(vendor)
    assert len(ALL_CONTROL_IDS) == 16

    for cid in ALL_CONTROL_IDS:
        finding = make_failed_finding(cid)
        action = remediator.generate_action(finding)
        assert action is not None, f"{vendor} missing remediation action for {cid}"
        assert action.control_id == cid
        assert action.vendor == remediator.vendor_name
        assert len(action.commands) > 0, f"{vendor} generated empty commands for {cid}"
        assert len(action.validation_commands) > 0, f"{vendor} generated empty validation for {cid}"
        assert action.safety_classification in [
            SafetyClassification.SAFE_AUTOMATIC,
            SafetyClassification.REVIEW_REQUIRED,
            SafetyClassification.MANUAL_ONLY
        ]


# ==============================================================================
# 3. Safety Classification & Guardrail Verification
# ==============================================================================

@pytest.mark.parametrize("vendor", ["Cisco", "Fortinet", "Palo Alto"])
def test_psc_4_1_wildcard_is_manual_only(vendor):
    """PSC-4.1 (wildcard permit any any) must NEVER be auto-deployed; it requires MANUAL_ONLY."""
    remediator = get_remediator(vendor)
    action = remediator.generate_action(make_failed_finding("PSC-4.1"))
    assert action.safety_classification == SafetyClassification.MANUAL_ONLY
    assert action.warning is not None
    assert (
        "outage" in action.warning.lower()
        or "manual" in action.warning.lower()
        or "policy" in action.warning.lower()
        or "manual" in action.remediation_description.lower()
    )


@pytest.mark.parametrize("vendor", ["Cisco", "Fortinet", "Palo Alto"])
def test_psc_1_2_telnet_is_safe_automatic(vendor):
    """Disabling Telnet is deterministic and safe (or requires review if interface placeholder is needed)."""
    remediator = get_remediator(vendor)
    action = remediator.generate_action(make_failed_finding("PSC-1.2"))
    assert action.safety_classification in [
        SafetyClassification.SAFE_AUTOMATIC,
        SafetyClassification.REVIEW_REQUIRED
    ]


@pytest.mark.parametrize("vendor", ["Cisco", "Fortinet", "Palo Alto"])
def test_placeholder_parameters_required(vendor):
    """External dependency controls (NTP, Syslog) must specify placeholders."""
    remediator = get_remediator(vendor)
    syslog_action = remediator.generate_action(make_failed_finding("PSC-2.2"))
    assert syslog_action.safety_classification == SafetyClassification.REVIEW_REQUIRED
    assert any("SYSLOG" in p or "SIEM" in p for p in syslog_action.placeholders)

    ntp_action = remediator.generate_action(make_failed_finding("PSC-2.3"))
    assert ntp_action.safety_classification == SafetyClassification.REVIEW_REQUIRED
    assert any("NTP" in p for p in ntp_action.placeholders)


@pytest.mark.parametrize("vendor", ["Cisco", "Fortinet", "Palo Alto"])
def test_no_hardcoded_passwords(vendor):
    """Ensure remediators do not embed hardcoded insecure passwords like 'admin123' or 'cisco'."""
    remediator = get_remediator(vendor)
    for cid in ["PSC-1.5", "PSC-2.5"]:
        action = remediator.generate_action(make_failed_finding(cid))
        full_text = " ".join(action.commands)
        assert "cisco123" not in full_text
        assert "admin123" not in full_text
        assert "password123" not in full_text


# ==============================================================================
# 4. RemediationEngine & Script Formatting
# ==============================================================================

def test_engine_plan_generation():
    findings = [
        make_failed_finding("PSC-1.1"),
        make_failed_finding("PSC-1.2"),
        make_failed_finding("PSC-4.1")
    ]
    plan = RemediationEngine.generate_plan(
        audit_id="TEST-AUDIT-001",
        vendor="Cisco",
        hostname="core-rtr",
        findings=findings
    )
    assert plan.audit_id == "TEST-AUDIT-001"
    assert plan.vendor == "Cisco"
    assert plan.hostname == "core-rtr"
    assert plan.total_failed_controls == 3
    assert plan.remediated_controls_count == 3
    assert plan.file_extension == ".cfg"
    assert plan.deployment_warning is not None
    assert "DO NOT blindly execute" in plan.full_script

    # Verify manual action is safely commented out in Cisco script
    assert "[MANUAL ACTION REQUIRED]" in plan.full_script


def test_fortinet_script_formatting():
    findings = [make_failed_finding("PSC-1.3")]
    plan = RemediationEngine.generate_plan(
        audit_id="TEST-FORTI-001",
        vendor="Fortinet",
        hostname="edge-fgt",
        findings=findings
    )
    assert plan.file_extension == ".conf"
    assert "# Target Vendor:     Fortinet" in plan.full_script
    assert "admin-https-redirect enable" in plan.full_script


def test_palo_alto_script_formatting():
    findings = [make_failed_finding("PSC-1.8")]
    plan = RemediationEngine.generate_plan(
        audit_id="TEST-PAN-001",
        vendor="Palo Alto",
        hostname="fw-pan-01",
        findings=findings
    )
    assert plan.file_extension == ".set"
    assert "# Target Vendor:     Palo Alto" in plan.full_script
    assert "set deviceconfig system login-banner" in plan.full_script


# ==============================================================================
# 5. REST API Integration Tests
# ==============================================================================

def test_api_remediation_endpoints(client):
    # 1. Ingest a sample configuration
    cisco_sample = """
    hostname edge-gw-01
    version 15.4
    line vty 0 4
     transport input telnet
     no exec-timeout
    ip access-list extended INBOUND-PERM
     permit ip any any
    """
    analyze_res = client.post(
        "/api/audits/analyze",
        json={"content": cisco_sample, "filename": "edge_gw.cfg"}
    )
    assert analyze_res.status_code == 200
    audit_data = analyze_res.json()
    audit_id = audit_data["id"]

    # 2. Query remediation plan endpoint
    rem_res = client.get(f"/api/audits/{audit_id}/remediation")
    assert rem_res.status_code == 200
    plan = rem_res.json()
    assert plan["audit_id"] == audit_id
    assert plan["vendor"] == "Cisco"
    assert plan["remediated_controls_count"] > 0
    assert len(plan["actions"]) > 0

    # 3. Query remediation download endpoint
    dl_res = client.get(f"/api/audits/{audit_id}/remediation/download")
    assert dl_res.status_code == 200
    assert "text/plain" in dl_res.headers["content-type"]
    assert "attachment;" in dl_res.headers["content-disposition"]
    assert f"remediation_cisco_{audit_id}.cfg" in dl_res.headers["content-disposition"]
    script_text = dl_res.text
    assert "AUTOMATED NETWORK SECURITY COMPLIANCE REMEDIATION SCRIPT" in script_text
    assert script_text == plan["full_script"]


def test_api_remediation_download_all_vendors(client):
    """Verify download endpoint produces correct extensions, MIME types, and exact script matches for Fortinet and Palo Alto."""
    # 1. Fortinet .conf download
    fgt_sample = """#config-version=FG100F-7.2.4:opmode=0
config system global
    set hostname "fgt-remediation-test"
    set admintimeout 30
end
config system interface
    edit "port1"
        set allowaccess ping telnet
    next
end
"""
    fgt_res = client.post("/api/audits/analyze", json={"content": fgt_sample, "filename": "fgt.conf"})
    assert fgt_res.status_code == 200
    fgt_id = fgt_res.json()["id"]

    fgt_plan = client.get(f"/api/audits/{fgt_id}/remediation").json()
    fgt_dl = client.get(f"/api/audits/{fgt_id}/remediation/download")
    assert fgt_dl.status_code == 200
    assert "text/plain" in fgt_dl.headers["content-type"]
    assert f"remediation_fortinet_{fgt_id}.conf" in fgt_dl.headers["content-disposition"]
    assert len(fgt_dl.text) > 0
    assert fgt_dl.text == fgt_plan["full_script"]
    assert "admin-telnet disable" in fgt_dl.text

    # 2. Palo Alto .set download
    pa_sample = """
    set deviceconfig system hostname "pa-remediation-test"
    set deviceconfig system service disable-telnet no
    set rulebase security rules "allow-all" action allow source any destination any
    """
    pa_res = client.post("/api/audits/analyze", json={"content": pa_sample, "filename": "pa.set"})
    assert pa_res.status_code == 200
    pa_id = pa_res.json()["id"]

    pa_plan = client.get(f"/api/audits/{pa_id}/remediation").json()
    pa_dl = client.get(f"/api/audits/{pa_id}/remediation/download")
    assert pa_dl.status_code == 200
    assert "text/plain" in pa_dl.headers["content-type"]
    assert f"remediation_palo_alto_{pa_id}.set" in pa_dl.headers["content-disposition"]
    assert len(pa_dl.text) > 0
    assert pa_dl.text == pa_plan["full_script"]
    assert "set deviceconfig system service disable-telnet yes" in pa_dl.text
    assert "commit" in pa_dl.text


def test_api_remediation_not_found(client):
    res = client.get("/api/audits/NON-EXISTENT-AUDIT-ID/remediation")
    assert res.status_code == 404

    res_dl = client.get("/api/audits/NON-EXISTENT-AUDIT-ID/remediation/download")
    assert res_dl.status_code == 404


# ==============================================================================
# 6. Hardened Vendor Command Syntax Verification
# ==============================================================================

def test_cisco_syntax_hardening():
    remediator = get_remediator("Cisco")
    
    # PSC-1.1 SSH timeout without hyphen
    ssh_act = remediator.generate_action(make_failed_finding("PSC-1.1"))
    assert "ip ssh timeout 60" in ssh_act.commands
    assert "ip ssh time-out 60" not in ssh_act.commands

    # PSC-1.2 Telnet downgraded to REVIEW_REQUIRED
    telnet_act = remediator.generate_action(make_failed_finding("PSC-1.2"))
    assert telnet_act.safety_classification == SafetyClassification.REVIEW_REQUIRED

    # PSC-2.4 SNMP defaults downgraded to REVIEW_REQUIRED
    snmp_act = remediator.generate_action(make_failed_finding("PSC-2.4"))
    assert snmp_act.safety_classification == SafetyClassification.REVIEW_REQUIRED

    # PSC-3.1 Legacy includes modern no ip finger
    legacy_act = remediator.generate_action(make_failed_finding("PSC-3.1"))
    assert "no ip finger" in legacy_act.commands


def test_fortinet_syntax_hardening():
    remediator = get_remediator("Fortinet")

    # PSC-1.1 strong-crypto
    ssh_act = remediator.generate_action(make_failed_finding("PSC-1.1"))
    assert any("strong-crypto enable" in c for c in ssh_act.commands)

    # PSC-1.2 global admin-telnet disable
    telnet_act = remediator.generate_action(make_failed_finding("PSC-1.2"))
    assert any("admin-telnet disable" in c for c in telnet_act.commands)
    assert telnet_act.safety_classification == SafetyClassification.REVIEW_REQUIRED

    # PSC-1.6 minimum-length keyword
    pwd_act = remediator.generate_action(make_failed_finding("PSC-1.6"))
    assert any("minimum-length 14" in c for c in pwd_act.commands)
    assert not any("min-length 14" in c for c in pwd_act.commands)

    # PSC-2.3 ntpsync enable
    ntp_act = remediator.generate_action(make_failed_finding("PSC-2.3"))
    assert any("ntpsync enable" in c for c in ntp_act.commands)

    # PSC-2.4 No guessed delete 1
    snmp_act = remediator.generate_action(make_failed_finding("PSC-2.4"))
    assert not any("delete 1" in c for c in snmp_act.commands)
    assert any("<DEFAULT_COMMUNITY_ID>" in c for c in snmp_act.commands)
    assert snmp_act.safety_classification == SafetyClassification.REVIEW_REQUIRED

    # PSC-4.2 fwpolicy-implicit-log enable
    deny_act = remediator.generate_action(make_failed_finding("PSC-4.2"))
    assert any("fwpolicy-implicit-log enable" in c for c in deny_act.commands)


def test_palo_alto_syntax_hardening():
    remediator = get_remediator("Palo Alto")

    # PSC-1.1 mgmt ciphers
    ssh_act = remediator.generate_action(make_failed_finding("PSC-1.1"))
    assert any("ciphers mgmt aes256-gcm" in c for c in ssh_act.commands)
    assert ssh_act.safety_classification == SafetyClassification.REVIEW_REQUIRED

    # PSC-1.6 minimum-length keyword
    pwd_act = remediator.generate_action(make_failed_finding("PSC-1.6"))
    assert any("minimum-length 14" in c for c in pwd_act.commands)
    assert not any("min-password-length 14" in c for c in pwd_act.commands)

    # PSC-1.7 setting management idle-timeout
    timeout_act = remediator.generate_action(make_failed_finding("PSC-1.7"))
    assert any("setting management idle-timeout 10" in c for c in timeout_act.commands)

    # PSC-2.1 shared auth profile
    aaa_act = remediator.generate_action(make_failed_finding("PSC-2.1"))
    assert any("set shared authentication-profile" in c for c in aaa_act.commands)
    assert any("server-profile" in c for c in aaa_act.commands)

    # PSC-2.2 Syslog collector hierarchy
    syslog_act = remediator.generate_action(make_failed_finding("PSC-2.2"))
    assert any('server "SIEM-Collector" server' in c for c in syslog_act.commands)

    # PSC-2.3 primary-ntp-server ntp-server-address
    ntp_act = remediator.generate_action(make_failed_finding("PSC-2.3"))
    assert any("primary-ntp-server ntp-server-address" in c for c in ntp_act.commands)

    # PSC-2.4 access-setting snmp-community-string
    snmp_act = remediator.generate_action(make_failed_finding("PSC-2.4"))
    assert any("access-setting version v2c snmp-community-string" in c for c in snmp_act.commands)
    assert snmp_act.safety_classification == SafetyClassification.REVIEW_REQUIRED

    # PSC-2.5 access-setting users authproto SHA privproto AES
    snmp3_act = remediator.generate_action(make_failed_finding("PSC-2.5"))
    assert any("access-setting version v3 users" in c for c in snmp3_act.commands)

    # PSC-4.2 interzone-default log-end override
    deny_act = remediator.generate_action(make_failed_finding("PSC-4.2"))
    assert any("interzone-default log-end yes" in c for c in deny_act.commands)
    assert deny_act.safety_classification == SafetyClassification.REVIEW_REQUIRED

    # Commit verification across all non-manual Palo Alto actions
    for cid in ALL_CONTROL_IDS:
        act = remediator.generate_action(make_failed_finding(cid))
        if act.safety_classification != SafetyClassification.MANUAL_ONLY and act.commands and not act.commands[0].startswith("#"):
            assert "commit" in act.commands, f"PAN-OS {cid} missing commit"

