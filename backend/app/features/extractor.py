"""
Security Feature Extractor.
Extracts 29-dimensional normalized numerical/binary feature vector for Machine Learning models.
Excludes post-compliance rule summary metrics to prevent label leakage and eliminate risk double-counting.
"""

from typing import List, Dict, Any, Optional
import numpy as np
from backend.app.schemas.normalized import NormalizedConfiguration
from backend.app.schemas.compliance import ComplianceSummary

FEATURE_NAMES = [
    "ssh_version",
    "ssh_enabled",
    "telnet_enabled",
    "http_server_enabled",
    "https_server_enabled",
    "password_encryption_enabled",
    "weak_password_algorithms_count",
    "strong_password_algorithms_count",
    "min_password_length",
    "aaa_new_model_enabled",
    "logging_enabled",
    "remote_syslog_count",
    "logging_buffered_level",
    "ntp_servers_count",
    "ntp_authenticated",
    "snmp_v1_v2c_enabled",
    "snmp_default_community_used",
    "snmp_v3_enabled",
    "insecure_services_count",
    "login_banner_configured",
    "exec_timeout_minutes",
    "firewall_rules_total",
    "unrestricted_rules_count",
    "default_deny_enforced",
    "exposed_management_interfaces",
    "vpn_crypto_modern",
    "vendor_cisco",
    "vendor_fortinet",
    "vendor_paloalto",
]


def extract_features(cfg: NormalizedConfiguration, compliance: Optional[ComplianceSummary] = None) -> Dict[str, float]:
    """
    Extracts dictionary of 29 raw configuration security features.
    Operates strictly on observable device configuration settings.
    """
    # Vendor one-hot
    v = cfg.vendor.lower()
    is_cisco = 1.0 if "cisco" in v else 0.0
    is_fortinet = 1.0 if "fortinet" in v or "fortigate" in v else 0.0
    is_paloalto = 1.0 if "palo" in v or "pan" in v else 0.0

    # Firewall unrestricted count
    unrestricted_count = sum(1 for r in cfg.firewall_rules if r.is_unrestricted)

    # Exposed management interfaces count
    exposed_mgmt = sum(1 for iface in cfg.interfaces if iface.is_management and ("telnet" in iface.management_protocols or "http" in iface.management_protocols))

    features: Dict[str, float] = {
        "ssh_version": float(cfg.ssh.version),
        "ssh_enabled": 1.0 if cfg.ssh.enabled else 0.0,
        "telnet_enabled": 1.0 if cfg.telnet_enabled else 0.0,
        "http_server_enabled": 1.0 if cfg.http_server_enabled else 0.0,
        "https_server_enabled": 1.0 if cfg.https_server_enabled else 0.0,
        "password_encryption_enabled": 1.0 if cfg.passwords.service_encryption else 0.0,
        "weak_password_algorithms_count": float(cfg.passwords.weak_algorithm_count),
        "strong_password_algorithms_count": float(cfg.passwords.strong_algorithm_count),
        "min_password_length": float(cfg.passwords.min_length),
        "aaa_new_model_enabled": 1.0 if cfg.auth.aaa_enabled else 0.0,
        "logging_enabled": 1.0 if cfg.logging.enabled else 0.0,
        "remote_syslog_count": float(len(cfg.logging.syslog_servers)),
        "logging_buffered_level": float(cfg.logging.buffered_level),
        "ntp_servers_count": float(len(cfg.ntp.servers)),
        "ntp_authenticated": 1.0 if cfg.ntp.authenticated else 0.0,
        "snmp_v1_v2c_enabled": 1.0 if cfg.snmp.v1_v2c_enabled else 0.0,
        "snmp_default_community_used": 1.0 if cfg.snmp.default_community_used else 0.0,
        "snmp_v3_enabled": 1.0 if cfg.snmp.v3_enabled else 0.0,
        "insecure_services_count": float(len(cfg.insecure_services)),
        "login_banner_configured": 1.0 if cfg.auth.login_banner_present else 0.0,
        "exec_timeout_minutes": float(cfg.auth.exec_timeout_minutes),
        "firewall_rules_total": float(len(cfg.firewall_rules)),
        "unrestricted_rules_count": float(unrestricted_count),
        "default_deny_enforced": 1.0 if cfg.default_deny else 0.0,
        "exposed_management_interfaces": float(exposed_mgmt),
        "vpn_crypto_modern": 1.0 if cfg.crypto.modern_ciphers else 0.0,
        "vendor_cisco": is_cisco,
        "vendor_fortinet": is_fortinet,
        "vendor_paloalto": is_paloalto,
    }

    return features


def features_to_vector(features: Dict[str, float]) -> np.ndarray:
    """Converts feature dictionary into an ordered 1D numpy array."""
    return np.array([features[name] for name in FEATURE_NAMES], dtype=np.float32)
