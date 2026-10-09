"""
Vendor-Neutral Common Security Configuration Schema.
Defines standardized data models representing network and firewall configuration state.
"""

from typing import List, Dict, Optional, Any
from pydantic import BaseModel, Field


class SSHConfig(BaseModel):
    enabled: bool = False
    version: int = 0  # 0: disabled, 1: v1, 2: v2
    ciphers: List[str] = Field(default_factory=list)
    timeout_seconds: Optional[int] = None
    authentication_retries: Optional[int] = None


class PasswordConfig(BaseModel):
    service_encryption: bool = False
    min_length: int = 0
    weak_algorithm_count: int = 0  # Type 7 / MD5
    strong_algorithm_count: int = 0  # Type 8/9/SHA256/bcrypt
    user_accounts: List[Dict[str, Any]] = Field(default_factory=list)
    enable_secret_present: bool = False
    enable_secret_strong: bool = False


class AuthenticationConfig(BaseModel):
    aaa_enabled: bool = False
    radius_servers: List[str] = Field(default_factory=list)
    tacacs_servers: List[str] = Field(default_factory=list)
    login_banner_present: bool = False
    login_banner_text: Optional[str] = None
    exec_timeout_minutes: int = 0  # 0 indicates no timeout


class LoggingConfig(BaseModel):
    enabled: bool = False
    buffered_level: int = 0  # 0-7 syslog levels
    console_logging: bool = False
    syslog_servers: List[str] = Field(default_factory=list)
    timestamp_enabled: bool = False


class NTPConfig(BaseModel):
    servers: List[str] = Field(default_factory=list)
    authenticated: bool = False


class SNMPConfig(BaseModel):
    v1_v2c_enabled: bool = False
    v3_enabled: bool = False
    default_community_used: bool = False  # e.g., 'public', 'private'
    communities: List[str] = Field(default_factory=list)
    v3_users: List[str] = Field(default_factory=list)


class FirewallRule(BaseModel):
    rule_id: str
    name: Optional[str] = None
    action: str = "deny"  # permit / deny / reject
    source_zones: List[str] = Field(default_factory=list)
    destination_zones: List[str] = Field(default_factory=list)
    source_ips: List[str] = Field(default_factory=list)
    destination_ips: List[str] = Field(default_factory=list)
    services: List[str] = Field(default_factory=list)
    is_unrestricted: bool = False  # True if source=any AND dest=any AND action=permit
    logging_enabled: bool = False


class InterfaceConfig(BaseModel):
    name: str
    ip_address: Optional[str] = None
    is_management: bool = False
    management_protocols: List[str] = Field(default_factory=list)  # ssh, telnet, http, https, snmp
    zone: Optional[str] = None
    is_shutdown: bool = False


class CryptoConfig(BaseModel):
    vpn_configured: bool = False
    modern_ciphers: bool = False  # AES, SHA256+, DH 14+
    legacy_ciphers_detected: List[str] = Field(default_factory=list)  # DES, 3DES, MD5


class NormalizedConfiguration(BaseModel):
    vendor: str  # Cisco, Fortinet, Palo Alto, Generic
    device_type: str = "Router/Firewall"
    hostname: str = "unknown-device"
    os_version: Optional[str] = None
    raw_lines_count: int = 0

    ssh: SSHConfig = Field(default_factory=SSHConfig)
    passwords: PasswordConfig = Field(default_factory=PasswordConfig)
    auth: AuthenticationConfig = Field(default_factory=AuthenticationConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    ntp: NTPConfig = Field(default_factory=NTPConfig)
    snmp: SNMPConfig = Field(default_factory=SNMPConfig)
    crypto: CryptoConfig = Field(default_factory=CryptoConfig)

    telnet_enabled: bool = False
    http_server_enabled: bool = False
    https_server_enabled: bool = False
    insecure_services: List[str] = Field(default_factory=list)

    firewall_rules: List[FirewallRule] = Field(default_factory=list)
    default_deny: bool = False
    interfaces: List[InterfaceConfig] = Field(default_factory=list)

    metadata: Dict[str, Any] = Field(default_factory=dict)
