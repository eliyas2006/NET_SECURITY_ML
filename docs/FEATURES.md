# Security Feature Dictionary
## AI-Driven Multi-Vendor Network Security Compliance Auditor

This document defines the 29 active security features extracted from the Vendor-Neutral Normalized Configuration Schema and fed into the Machine Learning Risk and Anomaly detection pipeline (and documents the 3 retired post-compliance features).

---

### Feature Definitions & Security Rationale

#### 1. `ssh_version` (Integer: 0, 1, 2)
- **Extraction**: Parsed from SSH configuration stanzas (`ip ssh version X` in Cisco, `set ssh-enc-algo` in Fortinet, `set deviceconfig system ssh` in Palo Alto).
- **Security Rationale**: SSHv1 suffers from CRC32 compensation attack vulnerabilities and weak key exchange. SSHv2 is required by CIS Benchmark 1.1 and NIST 800-53 SC-13.

#### 2. `ssh_enabled` (Binary: 0, 1)
- **Extraction**: True if SSH transport is allowed on terminal lines or admin interfaces.
- **Security Rationale**: Encrypted remote CLI access is an essential prerequisite for administrative confidentiality.

#### 3. `telnet_enabled` (Binary: 0, 1)
- **Extraction**: Detected if `transport input telnet` or `transport input all` is present (Cisco), `allowaccess telnet` is enabled on interfaces (FortiOS), or telnet service is permitted (PAN-OS).
- **Security Rationale**: Telnet transmits user credentials and session traffic in cleartext, exposing the network to eavesdropping and credential theft.

#### 4. `http_server_enabled` (Binary: 0, 1)
- **Extraction**: Detected via `ip http server` (Cisco), `allowaccess http` on interfaces (Fortinet), or HTTP web interface enabled without redirect (PAN-OS).
- **Security Rationale**: Cleartext HTTP management exposes session cookies and administrative passwords to local network adversaries.

#### 5. `https_server_enabled` (Binary: 0, 1)
- **Extraction**: Detected via `ip http secure-server` or `admin-https` directives.
- **Security Rationale**: Encrypted TLS management is the compliant standard for web-based device administration.

#### 6. `password_encryption_enabled` (Binary: 0, 1)
- **Extraction**: Presence of `service password-encryption` (Cisco) or equivalent global reversible password protection.
- **Security Rationale**: Prevents casual shoulder-surfing of cleartext passwords in configuration output.

#### 7. `weak_password_algorithms_count` (Integer >= 0)
- **Extraction**: Count of user/enable passwords stored using Cisco Type 7 (Vigenère-like reversible cipher) or plain MD5 (Type 5) without salt hardening.
- **Security Rationale**: Cisco Type 7 passwords can be decrypted instantly in Python or web tools; weak hashes expose root credentials when configurations are leaked or backed up.

#### 8. `strong_password_algorithms_count` (Integer >= 0)
- **Extraction**: Count of secrets using SHA-256 (Type 8), scrypt (Type 9), or strong PBKDF2/bcrypt.
- **Security Rationale**: Provides high computational resistance against offline dictionary and brute-force attacks.

#### 9. `min_password_length` (Integer: 0 - 32)
- **Extraction**: Value configured in `security passwords min-length X` or password-policy stanzas.
- **Security Rationale**: Enforcing a minimum length (>= 12 characters) exponentially increases entropy against credential guessing.

#### 10. `aaa_new_model_enabled` (Binary: 0, 1)
- **Extraction**: Presence of `aaa new-model` and associated authentication/authorization lists.
- **Security Rationale**: Centralized AAA (RADIUS/TACACS+) decouples identity from local static device accounts and enables granular role-based access control and audit accountability.

#### 11. `logging_enabled` (Binary: 0, 1)
- **Extraction**: Presence of active `logging` directives (console, buffered, or host).
- **Security Rationale**: Without logging, security incident response, forensic reconstruction, and intrusion detection are impossible.

#### 12. `remote_syslog_count` (Integer >= 0)
- **Extraction**: Number of configured remote syslog/SIEM destinations (`logging host X.X.X.X` or `config log syslogd setting`).
- **Security Rationale**: Local logs can be cleared by an attacker who gains privileged access; forwarding to external write-once SIEM systems preserves evidence integrity.

#### 13. `logging_buffered_level` (Integer: 0 - 7)
- **Extraction**: Syslog severity level retained in local buffer (0=Emergencies, 6=Informational, 7=Debugging).
- **Security Rationale**: Retaining informational/warning logs (level 6 or 7) ensures sufficient event depth for post-incident analysis.

#### 14. `ntp_servers_count` (Integer >= 0)
- **Extraction**: Number of upstream NTP time servers configured.
- **Security Rationale**: Correlating security event logs across firewalls, routers, and servers requires millisecond-accurate synchronized clocks.

#### 15. `ntp_authenticated` (Binary: 0, 1)
- **Extraction**: Check if `ntp authenticate` and trusted keys are enforced.
- **Security Rationale**: Unauthenticated NTP allows attackers on adjacent networks to manipulate system clocks to invalidate TLS certificates or conceal timestamps.

#### 16. `snmp_v1_v2c_enabled` (Binary: 0, 1)
- **Extraction**: Configuration of SNMP communities without version 3 user specifications.
- **Security Rationale**: SNMPv1 and v2c send community strings in plaintext across the management network.

#### 17. `snmp_default_community_used` (Binary: 0, 1)
- **Extraction**: Search for well-known default strings: `public`, `private`, `cisco`, `monitor`, `manager`.
- **Security Rationale**: Default community strings are scanned automatically by adversary reconnaissance bots to dump routing tables and interface statistics.

#### 18. `snmp_v3_enabled` (Binary: 0, 1)
- **Extraction**: Presence of `snmp-server group ... v3 priv` or `config system snmp user` with auth/priv algorithms.
- **Security Rationale**: SNMPv3 provides USM authentication and DES/AES packet encryption.

#### 19. `insecure_services_count` (Integer >= 0)
- **Extraction**: Sum of enabled legacy services: `service finger`, `ip bootp server`, `ip rcmd`, `ip source-route`, `service udp-small-servers`, `service tcp-small-servers`.
- **Security Rationale**: Legacy diagnostic services provide amplification DDoS vectors or direct memory inspection avenues for attackers.

#### 20. `login_banner_configured` (Binary: 0, 1)
- **Extraction**: Presence of `banner motd`, `banner login`, or vendor legal warning stanzas.
- **Security Rationale**: Legally required by NIST and PCI-DSS to notify unauthorized intruders that activities are monitored and prosecuted.

#### 21. `exec_timeout_minutes` (Integer: 0 - 120)
- **Extraction**: Inactivity timeout value from `line vty` / `line con 0` or admin profile (0 indicates timeout disabled).
- **Security Rationale**: Unattended open management sessions can be hijacked by physical or network session hijackers. CIS specifies a maximum timeout of 10 or 15 minutes.

#### 22. `firewall_rules_total` (Integer >= 0)
- **Extraction**: Total count of access-list lines, firewall policies, or security rules.
- **Security Rationale**: Metric of network complexity and policy size.

#### 23. `unrestricted_rules_count` (Integer >= 0)
- **Extraction**: Rules configured with source `any`, destination `any`, service `any`, and action `permit` / `allow`.
- **Security Rationale**: Wildcard permit rules bypass the purpose of a perimeter firewall and frequently represent dangerous misconfigurations or forgotten test exceptions.

#### 24. `default_deny_enforced` (Binary: 0, 1)
- **Extraction**: Verification that firewall policies or ACLs end with an explicit or implicit deny-all stance.
- **Security Rationale**: The principle of zero trust and least privilege mandates that any traffic not explicitly permitted must be dropped.

#### 25. `exposed_management_interfaces` (Integer >= 0)
- **Extraction**: Count of interfaces with management access (SSH/HTTP/Telnet/SNMP) bound to untrusted or external interface zones.
- **Security Rationale**: Administrative interfaces should never be exposed to external or untrusted traffic zones.

#### 26. `vpn_crypto_modern` (Binary: 0, 1)
- **Extraction**: Checks if IPsec/IKE transforms utilize modern cryptographic suites (AES-256, SHA-256/384, DH group 14+) rather than deprecated suites (DES, 3DES, MD5, DH group 1/2).
- **Security Rationale**: Deprecated cryptosystems are vulnerable to cryptanalysis (Sweet32, collision attacks).

#### 27. `vendor_cisco` (Binary: 0, 1)
- One-hot indicator: 1 if configuration originates from Cisco IOS/IOS-XE, else 0.

#### 28. `vendor_fortinet` (Binary: 0, 1)
- One-hot indicator: 1 if configuration originates from Fortinet FortiOS, else 0.

#### 29. `vendor_paloalto` (Binary: 0, 1)
- One-hot indicator: 1 if configuration originates from Palo Alto PAN-OS, else 0.

---

### Retired Features (Audit Remediation)
The following 3 features were retired from the ML feature vector during the **Stage 2 Technical Audit** to eliminate label leakage and prevent risk double-counting in the hybrid risk engine:
- `critical_violations_count` (Retired from ML): Formerly derived from `ComplianceSummary.critical_violations`.
- `high_violations_count` (Retired from ML): Formerly derived from `ComplianceSummary.high_violations`.
- `compliance_pass_ratio` (Retired from ML): Formerly derived from `ComplianceSummary.compliance_score / 100.0`.

*Note*: These metrics remain actively calculated by the deterministic `ComplianceEngine` for policy reporting and for computing the 55% rule-based risk score in `RiskEngine`, but they no longer pollute the 29-dimensional machine learning feature space.
