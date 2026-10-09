# Automated Vendor-Specific Remediation Script Generation Engine
## AI-Driven Multi-Vendor Network Security Compliance Auditor — Stage 3A

---

### 1. Executive Summary & Objective

The **Automated Remediation Engine** synthesizes actionable, syntactically correct CLI remediation commands tailored specifically for:
1. **Cisco IOS / IOS-XE** (`.cfg`)
2. **Fortinet FortiOS** (`.conf`)
3. **Palo Alto PAN-OS** (`.set`)

The system enables security operators and network engineers to rapidly transition from audit discovery to remediation while enforcing rigorous safety protocols, parameter hygiene, and verification routines.

---

### 2. Architectural Role & Boundary Separation

```
                    ┌─────────────────────────┐
                    │    Raw Configuration    │
                    └────────────┬────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │ Vendor Detection/Parser │
                    └────────────┬────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │ NormalizedConfiguration │
                    └────────────┬────────────┘
                                 │
                     ┌───────────┴───────────┐
                     │                       │
                     ▼                       ▼
        ┌─────────────────────────┐ ┌─────────────────┐
        │ PSC Compliance Engine   │ │ ML Risk Engine  │
        │ (16 Security Controls)  │ │ (Risk & Anomaly │
        └────────────┬────────────┘ │  Inference ONLY)│
                     │              └─────────────────┘
                     ▼
        ┌─────────────────────────┐
        │ Failed & Warn Findings  │
        └────────────┬────────────┘
                     │
                     ▼
        ┌─────────────────────────┐
        │   Remediation Engine    │
        │   & Vendor Registry     │
        └────────────┬────────────┘
                     │
       ┌─────────────┼─────────────┐
       ▼             ▼             ▼
┌──────────────┐┌──────────────┐┌──────────────┐
│ Cisco IOS    ││ Fortinet     ││ Palo Alto    │
│ Remediator   ││ Remediator   ││ Remediator   │
└──────┬───────┘└──────┬───────┘└──────┬───────┘
       │               │               │
       └───────────────┼───────────────┘
                       │
                       ▼
       ┌───────────────────────────────┐
       │ RemediationPlan Data Object   │
       │ - Per-finding Actions         │
       │ - Verification Commands       │
       │ - Rollback Procedures         │
       │ - Compiled CLI Script         │
       └───────────────┬───────────────┘
                       │
             ┌─────────┴─────────┐
             ▼                   ▼
    ┌─────────────────┐ ┌─────────────────┐
    │  REST API JSON  │ │ Direct Download │
    │  & Frontend UI  │ │ (.cfg/.conf/.set│
    └─────────────────┘ └─────────────────┘
```

#### Deterministic vs. ML Architectural Boundary
- **Deterministic Compliance & Remediation Pipeline**: Direct mapping from failed Project Security Controls (`PSC-1.1` through `PSC-4.2`) to verified, vendor-specific syntax structures.
- **Machine Learning Role**: The ML models (Random Forest Classifier & Isolation Forest Anomaly Detector) predict posture tier, estimate holistic exposure, and flag configuration outliers. **The ML model NEVER directly generates configuration commands**, eliminating hallucinated syntax, command injection, or unauthorized configuration changes.

---

### 3. Safety Classification Matrix

Every generated remediation action is categorized into one of three strict safety tiers:

| Safety Tier | Definition | Examples | Engine Behavior |
| :--- | :--- | :--- | :--- |
| **`SAFE_AUTOMATIC`** | Exact fix can be generated deterministically without guessing values or operational topology context. Minimal risk of disruption. | Disabling Telnet (`PSC-1.2`), Disabling HTTP Server (`PSC-1.3`), Enabling Password Encryption (`PSC-1.4`), Setting Password Min-Length (`PSC-1.6`), Setting Exec-Timeout (`PSC-1.7`), MOTD Banner (`PSC-1.8`), Disabling Small Servers/Finger (`PSC-3.1`). | CLI commands are immediately generated and marked safe for automated staging application. |
| **`REVIEW_REQUIRED`** | Remediation syntax is standard, but the change requires environment-specific inputs (server IPs, keys) or may impact administrator access. | RSA Key Generation (`PSC-1.1`), Strong Secret Hashing (`PSC-1.5`), AAA Server Setup (`PSC-2.1`), Syslog Server (`PSC-2.2`), NTP Server (`PSC-2.3`), SNMPv3 (`PSC-2.5`), Default Deny Append (`PSC-4.2`). | Commands include structured `<PLACEHOLDER>` tokens that must be populated by the engineer before execution. |
| **`MANUAL_ONLY`** | Change requires manual policy and traffic flow analysis. Automated command generation would risk dropping production traffic. | Replacing Wildcard `permit any any` rules (`PSC-4.1`). | The remediation engine **comments out** executable lines in scripts (`! [MANUAL ACTION REQUIRED]` / `# [MANUAL ACTION REQUIRED]`) and outputs an operational guidance workflow. |

---

### 4. Control-by-Control Vendor CLI Mapping (All 16 PSC Controls)

#### Domain 1: Management Plane Security

| Control ID | Control Title | Safety | Cisco IOS Remediation | Fortinet FortiOS Remediation | Palo Alto PAN-OS Remediation |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **PSC-1.1** | SSH Enforced | `REVIEW_REQUIRED` | `crypto key generate rsa modulus 2048`<br>`ip ssh version 2` | `config system global`<br>` set admin-ssh-port 22`<br>`end` | `set deviceconfig system ssh ciphers ...`<br>`commit` |
| **PSC-1.2** | Disable Telnet | `SAFE_AUTOMATIC` | `line vty 0 15`<br>` transport input ssh`<br>`exit` | `config system interface`<br>` edit "<IFACE>"`<br>` set allowaccess ping https ssh`<br>`end` | `set deviceconfig system service disable-telnet yes`<br>`commit` |
| **PSC-1.3** | Disable HTTP | `SAFE_AUTOMATIC` | `no ip http server`<br>`ip http secure-server` | `config system global`<br>` set admin-https-redirect enable`<br>`end` | `set deviceconfig system service disable-http yes`<br>`commit` |
| **PSC-1.4** | Password Encryption | `SAFE_AUTOMATIC` | `service password-encryption` | `config system global`<br>` set strong-crypto enable`<br>`end` | *(Implicitly encrypted via master key)* |
| **PSC-1.5** | Strong Password Hash | `REVIEW_REQUIRED` | `enable algorithm-type sha256 secret <PWD>` | `config system admin`<br>` edit "<USER>"`<br>` set password <PWD>`<br>`end` | `set mgt-config users <USER> password`<br>`commit` |
| **PSC-1.6** | Min Password Length | `SAFE_AUTOMATIC` | `security passwords min-length 14` | `config system global`<br>` set admin-password-min-len 14`<br>`end` | `set deviceconfig system password-complexity min-length 14`<br>`commit` |
| **PSC-1.7** | Session Timeout | `SAFE_AUTOMATIC` | `line con 0`<br>` exec-timeout 10 0`<br>`line vty 0 15`<br>` exec-timeout 10 0` | `config system global`<br>` set admintimeout 10`<br>`end` | `set deviceconfig system idle-timeout 10`<br>`commit` |
| **PSC-1.8** | Legal Warning Banner | `SAFE_AUTOMATIC` | `banner motd ^C Authorized Personnel Only. All activities monitored. ^C` | `config system global`<br>` set pre-login-banner enable`<br>` set post-login-banner enable`<br>`end` | `set deviceconfig system login-banner "Authorized Access Only..."`<br>`commit` |

#### Domain 2: AAA & Monitoring Controls

| Control ID | Control Title | Safety | Cisco IOS Remediation | Fortinet FortiOS Remediation | Palo Alto PAN-OS Remediation |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **PSC-2.1** | Centralized AAA | `REVIEW_REQUIRED` | `aaa new-model`<br>`aaa group server tacacs+ TACACS_GROUP`<br>` server-private <TACACS_IP> key 7 <KEY>` | `config user tacacs+`<br>` edit "ENTERPRISE_TACACS"`<br>` set server "<TACACS_IP>"`<br>` set key "<KEY>"` | `set authentication-profile "ENTERPRISE_RADIUS" ...`<br>`commit` |
| **PSC-2.2** | Remote Syslog | `REVIEW_REQUIRED` | `logging buffered 64000 informational`<br>`logging host <SIEM_SERVER_IP>` | `config log syslogd setting`<br>` set status enable`<br>` set server "<SIEM_SERVER_IP>"` | `set shared log-settings syslog "Central-SIEM" server "<SIEM_SERVER_IP>" ...`<br>`commit` |
| **PSC-2.3** | NTP Synchronization | `REVIEW_REQUIRED` | `ntp server <NTP_SERVER_IP>`<br>`ntp authenticate` | `config system ntp`<br>` set type custom`<br>` config ntpserver`<br>` edit 1`<br>` set server "<NTP_SERVER_IP>"` | `set deviceconfig system ntp-servers primary-ntp-server ntp-server-address <NTP_IP>`<br>`commit` |
| **PSC-2.4** | Default SNMP Community | `SAFE_AUTOMATIC` | `no snmp-server community public`<br>`no snmp-server community private` | `config system snmp community`<br>` delete 1`<br>`end` | `delete deviceconfig system snmp-setting version v2c`<br>`commit` |
| **PSC-2.5** | SNMPv3 Enforced | `REVIEW_REQUIRED` | `snmp-server group SEC_V3 v3 priv`<br>`snmp-server user <USER> SEC_V3 v3 auth sha <AUTH_PWD> priv aes 128 <PRIV_PWD>` | `config system snmp user`<br>` edit "snmpv3_sec"`<br>` set security-level auth-priv`<br>` set auth-proto sha`<br>` set priv-proto aes` | `set deviceconfig system snmp-setting version v3 ...`<br>`commit` |

#### Domain 3: Network Service Hardening

| Control ID | Control Title | Safety | Cisco IOS Remediation | Fortinet FortiOS Remediation | Palo Alto PAN-OS Remediation |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **PSC-3.1** | Insecure Services | `SAFE_AUTOMATIC` | `no service finger`<br>`no ip source-route`<br>`no service tcp-small-servers`<br>`no service udp-small-servers` | `config system global`<br>` set dnsproxy-worker-count 0`<br>`end` | `delete deviceconfig system service disable-telnet`<br>`commit` |

#### Domain 4: Firewall & Access Control

| Control ID | Control Title | Safety | Cisco IOS Remediation | Fortinet FortiOS Remediation | Palo Alto PAN-OS Remediation |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **PSC-4.1** | No Wildcard Permit Rules | `MANUAL_ONLY` | *(Commented out guidance)*<br>`! Identify required flows`<br>`! Remove wildcard: no permit ip any any`<br>`! Add specific least-privilege permits` | *(Commented out guidance)*<br>`# Identify traffic flows`<br>`# Edit policy and restrict service/destination` | *(Commented out guidance)*<br>`# Replace any-any rule with explicit application/service definitions` |
| **PSC-4.2** | Default Deny Enforced | `REVIEW_REQUIRED` | `ip access-list extended <ACL_NAME>`<br>` deny ip any any log` | `config firewall policy`<br>` edit <POLICY_ID>`<br>` set action deny`<br>` set logtraffic all` | `set rulebase security rules "default-deny" action deny ...`<br>`commit` |

---

### 5. Guardrails, Disclaimers, and Zero-Execution Guarantee

1. **Zero-Execution Architecture**:
   - The application has **no execution pipeline** to deploy commands onto network devices.
   - It contains no SSH/Telnet pushing agent, no Netmiko/NAPALM deployer, and no shell command execution primitives (`os.system`, `subprocess.Popen`).
   - Remediation artifacts are strictly rendered as downloadable text scripts or interactive UI cards.
2. **Credential Hygiene**:
   - The system **never fabricates passwords or secret keys**.
   - Where secrets are required, clear placeholders are generated (e.g. `<STRONG_ENABLE_SECRET_PASSWORD>`, `<SHARED_SECRET_KEY>`, `<TACACS_KEY>`).
3. **Mandatory Header Disclaimers**:
   - Every generated script starts with a standardized operator banner reminding engineers to test in lab environments before production deployment.
4. **Validation and Rollback**:
   - Every remediation action includes non-destructive `validation_commands` (e.g., `show running-config | include ip ssh`) and exact `rollback_commands` to revert the configuration if required.

---

### 6. API Reference & Output Formats

- **`GET /api/audits/{audit_id}/remediation`**: Returns full structured `RemediationPlan` JSON including counts, safety classifications, placeholders, and action list.
- **`GET /api/audits/{audit_id}/remediation/download`**: Streams the compiled CLI script formatted with appropriate vendor comments and file extension:
  - Cisco: `remediation_cisco_{audit_id}.cfg`
  - Fortinet: `remediation_fortinet_{audit_id}.conf`
  - Palo Alto: `remediation_palo_alto_{audit_id}.set`
