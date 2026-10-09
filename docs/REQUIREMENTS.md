# Requirements Specification
## AI-Driven Multi-Vendor Network Security Compliance Auditor

### 1. Problem Statement
Enterprise networks deploy heterogeneous security and routing hardware from vendors such as Cisco Systems, Fortinet, and Palo Alto Networks. Maintaining compliance with cybersecurity benchmarks (such as CIS Controls, NIST SP 800-53, and PCI-DSS) across multi-vendor configurations is challenging:
- Syntax and command models differ fundamentally across vendors (hierarchical blocks, bracketed trees, set-based commands, XML-style stanzas).
- Human auditing is error-prone, periodic, and unable to detect subtle configuration drift or multi-factor configuration anomalies.
- Purely deterministic scanners check known static rules (e.g. `no ip ssh version 1`) but fail to classify contextual risk profile, latent security posture anomalies, or configuration patterns indicating negligence or risky deviations.
- Purely machine learning scanners hallucinate vulnerabilities, lack compliance lineage, and cannot guarantee regulatory control enforcement.

**Solution**: A dual-engine hybrid architecture:
1. **Vendor Parsers & Normalization Engine**: Ingest raw multi-vendor configurations and transform them into a Vendor-Neutral Common Security Schema.
2. **Deterministic Compliance Rule Engine**: Enforces exact, auditable security benchmarks (CIS / NIST / Hardening controls) with explicit configuration evidence, pass/fail/warn statuses, and remediation instructions.
3. **ML Risk & Anomaly Engine**: Extracts high-dimensional multidimensional security features from normalized schemas to predict overall configuration risk classification (LOW / MEDIUM / HIGH / CRITICAL) and detect structural configuration anomalies.
4. **Transparent Risk Aggregation Layer**: Merges compliance violations, severity weights, and ML risk predictions using an explainable mathematical formula.
5. **Interactive Dashboard & Reporting System**: Provides a modern cybersecurity management UI with audit logs, findings explorer, filterable tables, and downloadable audit reports.

---

### 2. Target Users
- **Network Security Engineers**: Audit device configuration state prior to staging or deployment.
- **Compliance Auditors (GRC Teams)**: Verify regulatory compliance with clear control mappings and evidence.
- **SecOps / SOC Analysts**: Prioritize risky perimeter and interior devices based on combined rule & ML risk scoring.
- **Enterprise IT Architects**: Maintain standard configuration baselines across multi-vendor fleets.

---

### 3. Functional Requirements (FR)
- **FR-01: Vendor Detection**: Automatically identify configuration vendor (Cisco IOS/IOS-XE, Fortinet FortiOS, Palo Alto PAN-OS) using syntax heuristics and structural fingerprints with confidence scoring; support manual override.
- **FR-02: Multi-Vendor Parsing**: Parse vendor-specific configurations into syntax trees:
  - Cisco IOS hierarchical block syntax (`interface`, `line vty`, `ip access-list`, `snmp-server`, etc.)
  - Fortinet FortiOS structured stanza syntax (`config firewall policy`, `config system interface`, `config user`, `config system admin`, etc.)
  - Palo Alto PAN-OS set/stanza hierarchy (`set rulebase security rules`, `set service`, `set deviceconfig system`, etc.)
- **FR-03: Common Schema Normalization**: Map parsed ASTs into a typed common representation covering:
  - System identification (`hostname`, `vendor`, `device_type`, `os_version`)
  - Remote Access & Management (`ssh`, `telnet`, `http`, `snmp`, `timeouts`)
  - Authentication, Authorization & Accounting (`aaa`, `password_policy`, `local_users`, `banners`)
  - Logging & Auditing (`syslog`, `ntp`, `audit_trails`)
  - Network Services & Protocols (`insecure_services`, `dns`, `routing_security`)
  - Access Control & Firewall (`firewall_rules`, `acls`, `default_actions`, `wildcard_rules`)
  - Cryptography & Transport (`ciphers`, `tls_versions`, `crypto_maps`)
- **FR-04: Deterministic Compliance Engine**: Execute 15+ benchmark rules mapped to CIS/NIST standards with structured findings:
  - Status: `PASS`, `FAIL`, `WARN`
  - Severity: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`
  - Control metadata: `control_id`, `title`, `standard`, `evidence_snippet`, `remediation`
- **FR-05: Security Feature Extraction**: Extract numerical and categorical features (30+ security indicators) quantifying hardening completeness, exposure, and posture metrics.
- **FR-06: ML Risk & Anomaly Assessment**: Evaluate the extracted features through a trained classification model to output risk class probabilities, predicted risk grade, anomaly score, and top contributing feature factors.
- **FR-07: Composite Risk Score Calculation**: Compute normalized risk score (0-100) and risk tier through transparent weighted aggregation combining deterministic severity weights and ML risk probabilities.
- **FR-08: REST API**: Full OpenAPI compliant endpoints for upload, synchronous/asynchronous analysis, audit management, filtering, and report generation.
- **FR-09: Web Dashboard**: Responsive single-page interface with summary KPIs, interactive file upload with real-time pipeline status, audit detail views, filterable findings table, and audit history.
- **FR-10: Audit Report Generation**: Generate standalone, comprehensive audit reports (HTML/printable view & export) containing executive summary, compliance breakdown, ML insights, and full remediation guidance.

---

### 4. Non-Functional Requirements (NFR)
- **NFR-01: Performance**: Configuration parsing and audit evaluation under 2 seconds for configurations up to 10,000 lines.
- **NFR-02: Determinism**: Deterministic compliance rules must produce 100% reproducible results for identical inputs.
- **NFR-03: Explainability**: Every ML prediction must list top feature contributions; ML output is never presented as an unverified vulnerability.
- **NFR-04: Security**: Safe file handling, strict file size limits (max 10MB), no dynamic code execution, strict input sanitization, parameterization in SQL queries, safe path handling to prevent directory traversal.
- **NFR-05: Portability & Local Execution**: Can run completely offline on a developer workstation via standard Python + Node.js or Docker Compose without external SaaS cloud dependencies.
- **NFR-06: Test Coverage**: Automated unit and integration test suite covering all parsers, normalizers, rules, ML inference, and API endpoints.

---

### 5. Supported Inputs & Outputs
- **Inputs**: Raw network device configuration files (`.txt`, `.cfg`, `.conf`, `.set`) for Cisco IOS, Fortinet FortiOS, and Palo Alto PAN-OS.
- **Outputs**:
  - Structured JSON audit result (conforming to OpenAPI schema).
  - Executive summary and compliance score (0-100%).
  - Composite risk score (0-100) and risk grade (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
  - Itemized findings with rule ID, standard reference, severity, evidence lines, and remediation CLI commands.
  - Downloadable/Printable Security Audit Report.

---

### 6. Scope Boundaries
- **MVP Scope**:
  - Cisco IOS/IOS-XE, Fortinet FortiOS, Palo Alto PAN-OS syntax parsers.
  - 16 core CIS/NIST-aligned deterministic compliance controls.
  - Random Forest + Isolation Forest hybrid model trained on documented multi-vendor security feature vectors.
  - SQLite default database (zero-setup) with optional PostgreSQL support via SQLAlchemy.
  - FastAPI backend and modern React + Tailwind/Lucide frontend.
- **Future Scope**:
  - Juniper JunOS, Arista EOS, Check Point Gaia parsers.
  - Automated remediation push via Netmiko/Ansible over SSH.
  - Continuous configuration drift detection via GitOps / syslog hooks.
