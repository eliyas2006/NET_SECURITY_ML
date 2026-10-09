# System Architecture & Technical Specification
## AI-Driven Multi-Vendor Network Security Compliance Auditor

### 1. Architectural Blueprint
The platform implements a multi-tier hybrid architecture combining deterministic rules for precise regulatory standard compliance with machine learning models for holistic configuration risk and anomaly assessment.

```
                          ┌──────────────────────────┐
                          │    Security Engineer     │
                          └────────────┬─────────────┘
                                       │ (HTTP/REST)
                                       ▼
                          ┌──────────────────────────┐
                          │  React 18 + Vite Web UI  │
                          └────────────┬─────────────┘
                                       │ (JSON / Multipart)
                                       ▼
                          ┌──────────────────────────┐
                          │  FastAPI Backend Server  │
                          └────────────┬─────────────┘
                                       │
                                       ▼
                          ┌──────────────────────────┐
                          │   Audit Orchestrator     │
                          └────────────┬─────────────┘
                                       │
                                       ▼
                          ┌──────────────────────────┐
                          │ Vendor Detector & Parser │
                          │ (Cisco, Fortinet, PAN-OS)│
                          └────────────┬─────────────┘
                                       │
                                       ▼
                          ┌──────────────────────────┐
                          │ Vendor-Neutral Normalizer│
                          │(Common Security Schema)  │
                          └────────────┬─────────────┘
                                       │
                     ┌─────────────────┴─────────────────┐
                     │                                   │
                     ▼                                   ▼
        ┌─────────────────────────┐         ┌─────────────────────────┐
        │   Deterministic Rule    │         │  Machine Learning Model │
        │         Engine          │         │     (Random Forest +    │
        │ (16 CIS/NIST Controls)  │         │    Isolation Forest)    │
        └────────────┬────────────┘         └────────────┬────────────┘
                     │                                   │
                     └─────────────────┬─────────────────┘
                                       │
                                       ▼
                          ┌──────────────────────────┐
                          │   Risk Aggregator        │
                          │ Score = 0.55*Rule +      │
                          │         0.45*ML + Anomaly│
                          └────────────┬─────────────┘
                                       │
                     ┌─────────────────┴─────────────────┐
                     │                                   │
                     ▼                                   ▼
        ┌─────────────────────────┐         ┌─────────────────────────┐
        │     Relational DB       │         │    Report Generator     │
        │ (SQLite / PostgreSQL)   │         │ (Standalone HTML / PDF) │
        └─────────────────────────┘         └─────────────────────────┘
```

An interactive vector diagram is also preserved in [`docs/assets/architecture.svg`](docs/assets/architecture.svg).

---

### 2. Subsystem Descriptions

#### 2.1 Web UI (React 18 + Vite)
- **Dashboard**: High-level posture KPIs (Total Audits, Compliant Ratio, High-Risk Nodes, Critical Violations), risk tier distribution bars, and recent audits table.
- **Upload & Audit**: Dual-mode ingestion (file upload or direct configuration text), preset 1-click test configurations, vendor override option, and real-time 8-stage animated pipeline progress visualizer.
- **Audit Detail View**: Device header, posture KPIs, transparent risk formula breakdown, ML factor explainability cards, and filterable findings explorer (status tabs, severity filter, search, copyable CLI remediation snippets).
- **History View**: Searchable archive of all historical audit runs with deletion and report generation triggers.

#### 2.2 Backend Orchestrator (Python + FastAPI)
- Asynchronous non-blocking architecture.
- Modular decoupled directory structure (`api`, `compliance`, `database`, `features`, `ml`, `parsers`, `reports`, `risk`, `schemas`, `services`).
- Full OpenAPI v3 documentation available at `/docs` and `/redoc`.

#### 2.3 Vendor Identification & Parsers
- **Vendor Identification**: Syntax heuristics, version headers, interface conventions, and command token analysis with confidence scoring.
- **Cisco IOS Parser**: Ingests line-based hierarchical Cisco blocks, user secrets (Type 5/7/8/9), line vty transport, AAA, logging, SNMPv3, and ACL stanzas.
- **Fortinet FortiOS Parser**: Parses hierarchical `config ... edit ... set ... next ... end` stanzas, firewall policies, interface allowaccess directives, admin timeouts, and syslog destinations.
- **Palo Alto PAN-OS Parser**: Parses `set` command trees for `rulebase security rules`, `deviceconfig system`, admin password profiles, and logging settings.

#### 2.4 Common Security Schema & Feature Extraction
- **Pydantic Models**: Type-safe normalized models (`SSHConfig`, `PasswordConfig`, `AuthenticationConfig`, `LoggingConfig`, `NTPConfig`, `SNMPConfig`, `FirewallRule`, `InterfaceConfig`, `CryptoConfig`).
- **Feature Extractor**: Maps the normalized schema into an ordered 29-dimensional numerical feature vector for the ML model, operating strictly on observable configuration settings without post-compliance label leakage.

#### 2.5 Dual Analysis Engines
- **Deterministic Rule Engine**: Enforces 16 baseline controls mapped to CIS and NIST SP 800-53. Produces status (`PASS`, `FAIL`, `WARN`), severity, evidence snippets, and remediation CLI commands.
- **Machine Learning Risk Engine**:
  - Primary Model: Random Forest Classifier (100 estimators, balanced weights) trained on 1,200 grounded multi-vendor configuration vectors.
  - Anomaly Detector: Isolation Forest model detecting structural configuration deviations.
  - Explainability: Dynamic calculation of feature contribution scores based on Gini/MDI importances.

#### 2.6 Transparent Risk Aggregator
- Formula:
  $$\text{Composite Risk} = \min\left(100, 0.55 \times \text{RuleScore} + 0.45 \times \text{MLScore} + \text{AnomalyPenalty}\right)$$
- Mandatory Safety Floor:
  - Any confirmed Critical compliance violation (e.g. unrestricted firewall rule) automatically floors the composite score to $\ge 70.0$ (`HIGH` tier minimum).
  - $\ge 2$ Critical violations automatically floors the composite score to $\ge 85.0$ (`CRITICAL` tier).

#### 2.7 Database & Persistence Layer
- SQLAlchemy ORM with support for SQLite (default) and PostgreSQL.
- Foreign-key cascaded tables for audits and findings.

#### 2.8 Automated Vendor-Specific Remediation Engine (Stage 3A)
- **Role**: Translates non-passing Project Security Controls (`PSC-1.1` to `PSC-4.2`) into native CLI command sequences for Cisco (`.cfg`), Fortinet (`.conf`), and Palo Alto (`.set`).
- **Safety Protocol**:
  - `SAFE_AUTOMATIC`: Deterministic fixes (e.g. disable Telnet/HTTP, exec-timeout, MOTD banner).
  - `REVIEW_REQUIRED`: Commands with explicit parameter placeholders (`<PLACEHOLDER>`) for server IPs, secrets, and interface names.
  - `MANUAL_ONLY`: Wildcard permit-any rules where automated execution risks network outages; safe procedural guidelines are rendered as commented blocks.
- **Verification & Reversibility**: Each remediation action provides non-destructive post-change validation commands and emergency rollback instructions.
- **Zero-Execution Architecture**: Scripts are generated for review and manual download only; the platform never executes commands against network nodes directly. See [`docs/REMEDIATION_ENGINE.md`](docs/REMEDIATION_ENGINE.md) for full specifications.

