# AI-Driven Multi-Vendor Network Security Compliance Auditor

[![FastAPI](https://img.shields.io/badge/Backend-FastAPI-009688.svg?style=flat&logo=fastapi)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/Frontend-React_19_%2B_Vite-61DAFB.svg?style=flat&logo=react)](https://react.dev)
[![Python](https://img.shields.io/badge/Python-3.12-3776AB.svg?style=flat&logo=python)](https://www.python.org)
[![Scikit-Learn](https://img.shields.io/badge/ML-Scikit--Learn_1.9.1-F7931E.svg?style=flat&logo=scikit-learn)](https://scikit-learn.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> An intelligent, production-grade cybersecurity compliance auditing platform that ingests raw network configuration files from heterogeneous vendors (**Cisco IOS / IOS-XE**, **Fortinet FortiOS**, **Palo Alto PAN-OS**), evaluates deterministic CIS / NIST compliance controls, extracts multi-dimensional security features, executes machine learning risk and anomaly models, generates reviewable CLI remediation artifacts, and renders findings on a modern web dashboard.

---

## 1. Problem Statement & Architecture

Enterprise networks deploy heterogeneous routing, switching, and firewall hardware. Auditing security compliance across varying command syntaxes presents fundamental challenges:
- Syntax models differ fundamentally (hierarchical blocks, bracketed trees, set-based commands).
- Purely deterministic scanners check static rules but miss multi-factor exposure patterns or latent posture drift.
- Purely machine learning scanners hallucinate vulnerabilities and lack verifiable compliance lineage.

**The Solution:** A dual-engine hybrid architecture:
1. **Deterministic Compliance Engine**: Enforces exact, auditable Project Security Controls (PSC-1.1 through PSC-4.2) based on CIS Benchmarks and NIST SP 800-53 controls with line-level evidence and actionable CLI remediation snippets.
2. **Machine Learning Risk Engine**: Evaluates 29 extracted security features via a trained **Random Forest Classifier** and an **Isolation Forest** to classify configuration risk, quantify posture anomalies, and provide explainable factor contributions.
3. **Transparent Risk Aggregator**: Combines compliance violations and ML probabilities into a composite score (0-100) with enforced safety floors:
   $$\text{Composite Risk} = 0.55 \cdot R_{\text{rule}} + 0.45 \cdot R_{\text{ml}} + \Delta_{\text{anomaly}}$$
4. **Automated Remediation Engine**: Generates vendor-specific remediation scripts (`.cfg`, `.conf`, `.set`) with validation commands, rollback procedures, safety classifications (`SAFE_AUTOMATIC`, `REVIEW_REQUIRED`, `MANUAL_ONLY`), and mandatory operator review warnings.

### Architectural Pipeline
```
Configuration Files (.cfg, .conf, .txt)
                    │
                    ▼
          Vendor Identification
        (Heuristic Fingerprinting)
                    │
                    ▼
          Vendor-Specific Parser
        (Cisco, Fortinet, Palo Alto)
                    │
                    ▼
          Vendor-Neutral Normalizer
         (Common Security Schema)
                    │
                    ▼
         Security Feature Extraction
        (29 Standardized Features)
                    │
         ┌──────────┴──────────┐
         │                     │
         ▼                     ▼
Rule-Based Engine       ML Risk Engine
(16 PSC Controls)       (Random Forest +
                         Isolation Forest)
         │                     │
         └──────────┬──────────┘
                    │
                    ▼
        Transparent Risk Aggregator
       Score = 0.55*Rule + 0.45*ML
                    │
                    ▼
         FastAPI REST Backend
                    │
                    ▼
        React 19 + Vite Dashboard
```
*(Vector diagram saved at [`docs/assets/architecture.svg`](docs/assets/architecture.svg))*

---

## 2. Technology Stack

- **Backend**: Python 3.12, FastAPI, Uvicorn, Pydantic v2, SQLAlchemy, Jinja2, Pytest, HTTPX.
- **Frontend**: React 19, Vite, Lucide-React, Custom Dark Cybersecurity UI Design System.
- **Machine Learning**: Scikit-Learn 1.9.1 (pinned), NumPy, Pandas, Joblib.
  - Primary Risk Classifier: Random Forest (100 estimators, balanced class weights, max depth 8).
  - Anomaly Detector: Isolation Forest (100 estimators, 8% contamination).
- **Database**: SQLite (default zero-config local storage) / PostgreSQL via SQLAlchemy.
- **Containerization**: Docker, Docker Compose.

---

## 3. Supported Vendors & Syntaxes

1. **Cisco Systems (IOS / IOS-XE)**:
   - Hierarchical blocks, line vty management, enable secret algorithms (Type 5/7/8/9), AAA, syslog, NTP, SNMPv3, access-lists.
2. **Fortinet (FortiOS)**:
   - Hierarchical `config ... edit ... set ... next ... end` stanzas, firewall policies, interface allowaccess directives, admin timeouts, syslog settings.
3. **Palo Alto Networks (PAN-OS)**:
   - Set-syntax and stanza hierarchies for `rulebase security rules`, `deviceconfig system`, admin password profiles, syslog destinations.

---

## 4. Implemented Compliance Controls (16 Project Security Controls)

Controls are informed by CIS Benchmarks, NIST SP 800-53 Rev. 5, and PCI-DSS v4.0:

| Control ID | Title | Reference Standard | Severity | Penalty |
|---|---|---|---|---|
| **PSC-1.1** | SSH Enabled and Version 2 Enforced | CIS Cisco 15.x Sec 1.2.2 / NIST SC-13, AC-17 | HIGH | 15 pts |
| **PSC-1.2** | Telnet Plaintext Service Disabled | CIS Cisco 15.x Sec 1.2.1 / NIST AC-17, CM-7 | HIGH | 15 pts |
| **PSC-1.3** | Plaintext HTTP Web Admin Disabled | CIS Cisco 15.x Sec 1.3.1 / NIST SC-8, CM-7 | MEDIUM | 7 pts |
| **PSC-1.4** | Global Password Encryption Enabled | CIS Cisco 15.x Sec 1.1.1 / NIST IA-5 | MEDIUM | 7 pts |
| **PSC-1.5** | Strong Password Algorithms Enforced (No Type 7) | CIS Cisco 15.x Sec 1.1.2 / NIST IA-5 | HIGH | 15 pts |
| **PSC-1.6** | Minimum Password Length >= 14 Characters | CIS Cisco 15.x Sec 1.1.3 / NIST IA-5 | MEDIUM | 7 pts |
| **PSC-1.7** | Inactivity Session Timeout Configured (<= 15 min) | CIS Cisco 15.x Sec 2.1.1 / NIST SC-10 | LOW | 2 pts |
| **PSC-1.8** | Authorized Legal Warning Banner Present | CIS Cisco 15.x Sec 1.4.1 / NIST AC-8 | LOW | 2 pts |
| **PSC-2.1** | Centralized AAA (TACACS+/RADIUS) Active | CIS Cisco 15.x Sec 1.1.4 / NIST IA-2 | MEDIUM | 7 pts |
| **PSC-2.2** | Logging to Remote Syslog/SIEM Configured | CIS Cisco 15.x Sec 3.1.1 / NIST AU-2, AU-6 | HIGH | 15 pts |
| **PSC-2.3** | NTP Time Synchronization with Auth Active | CIS Cisco 15.x Sec 2.2.1 / NIST AU-8 | MEDIUM | 7 pts |
| **PSC-2.4** | Default SNMP Community Strings Removed | CIS Cisco 15.x Sec 4.1.1 / NIST CM-6, IA-5 | HIGH | 15 pts |
| **PSC-2.5** | SNMPv3 Encrypted Management Enforced | CIS Cisco 15.x Sec 4.1.2 / NIST SC-13 | MEDIUM | 7 pts |
| **PSC-3.1** | Insecure Legacy Services Disabled (finger, bootp) | CIS Cisco 15.x Sec 1.5.1 / NIST CM-7 | MEDIUM | 7 pts |
| **PSC-4.1** | No Wildcard Any-Any Firewall Permit Rules | PCI-DSS v4.0 Req 1.3 / NIST SC-7 | CRITICAL | 25 pts |
| **PSC-4.2** | Default Deny Stance Enforced | CIS Firewall v1.0 / NIST SC-7 | HIGH | 15 pts |

---

## 5. Machine Learning Design & Evaluation Results

- **Dataset**: 1,200 configuration instances across Cisco, Fortinet, and Palo Alto vendors (400 per vendor).
- **Target Distribution**: `LOW`: 380, `MEDIUM`: 308, `HIGH`: 157, `CRITICAL`: 355.
- **Feature Space**: 29 standardized dimensions strictly derived from observable configuration settings (see [`docs/FEATURES.md`](docs/FEATURES.md)).
- **Leakage Prevention**: Post-compliance summary counts (`critical_violations_count`, `high_violations_count`, `compliance_pass_ratio`) were permanently retired from the feature vector to eliminate label leakage and risk double-counting.
- **Candidate Benchmark Results (Evaluated on Synthetic Test Split)**:
  - **Random Forest (Selected)**: **96.11% Test Acc** | **95.18% Macro F1** | **0 Critical False Negatives**
  - Gradient Boosting: 95.00% Test Acc | 93.55% Macro F1
  - Logistic Regression: 95.00% Test Acc | 93.04% Macro F1
  - Decision Tree: 92.78% Test Acc | 90.39% Macro F1
- **Cross-Vendor Generalization (Exp E)**: Trained on Cisco + Fortinet (800 samples) and evaluated on Palo Alto (400 samples): **75.75% Test Acc**, **0 false negatives into LOW**.
- **Top Predictive Features**: `min_password_length` (12.7%), `unrestricted_rules_count` (12.3%), `exec_timeout_minutes` (11.3%), `firewall_rules_total` (8.1%), `snmp_default_community_used` (6.9%).
- *(Full benchmark metrics documented in [`docs/MODEL_EVALUATION.md`](docs/MODEL_EVALUATION.md))*

---

## 6. Local Quickstart

### Prerequisites
- Python 3.12 (or 3.10+)
- Node.js 18+ (tested on Node v24)
- Git

### Windows PowerShell Instructions

```powershell
# 1. Clone and navigate to project root
cd c:\Users\De\AIML_PRO

# 2. Create and activate Python virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# 3. Install pinned backend dependencies
pip install -r backend\requirements.txt

# 4. (Optional) Regenerate dataset and train models
# Pre-trained models under ml/models/ are already included
python ml\preprocessing\generate_dataset.py
python ml\training\train.py

# 5. Run the complete test suite (64 tests)
python -m pytest backend\tests -v

# 6. Start the Backend API
$env:PYTHONPATH = (Get-Location).Path
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload

# 7. In a new PowerShell terminal, start the Frontend:
cd frontend
npm install
npm run dev
```

Open **`http://localhost:5173`** for the dashboard or **`http://127.0.0.1:8000/docs`** for interactive Swagger API docs!

### Linux / macOS Instructions

```bash
# 1. Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 2. Install dependencies
pip install -r backend/requirements.txt

# 3. Run tests
python -m pytest backend/tests -v

# 4. Start backend
export PYTHONPATH=$(pwd)
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload

# 5. Start frontend
cd frontend && npm install && npm run dev
```

---

## 7. Docker Quickstart

```bash
docker-compose up --build
```
- Dashboard UI: `http://localhost:5173`
- Backend API Docs: `http://localhost:8000/docs`
- PostgreSQL: `localhost:5432`

---

## 8. Sample Demonstration Configurations

Included in `sample_data/`:
- `sample_data/cisco/cisco_hardened_core.cfg`: High-compliance Cisco router.
- `sample_data/cisco/cisco_vulnerable_perimeter.cfg`: Critical-risk Cisco node.
- `sample_data/fortinet/fortinet_hardened_edge.conf`: Secure FortiOS edge firewall.
- `sample_data/fortinet/fortinet_permissive_dmz.conf`: Permissive Fortinet firewall.
- `sample_data/palo_alto/palo_alto_secure_gw.txt`: Secure PAN-OS gateway.
- `sample_data/palo_alto/palo_alto_misconfigured.txt`: Misconfigured PAN-OS firewall.

*(The web interface also includes 1-click sample loaders on the Upload screen).*

---

## 9. Important Limitations & Disclaimers

1. **Synthetic ML Evaluation**: ML risk models are trained and evaluated on synthetic configuration instances generated via combinatorial variation. High accuracy (96.11%) reflects mathematical alignment with expert scoring rules; it **does NOT constitute a proven guarantee of real-world breach prediction or zero-day detection**.
2. **Generation-Only Remediation**: Remediation CLI scripts (`.cfg`, `.conf`, `.set`) are generated strictly for operator review. The auditor **never connects to live network devices or executes commands directly**.
3. **Static Analysis**: The system evaluates static configuration files and does not query live runtime state (routing tables, dynamic ARP/CAM tables, or firmware vulnerabilities).

---

## 10. Documentation Index

- [`docs/FINAL_COMPLETION_AUDIT.md`](docs/FINAL_COMPLETION_AUDIT.md): Final completion audit & baseline findings.
- [`docs/FINAL_ACCEPTANCE_REPORT.md`](docs/FINAL_ACCEPTANCE_REPORT.md): Final acceptance verification report.
- [`docs/REQUIREMENTS.md`](docs/REQUIREMENTS.md): Requirements and user stories.
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md): System architecture and data pipeline.
- [`docs/DATASET_RESEARCH.md`](docs/DATASET_RESEARCH.md): Research of configuration corpora and hybrid strategy.
- [`docs/DATA_PREPROCESSING.md`](docs/DATA_PREPROCESSING.md): Preprocessing, 29-feature pipeline, and dataset characteristics.
- [`docs/FEATURES.md`](docs/FEATURES.md): 29-feature security dictionary and retired features.
- [`docs/ML_DESIGN.md`](docs/ML_DESIGN.md): Machine learning design, candidates, and benchmarks.
- [`docs/MODEL_EVALUATION.md`](docs/MODEL_EVALUATION.md): Genuine measured model evaluation results.
- [`docs/ML_LEAKAGE_AUDIT.md`](docs/ML_LEAKAGE_AUDIT.md): Detailed leakage audit and controlled experiments A–E.
- [`docs/COMPLIANCE_ENGINE.md`](docs/COMPLIANCE_ENGINE.md): Deterministic compliance engine and control mappings.
- [`docs/REMEDIATION_ENGINE.md`](docs/REMEDIATION_ENGINE.md): Remediation engine architecture and safety levels.
- [`docs/API.md`](docs/API.md): Complete REST API documentation.
- [`docs/DATABASE.md`](docs/DATABASE.md): Relational database ERD and schema.
- [`docs/TESTING.md`](docs/TESTING.md): Testing methodology and 64-test matrix.
- [`docs/SECURITY.md`](docs/SECURITY.md): Threat modeling and application security safeguards.
- [`docs/LIMITATIONS.md`](docs/LIMITATIONS.md): Documented boundaries and future roadmap.
- [`docs/IMPLEMENTATION_STATUS.md`](docs/IMPLEMENTATION_STATUS.md): Component implementation checklist.

---

## 11. License

Released under the [MIT License](LICENSE).
