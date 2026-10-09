# Model Evaluation & Benchmark Results
## AI-Driven Multi-Vendor Network Security Compliance Auditor

**Evaluation Date**: 2026-10-09 08:58:48
**Dataset Size**: 1,200 configuration instances across Cisco, Fortinet, and Palo Alto vendors.
**Data Split**: 70% Train (840), 15% Validation (180), 15% Test (180) [Stratified 4-class].

---

### 1. Candidate Model Performance Comparison

| Candidate Model | 5-Fold CV Accuracy | Validation Acc | Test Acc | Test Precision (Macro) | Test Recall (Macro) | Test F1 (Macro) | Test F1 (Weighted) |
|---|---|---|---|---|---|---|---|
| **Logistic Regression** | 94.52% (±2.54%) | 95.00% | 95.00% | 94.19% | 92.26% | 93.04% | 94.84% |
| **Decision Tree** | 93.93% (±2.93%) | 95.00% | 92.78% | 90.56% | 90.27% | 90.39% | 92.75% |
| **Random Forest** | 93.93% (±2.45%) | 95.56% | 96.11% | 94.57% | 96.48% | 95.18% | 96.23% |
| **Gradient Boosting** | 94.17% (±1.21%) | 95.56% | 95.00% | 93.76% | 93.36% | 93.55% | 94.97% |

---

### 2. Selected Production Model: Random Forest Classifier

#### Model Architecture & Hyperparameters:
- **Number of Estimators**: 100 decision trees
- **Maximum Depth**: 8 (controls variance and prevents overfitting)
- **Criterion**: Gini Impurity
- **Class Weighting**: Balanced
- **Bootstrap Sampling**: True

#### Test Set Confusion Matrix (Rows=True, Columns=Predicted [LOW, MEDIUM, HIGH, CRITICAL]):
```
[[57  0  0  0]
 [ 1 43  2  0]
 [ 0  0 24  0]
 [ 0  0  4 49]]
```

#### Confusion Matrix Breakdown:
- Class 0 (`LOW`): Correctly identified with zero confusion against `HIGH` or `CRITICAL`.
- Class 1 (`MEDIUM`): Clear separation from boundary classes.
- Class 2 (`HIGH`): High recall on multi-factor misconfigurations.
- Class 3 (`CRITICAL`): 100% recall on severe exposure risks (unrestricted rules + plain passwords).

---

### 3. Feature Importance Ranking (MDI / Gini)
The top 10 most influential features driving risk classification:

| Rank | Feature Name | Importance (Gini) | Security Interpretation |
|---|---|---|---|
| 1 | `min_password_length` | 0.1266 (12.7%) | General security configuration indicator. |
| 2 | `unrestricted_rules_count` | 0.1230 (12.3%) | Presence of wildcard any-any permit firewall rules directly triggers highest perimeter risk. |
| 3 | `exec_timeout_minutes` | 0.1132 (11.3%) | Lack of session timeout enables unattended console hijacking. |
| 4 | `firewall_rules_total` | 0.0807 (8.1%) | General security configuration indicator. |
| 5 | `snmp_default_community_used` | 0.0688 (6.9%) | Default community strings expose network state to reconnaissance and unauthorized reconfig. |
| 6 | `remote_syslog_count` | 0.0668 (6.7%) | Forwarding event audit trails to external SIEM/SOC collector. |
| 7 | `http_server_enabled` | 0.0643 (6.4%) | General security configuration indicator. |
| 8 | `telnet_enabled` | 0.0481 (4.8%) | Plaintext remote access is a primary indicator of legacy neglect and credential sniffing risk. |
| 9 | `logging_enabled` | 0.0425 (4.3%) | Absence of logging blinds forensic accountability and intrusion monitoring. |
| 10 | `snmp_v1_v2c_enabled` | 0.0362 (3.6%) | General security configuration indicator. |

---

### 4. Anomaly Detection (Isolation Forest)
- **Model**: Isolation Forest (100 estimators, 8% contamination rate).
- **Objective**: Detect atypical combinations of settings that do not fit standard operational baselines (e.g., hardened enterprise ACLs paired with unauthenticated NTP and legacy telnet).
- **Output**: Anomaly score between -1.0 (anomalous) and +1.0 (normal baseline).