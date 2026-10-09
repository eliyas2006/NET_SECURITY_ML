# Machine Learning Design Document
## AI-Driven Multi-Vendor Network Security Compliance Auditor

### 1. Problem Formulation
- **Objective**: Accurately predict the holistic **Configuration Risk Classification** (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) and compute an **Anomaly Index** for heterogeneous network device configurations.
- **Task Type**: Supervised Multiclass Classification + Unsupervised Outlier/Anomaly Detection.
- **Role in Hybrid Architecture**:
  - Deterministic rules enforce exact binary regulatory compliance (e.g. `SSH version must be 2`).
  - The ML engine evaluates high-order feature interactions, exposure concentrations, posture drift, and latent risk severity across multi-vendor devices.

---

### 2. Feature Space
The feature extractor processes normalized configuration objects into a standardized 29-dimensional numerical vector strictly derived from observable configuration settings:

| # | Feature Name | Type | Value Range | Security Significance |
|---|--------------|------|-------------|-----------------------|
| 1 | `ssh_version` | Numerical | 0, 1, 2 | 0=disabled, 1=v1 (vulnerable), 2=v2 (secure) |
| 2 | `ssh_enabled` | Binary | 0, 1 | Remote encrypted administration availability |
| 3 | `telnet_enabled` | Binary | 0, 1 | Plaintext remote administration vulnerability |
| 4 | `http_server_enabled` | Binary | 0, 1 | Plaintext web administration exposure |
| 5 | `https_server_enabled`| Binary | 0, 1 | Secure web administration availability |
| 6 | `password_encryption_enabled` | Binary | 0, 1 | Prevents plaintext passwords in memory/config |
| 7 | `weak_password_algorithms_count`| Numerical | 0 - 50 | Type 7 / MD5 / legacy hashes in configuration |
| 8 | `strong_password_algorithms_count`| Numerical | 0 - 50 | Type 8/9/SHA256/bcrypt hashes in use |
| 9 | `min_password_length` | Numerical | 0 - 32 | Enforced password complexity length |
| 10 | `aaa_new_model_enabled` | Binary | 0, 1 | Centralized authentication framework active |
| 11 | `logging_enabled` | Binary | 0, 1 | Audit trail logging activity |
| 12 | `remote_syslog_count` | Numerical | 0 - 10 | Centralized SIEM/syslog destination count |
| 13 | `logging_buffered_level` | Numerical | 0 - 7 | Severity level for log retention |
| 14 | `ntp_servers_count` | Numerical | 0 - 5 | Clock synchronization for forensic timestamps |
| 15 | `ntp_authenticated` | Binary | 0, 1 | NTP spoofing protection via authentication key |
| 16 | `snmp_v1_v2c_enabled` | Binary | 0, 1 | Cleartext community string vulnerability |
| 17 | `snmp_default_community_used` | Binary | 0, 1 | Default `public`/`private` community strings |
| 18 | `snmp_v3_enabled` | Binary | 0, 1 | Encrypted authenticated SNMPv3 active |
| 19 | `insecure_services_count` | Numerical | 0 - 10 | Finger, PAD, bootp, source-route active |
| 20 | `login_banner_configured` | Binary | 0, 1 | Legal warning banner for unauthorized access |
| 21 | `exec_timeout_minutes` | Numerical | 0 - 120 | Inactivity session timeout (0 = infinite/risky) |
| 22 | `firewall_rules_total` | Numerical | 0 - 1000 | Total access control / security policies |
| 23 | `unrestricted_rules_count` | Numerical | 0 - 500 | Overly permissive `any-any-permit` rules |
| 24 | `default_deny_enforced` | Binary | 0, 1 | Implicit/explicit drop at end of policy chain |
| 25 | `exposed_management_interfaces` | Numerical | 0 - 20 | Interfaces with direct admin protocols bound |
| 26 | `vpn_crypto_modern` | Binary | 0, 1 | AES-GCM / SHA256 vs DES/3DES/MD5 |
| 27 | `vendor_cisco` | Binary | 0, 1 | One-hot encoded vendor flag |
| 28 | `vendor_fortinet` | Binary | 0, 1 | One-hot encoded vendor flag |
| 29 | `vendor_paloalto` | Binary | 0, 1 | One-hot encoded vendor flag |

#### Retired Features (Leakage & Double-Counting Elimination)
Three post-compliance summary metrics were permanently retired from the ML feature vector:
- `critical_violations_count` (Retired): Derived from post-compliance rule summary.
- `high_violations_count` (Retired): Derived from post-compliance rule summary.
- `compliance_pass_ratio` (Retired): Derived from compliance score percentage.

Retiring these metrics ensures the ML classifier evaluates raw configuration topology independently of the deterministic rule engine, preventing label leakage and eliminating risk score double-counting.

---

### 3. Model Architecture & Selection
We compare four candidate models for classification on synthetic data:
1. **Logistic Regression (Multinomial)**: Linear baseline with L2 regularization.
2. **Decision Tree Classifier**: Single tree baseline.
3. **Random Forest Classifier** (Selected Production Model): Ensemble of 100 decision trees with balanced class weighting, Gini impurity splitting, and bootstrap sampling.
4. **Gradient Boosting Classifier**: Sequential additive boosted trees.

In addition, an **Isolation Forest** model (unsupervised, 100 estimators, 8% contamination) is fitted to detect multidimensional configuration anomalies that deviate from typical enterprise postures.

| Candidate Model | 5-Fold CV Accuracy | Validation Acc | Test Acc | Test Precision (Macro) | Test Recall (Macro) | Test F1 (Macro) | Test F1 (Weighted) | CRIT→LOW FN |
|---|---|---|---|---|---|---|---|---|
| **Random Forest** | **93.93% (±2.45%)** | **95.56%** | **96.11%** | **94.57%** | **96.48%** | **95.18%** | **96.23%** | **0** |
| **Gradient Boosting** | 94.17% (±1.21%) | 95.56% | 95.00% | 93.76% | 93.36% | 93.55% | 94.97% | 0 |
| **Logistic Regression** | 94.52% (±2.54%) | 95.00% | 95.00% | 94.19% | 92.26% | 93.04% | 94.84% | 0 |
| **Decision Tree** | 93.93% (±2.93%) | 95.00% | 92.78% | 90.56% | 90.27% | 90.39% | 92.75% | 0 |

#### Why Random Forest for the Primary Classifier?
- Tabular feature space with non-linear thresholding effects (e.g. `unrestricted_rules_count > 0` combined with `snmp_default_community_used == 1`).
- Robust against feature scale disparities without requiring complex normalization inversion.
- Built-in Gini / MDI (Mean Decrease in Impurity) feature importances provide instant, mathematically transparent explainability.
- No susceptibility to catastrophic gradient divergences on small/medium enterprise baselines.

---

### 4. Training & Validation Strategy
- **Split**: 70% Train, 15% Validation, 15% Test (Stratified by risk class).
- **Class Imbalance**: Controlled using `class_weight='balanced'` in tree learning.
- **Cross-Validation**: 5-fold Stratified K-Fold on training set.
- **Metrics**: Accuracy, Balanced Accuracy, Precision (Macro/Weighted), Recall (Macro/Weighted), F1-Score (Macro/Weighted), and Confusion Matrix.

---

### 5. Explainability Strategy
Every model inference returns:
1. `predicted_class`: Target risk tier (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
2. `probabilities`: Calibrated probability distribution across all 4 classes.
3. `top_risk_factors`: The top 5 features with the highest local risk contribution, derived from feature value times global feature importance.
4. `anomaly_score`: Isolation Forest score between -1.0 (highly anomalous) and +1.0 (normal).
