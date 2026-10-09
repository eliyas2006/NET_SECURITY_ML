# Data Preprocessing & Pipeline Documentation
## AI-Driven Multi-Vendor Network Security Compliance Auditor

### 1. Data Pipeline Overview
The data pipeline transforms unstructured network device configuration files into model-ready numerical feature matrices:

```
Raw Configuration (.cfg, .conf, .txt)
           │
           ▼
Vendor Identification (Fingerprinting & confidence evaluation)
           │
           ▼
Vendor-Specific Syntax Parser (AST / Section stanzas extraction)
           │
           ▼
Vendor-Neutral Normalizer (Pydantic Common Security Schema)
           ├──► Deterministic Rule Evaluation (16 Project Security Controls)
           │
           ▼
Security Feature Extractor (29 standardized dimensions, no post-rule leakage)
           │
           ▼
Label Preparation & Stratified Train/Val/Test Splitting
           │
           ▼
Model Training & Artifact Serialization (Random Forest + Isolation Forest)
```

---

### 2. Dataset Characteristics
- **Total Samples**: 1,200 configuration instances.
- **Vendors**:
  - Cisco Systems: 400 instances (33.3%)
  - Fortinet FortiOS: 400 instances (33.3%)
  - Palo Alto PAN-OS: 400 instances (33.3%)
- **Target Classes (Defensible Multi-Factor Impact Model)**:
  - `LOW`: 380 instances (31.7%)
  - `MEDIUM`: 308 instances (25.7%)
  - `HIGH`: 157 instances (13.1%)
  - `CRITICAL`: 355 instances (29.6%)
- **Dimensions**: 29 numerical/binary features + 1 sample identifier + 1 vendor name + 1 target class + 1 continuous score (33 total CSV columns).
- **Unique Feature Vectors**: 290 unique configuration vectors introducing realistic combinatorial variance.

---

### 3. Preprocessing Steps
1. **Handling Categorical Variables**:
   - Vendor identity is converted to one-hot binary flags: `vendor_cisco`, `vendor_fortinet`, `vendor_paloalto`.
   - All other categorical states (e.g. actions, algorithms, boolean toggles) are pre-mapped into quantitative presence indicators during feature extraction.
2. **Missing Values**:
   - The normalization schema enforces safe defaults (e.g. `timeout=0`, `remote_syslog_count=0`, `default_deny=False`).
   - Hence, there are zero missing (`NaN`) values in the feature space.
3. **Data Splitting**:
   - Stratified 70% Train (840 samples), 15% Validation (180 samples), 15% Test (180 samples).
   - Stratified splitting preserves class balance across training, validation, and test sets.
4. **Reproducibility**:
   - Fixed random seeds across dataset generation (`ml/preprocessing/generate_dataset.py`) and training (`ml/training/train.py`).
