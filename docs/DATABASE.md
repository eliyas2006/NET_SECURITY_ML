# Database Design & Schema Documentation
## AI-Driven Multi-Vendor Network Security Compliance Auditor

### 1. Database Overview
The application uses SQLAlchemy ORM to manage database persistence, providing portability between **SQLite** (default zero-configuration local storage) and **PostgreSQL** (production deployment).

---

### 2. Entity Relationship Diagram (ERD)

```
       ┌────────────────────────┐
       │         audits         │
       ├────────────────────────┤
       │ id (PK, VARCHAR)       │◄────────┐
       │ filename               │         │
       │ vendor                 │         │
       │ vendor_confidence      │         │
       │ device_type            │         │
       │ hostname               │         │
       │ raw_lines_count        │         │ 1:N
       │ compliance_score       │         │ (CASCADE DELETE)
       │ final_risk_level       │         │
       │ composite_risk_score   │         │
       │ rule_risk_score        │         │
       │ ml_risk_score          │         │
       │ ml_predicted_class     │         │
       │ ml_confidence          │         │
       │ anomaly_score          │         │
       │ is_anomaly             │         │
       │ raw_config_preview     │         │
       │ normalized_json        │         │
       │ risk_assessment_json   │         │
       │ ml_result_json         │         │
       │ created_at             │         │
       └────────────────────────┘         │
                                          │
                               ┌──────────┴─────────────┐
                               │        findings        │
                               ├────────────────────────┤
                               │ id (PK, INT AUTOINC)   │
                               │ audit_id (FK, VARCHAR) │
                               │ control_id             │
                               │ title                  │
                               │ standard               │
                               │ status                 │
                               │ severity               │
                               │ evidence               │
                               │ recommendation         │
                               │ remediation_cli        │
                               │ affected_component     │
                               └────────────────────────┘
```

---

### 3. Data Privacy & Minimization
- **No Sensitive Credential Storage**: Raw configuration passwords and hashed secrets are filtered during preview creation; only non-sensitive stanzas are saved in `raw_config_preview`.
- **JSON Field Serialization**: Structured snapshots of `NormalizedConfiguration`, `RiskAssessment`, and `MLInferenceResult` are preserved as JSON text fields to enable audit playback without schema migration friction.
