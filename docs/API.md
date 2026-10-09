# REST API Documentation & Endpoints
## AI-Driven Multi-Vendor Network Security Compliance Auditor

Base URL: `http://localhost:8000/api`
Interactive OpenAPI Docs: `http://localhost:8000/docs`
Alternative ReDoc: `http://localhost:8000/redoc`

---

### 1. Audit Operations

#### `POST /api/audits/upload`
Uploads a configuration file (.cfg, .conf, .txt) and triggers complete analysis.
- **Request**: Multipart Form Data
  - `file`: Configuration file (max 10MB)
  - `vendor_override`: (Optional) "Cisco", "Fortinet", "Palo Alto", or "auto"
- **Response**: `AuditDetailResponse` (HTTP 200)

#### `POST /api/audits/analyze`
Submits raw text configuration for analysis.
- **Request Body**:
  ```json
  {
    "content": "version 15.6\\nhostname core-rtr\\n...",
    "filename": "custom_config.cfg",
    "vendor_override": null
  }
  ```
- **Response**: `AuditDetailResponse` (HTTP 200)

#### `POST /api/audits/detect-vendor`
Pre-checks a configuration snippet and returns vendor and confidence score.
- **Request Body**: `{"content": "config firewall policy..."}`
- **Response**:
  ```json
  {
    "vendor": "Fortinet",
    "confidence": 0.99,
    "confidence_level": "High",
    "reason": "Detected FortiOS 'config firewall policy' stanza.",
    "suggested_device_type": "Next-Gen Firewall"
  }
  ```

#### `GET /api/audits`
Retrieves a paginated list of historical audits.
- **Query Params**: `limit` (int, default 50, max 200)
- **Response**: `List[AuditListItem]`

#### `GET /api/audits/{audit_id}`
Retrieves full details, 16 findings, risk assessment, and ML insights for an audit.
- **Response**: `AuditDetailResponse`

#### `GET /api/audits/{audit_id}/report`
Generates a standalone, printable HTML executive audit report.
- **Response**: HTML Page (`text/html`)

#### `GET /api/audits/{audit_id}/remediation`
Retrieves structured, vendor-specific remediation plan for all non-compliant controls.
- **Response**: `RemediationPlan` (JSON) containing per-control actions, safety classifications (`SAFE_AUTOMATIC`, `REVIEW_REQUIRED`, `MANUAL_ONLY`), placeholders, and CLI commands.

#### `GET /api/audits/{audit_id}/remediation/download`
Downloads complete reviewable vendor CLI configuration script (`.cfg` for Cisco, `.conf` for Fortinet, `.set` for Palo Alto) with standard safety disclaimers, verification commands, and rollback procedures.
- **Response**: Plain text attachment (`text/plain; charset=utf-8`) with header `Content-Disposition: attachment; filename="remediation_<vendor>_<audit_id>.<ext>"`

#### `DELETE /api/audits/{audit_id}`
Deletes an audit record and cascades deletion to findings.
- **Response**: `{"status": "success", "message": "Audit AUD-XXXX deleted."}`

---

### 2. Dashboard Operations

#### `GET /api/dashboard/summary`
Returns high-level posture KPIs, compliant device count, risk distribution, and vendor share.
- **Response**: `DashboardSummary`

---

### 3. Health & Status

#### `GET /api/health`
- **Response**:
  ```json
  {
    "status": "healthy",
    "service": "AI Network Compliance Auditor",
    "supported_vendors": ["Cisco", "Fortinet", "Palo Alto"],
    "version": "1.0.0"
  }
  ```
