# Application Security & Safe Development Practices
## AI-Driven Multi-Vendor Network Security Compliance Auditor

### 1. Threat Modeling & Safeguards

#### 1.1 Ingestion Security & Safe File Handling
- **File Size Restrictions**: Uploaded configuration files are constrained to a strict maximum limit of 10MB to protect against Denial of Service (DoS) memory exhaustion.
- **Path Traversal Protection**: Uploaded filenames are purely recorded as descriptive metadata; files are read directly from memory streams and never saved to arbitrary disk locations with user-controlled paths.
- **Character Encoding Resilience**: Gracefully handles UTF-8 and Latin-1 encoded network device configuration files without crashing.

#### 1.2 Sanitization & Credential Protection
- **No In-Memory Secret Storage**: Passwords, enable secrets, and private keys parsed from configuration files are categorized by hash type (Type 7, Type 8/9, SHA256) and never logged in plain text or rendered in audit summaries.
- **Automated Regex Redaction**: Configuration previews stored in the database and rendered in audit summaries pass through `sanitize_config_text()`, which actively strips Cisco Type 7/5/8/9 hashes, plaintext password directives, SNMP community strings, and IPsec preshared keys with `[REDACTED_*]` placeholders.

#### 1.3 Database Security
- **Parameterization**: All queries use SQLAlchemy ORM parameter binding, completely eliminating SQL injection vectors.
- **Cascade Control**: Audit deletion cascades cleanly to all associated findings via `ondelete="CASCADE"` and SQLite `PRAGMA foreign_keys=ON`, preventing orphaned audit records.

#### 1.4 API Hardening & Network Security
- **Strict Input Validation**: All payloads are validated using Pydantic v2 schemas; both file uploads and raw text analysis enforce a 10MB maximum payload limit.
- **Explicit CORS Configuration**: Allowed origins are explicitly parsed from the `CORS_ORIGINS` environment variable. To comply with W3C CORS specifications, credentialed requests are strictly disallowed whenever a wildcard origin (`*`) is configured.
- **Structured Error Handling**: Exception messages return structured error JSON without leaking internal server stack traces or server file system paths.

#### 1.5 Generation-Only Remediation Architecture
- **Zero Live Execution**: The system generates remediation CLI scripts for offline operator inspection only. It contains no Netmiko/Paramiko SSH connection engines and never connects to or modifies live network devices.
- **Operator Review Warnings**: All generated `.cfg`, `.conf`, and `.set` scripts embed mandatory warnings requiring staging topology validation and manual population of all `<PLACEHOLDER>` parameters prior to change windows.

#### 1.6 Environment Isolation
- All credentials and sensitive connection parameters are loaded from environment variables (`.env`).
- `.env.example` is provided; `.env` and SQLite database files (`*.db`) are ignored in `.gitignore`.
