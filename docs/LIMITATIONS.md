# System Limitations & Operational Boundaries
## AI-Driven Multi-Vendor Network Security Compliance Auditor

### 1. Documented Limitations & Disclaimers

#### 1.1 Synthetic ML Evaluation & Real-World Breach Prediction Non-Claim
- **Synthetic Ground Truth**: The Machine Learning risk classification model and Isolation Forest anomaly detector are trained and evaluated on synthetic configuration instances generated via combinatorial parameter variation.
- **No Breach Prediction Claim**: High evaluation accuracy (96.11% on holdout test data) demonstrates statistical alignment with expert-defined multi-factor security scoring. It **does NOT thereby prove or guarantee prediction of real-world security breaches, zero-day compromises, or active adversary campaigns**.
- **Not a Penetration Test**: Machine learning risk inference operates on static configuration posture and does not substitute for dynamic penetration testing, red teaming, or vulnerability scanning of active services.

#### 1.2 Vendor and Syntax Scope
- The current implementation supports **Cisco IOS/IOS-XE (15.x/16.x/17.x)**, **Fortinet FortiOS (7.x)**, and **Palo Alto PAN-OS (10.x/11.x)**.
- Bracketed hierarchical syntaxes (e.g., Juniper JunOS) or Linux firewall tools (`iptables`, `nftables`) will trigger an unknown vendor error unless an explicit vendor override is supplied.

#### 1.3 Static vs Dynamic Device State
- The auditor inspects **offline static configuration text** (`show running-config` / `backup.conf`).
- It does not query runtime device operational state (such as dynamic routing tables, BGP peering flaps, live interface drop counters, ARP/CAM tables, or real-time CPU/memory utilization).

#### 1.4 Generation-Only Remediation (No Live Execution)
- Remediation outputs are strictly text-based configuration scripts (`.cfg`, `.conf`, `.set`).
- The application **never initiates SSH/Telnet connections, never pushes configurations, and never executes commands on live networking hardware**.
- Operators must review all generated CLI snippets in a staging sandbox and replace all `<PLACEHOLDER>` parameters before deployment.

#### 1.5 No Production Certification Without Engineering Review
- Successful execution of automated unit/integration tests validates software correctness against the test specification.
- It does not constitute official vendor certification (e.g., Cisco, Fortinet, or Palo Alto formal hardware validation) or production clearance without operator review.

---

### 2. Future Scope & Roadmap
1. **Additional Vendor Parsers**: Support for Juniper JunOS bracketed syntax, Arista EOS, and Linux `nftables`.
2. **Automated Staging Sandbox Deployment**: Optional SSH/Netmiko integration allowing engineers to push generated remediation CLI snippets to isolated lab devices.
3. **Continuous Drift Monitoring**: GitOps webhooks and syslog daemon integration to automatically trigger audits upon configuration commit.
4. **CVE Vulnerability Correlation**: Cross-referencing parsed device OS version strings with the NIST National Vulnerability Database (NVD) for real-time CVE correlation.

