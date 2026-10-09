# Compliance Engine Specification
## AI-Driven Multi-Vendor Network Security Compliance Auditor

### 1. Compliance Architecture Overview
The deterministic compliance engine assesses normalized device configurations against established cybersecurity benchmarks. Determinism ensures that every evaluation is 100% reproducible and directly auditable by external compliance authorities (GRC).

---

### 2. Implemented Security Controls & Standard Mappings
All 16 compliance rules are designated as **Project Security Controls (PSC)** informed by CIS Benchmarks, NIST SP 800-53 Rev. 5, and PCI-DSS v4.0:

| Control ID | Control Title | Baseline Standard & Citations | Severity | Penalty Weight | Target Component |
|------------|---------------|-------------------------------|----------|----------------|------------------|
| **PSC-1.1** | Ensure SSH is Enabled and Version 2 Enforced | CIS Cisco IOS 15.x v4.1.0 Sec 1.2.2 / NIST SP 800-53 SC-13, AC-17 | HIGH | 15 pts | SSH Administration |
| **PSC-1.2** | Ensure Telnet Service is Disabled | CIS Cisco IOS 15.x v4.1.0 Sec 1.2.1 / NIST SP 800-53 AC-17, CM-7 | HIGH | 15 pts | Remote Management |
| **PSC-1.3** | Ensure Plaintext HTTP Server is Disabled | CIS Cisco IOS Sec 1.2.4 / NIST SP 800-53 SC-8, AC-17 | MEDIUM | 7 pts | Web Administration |
| **PSC-1.4** | Ensure Global Password Encryption is Enabled | CIS Cisco IOS Sec 1.1.2 / NIST SP 800-53 IA-5 | MEDIUM | 7 pts | Authentication |
| **PSC-1.5** | Ensure Strong Password Hashing Algorithms Enforced | CIS Cisco IOS Sec 1.1.1 / NIST SP 800-53 IA-5 | HIGH | 15 pts | Authentication |
| **PSC-1.6** | Ensure Minimum Password Length >= 12 Characters | CIS Cisco IOS Sec 1.1.3 / NIST SP 800-53 IA-5 | MEDIUM | 7 pts | Authentication |
| **PSC-1.7** | Ensure Inactivity Session Timeout Configured (<= 15 min) | CIS Cisco IOS Sec 1.3.1 / NIST SP 800-53 AC-12 | LOW | 2 pts | Session Management |
| **PSC-1.8** | Ensure Authorized Legal Warning Banner Configured | CIS Cisco IOS Sec 1.4.1 / NIST SP 800-53 AC-8 | LOW | 2 pts | Legal Notice |
| **PSC-2.1** | Ensure Centralized AAA Authentication is Configured | CIS Cisco IOS Sec 1.1.4 / NIST SP 800-53 IA-2, AC-2 | MEDIUM | 7 pts | Identity & Access |
| **PSC-2.2** | Ensure Logging to Remote Syslog/SIEM is Active | CIS Cisco IOS Sec 2.1.1 / NIST SP 800-53 AU-2, AU-6 | HIGH | 15 pts | Audit & Forensics |
| **PSC-2.3** | Ensure NTP Time Synchronization is Configured | CIS Cisco IOS Sec 2.2.1 / NIST SP 800-53 AU-8 | MEDIUM | 7 pts | Time Synchronization |
| **PSC-2.4** | Ensure Default SNMP Community Strings are Removed | CIS Cisco IOS Sec 2.3.1 / NIST SP 800-53 CM-6, IA-5 | HIGH | 15 pts | Network Management |
| **PSC-2.5** | Ensure SNMPv3 is Configured for Encrypted Polling | CIS Cisco IOS Sec 2.3.2 / NIST SP 800-53 SC-13, AC-17 | MEDIUM | 7 pts | Network Management |
| **PSC-3.1** | Ensure Insecure Legacy Services Disabled (finger, bootp) | CIS Cisco IOS Sec 3.1 / NIST SP 800-53 CM-7 | MEDIUM | 7 pts | Service Hardening |
| **PSC-4.1** | Ensure Firewall Has No Unrestricted Any-Any Rules | PCI-DSS v4.0 Req 1.3 / NIST SP 800-53 SC-7 | CRITICAL | 25 pts | Firewall & Perimeter |
| **PSC-4.2** | Ensure Default Deny Stance is Enforced | CIS Firewall Benchmark v1.0 / NIST SP 800-53 SC-7 | HIGH | 15 pts | Firewall & Perimeter |

---

### 3. Finding Structure
Every evaluation produces a structured object:
```json
{
  "control_id": "PSC-4.1",
  "title": "Ensure Firewall Has No Unrestricted Any-to-Any Permit Rules",
  "standard": "Project Security Control [Informed by PCI-DSS v4.0 Req 1.3 / NIST SP 800-53 Rev. 5 SC-7]",
  "status": "FAIL",
  "severity": "CRITICAL",
  "evidence": "Found 1 unrestricted permit rule(s) (e.g. DANGEROUS-ACL) allowing all traffic between any source and destination.",
  "recommendation": "Eliminate wildcard permit rules. Define least-privilege source, destination, port, and application filters.",
  "remediation_cli": "no permit ip any any",
  "affected_component": "Firewall & ACL"
}
```

---

### 4. Compliance Score Formula
$$\text{Compliance Score (\%)} = \frac{\text{Passed Controls} \times 1.0 + \text{Warn Controls} \times 0.5}{\text{Total Controls}} \times 100$$
- $\ge 80\%$: Compliant baseline.
- $50\% - 79\%$: Partially compliant; remediation plan required.
- $< 50\%$: Non-compliant; immediate intervention mandatory.
