"""
Vendor Identification Service.
Detects network configuration vendor using syntax heuristics, structural keywords, and command fingerprints.
"""

import re
from backend.app.parsers.base import VendorIdentificationResult


def detect_vendor(content: str) -> VendorIdentificationResult:
    """
    Analyzes raw configuration text to identify vendor (Cisco, Fortinet, Palo Alto).
    Returns VendorIdentificationResult with vendor, confidence score, confidence level, and rationale.
    """
    if not content or not content.strip():
        return VendorIdentificationResult(
            vendor="Unknown",
            confidence=0.0,
            confidence_level="Low",
            reason="Configuration content is empty.",
            suggested_device_type="Unknown"
        )

    lines = [line.strip() for line in content.splitlines() if line.strip()]

    cisco_score = 0
    fortinet_score = 0
    palo_alto_score = 0

    cisco_signals = []
    fortinet_signals = []
    palo_signals = []

    # 1. Fortinet FortiOS signatures
    if re.search(r'#config-version=\s*FG', content, re.IGNORECASE):
        fortinet_score += 50
        fortinet_signals.append("FortiOS version header (#config-version=FG)")
    if "config firewall policy" in content:
        fortinet_score += 35
        fortinet_signals.append("FortiOS 'config firewall policy' stanza")
    if "config system interface" in content:
        fortinet_score += 25
        fortinet_signals.append("FortiOS 'config system interface' block")
    if "config system global" in content:
        fortinet_score += 20
        fortinet_signals.append("FortiOS 'config system global' block")
    if re.search(r'\b(edit\s+\d+|next|end)\b', content):
        fortinet_score += 20
        fortinet_signals.append("Fortinet hierarchical block delimiters ('edit', 'next', 'end')")
    if "set allowaccess" in content:
        fortinet_score += 15
        fortinet_signals.append("Fortinet 'set allowaccess' management directive")

    # 2. Palo Alto PAN-OS signatures
    if re.search(r'set\s+rulebase\s+security\s+rules', content, re.IGNORECASE):
        palo_alto_score += 45
        palo_signals.append("PAN-OS 'set rulebase security rules' stanza")
    if re.search(r'set\s+deviceconfig\s+system', content, re.IGNORECASE):
        palo_alto_score += 35
        palo_signals.append("PAN-OS 'set deviceconfig system' stanza")
    if re.search(r'set\s+network\s+interface', content, re.IGNORECASE):
        palo_alto_score += 25
        palo_signals.append("PAN-OS 'set network interface' hierarchy")
    if re.search(r'set\s+zone\s+', content, re.IGNORECASE):
        palo_alto_score += 20
        palo_signals.append("PAN-OS security zone definition")
    if "<config version=" in content or "<devices>" in content:
        palo_alto_score += 40
        palo_signals.append("PAN-OS XML configuration structure")

    # 3. Cisco IOS / IOS-XE / ASA signatures
    if re.search(r'^\s*version\s+\d+\.\d+', content, re.MULTILINE):
        cisco_score += 30
        cisco_signals.append("Cisco IOS 'version X.X' declaration")
    if re.search(r'^\s*service\s+password-encryption', content, re.MULTILINE):
        cisco_score += 25
        cisco_signals.append("Cisco 'service password-encryption' directive")
    if re.search(r'^\s*enable\s+(secret|password)\s+', content, re.MULTILINE):
        cisco_score += 25
        cisco_signals.append("Cisco 'enable secret/password' directive")
    if re.search(r'^\s*line\s+(vty|con|aux)\s+\d+', content, re.MULTILINE):
        cisco_score += 25
        cisco_signals.append("Cisco terminal line stanza ('line vty/con')")
    if re.search(r'^\s*interface\s+(GigabitEthernet|FastEthernet|TenGigabitEthernet|Vlan|Loopback|Serial|Ethernet)', content, re.MULTILINE | re.IGNORECASE):
        cisco_score += 25
        cisco_signals.append("Cisco standard interface naming convention")
    if re.search(r'^\s*ip\s+access-list\s+', content, re.MULTILINE):
        cisco_score += 25
        cisco_signals.append("Cisco 'ip access-list' stanza")
    if re.search(r'^\s*!\s*Last\s+configuration\s+change', content, re.MULTILINE):
        cisco_score += 20
        cisco_signals.append("Cisco IOS NVRAM timestamp comment")
    if re.search(r'^\s*ip\s+ssh\s+version', content, re.MULTILINE):
        cisco_score += 20
        cisco_signals.append("Cisco 'ip ssh version' command")
    if re.search(r'^\s*snmp-server\s+', content, re.MULTILINE):
        cisco_score += 15
        cisco_signals.append("Cisco 'snmp-server' directive")

    scores = [
        ("Cisco", cisco_score, cisco_signals, "Router/Switch"),
        ("Fortinet", fortinet_score, fortinet_signals, "Next-Gen Firewall"),
        ("Palo Alto", palo_alto_score, palo_signals, "Next-Gen Firewall"),
    ]

    scores.sort(key=lambda x: x[1], reverse=True)
    top_vendor, top_score, signals, dev_type = scores[0]

    if top_score >= 35:
        confidence = min(0.99, 0.65 + (top_score / 200.0))
        level = "High"
        reason = f"Detected characteristic {top_vendor} syntax: {'; '.join(signals[:3])}."
    elif top_score >= 20:
        confidence = 0.55 + (top_score / 150.0)
        level = "Medium"
        reason = f"Possible {top_vendor} configuration: {'; '.join(signals[:2])}."
    else:
        return VendorIdentificationResult(
            vendor="Unknown",
            confidence=0.20,
            confidence_level="Low",
            reason="No decisive vendor-specific command signatures recognized. Please select vendor manually.",
            suggested_device_type="Unknown"
        )

    return VendorIdentificationResult(
        vendor=top_vendor,
        confidence=round(confidence, 2),
        confidence_level=level,
        reason=reason,
        detected_syntax="; ".join(signals),
        suggested_device_type=dev_type
    )
