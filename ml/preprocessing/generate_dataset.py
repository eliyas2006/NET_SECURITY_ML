"""
Synthetic Network Security Configuration Dataset Generator.
Redesigned for Scientific ML Validity:
- Generates diverse, realistic multi-vendor configurations (Cisco IOS, Fortinet FortiOS, Palo Alto PAN-OS).
- Combinatorial variation across security parameters (SSH, Telnet, AAA, Passwords, Logging, NTP, SNMP, ACLs).
- Ground truth risk class and score computed via a defensible, multi-factor cybersecurity impact model.
- Eliminates label leakage by omitting post-compliance summary metrics from the feature vector.
- Includes borderline cases and non-linear control interactions to create a realistic ML learning problem.
"""

import os
import sys
import random
from typing import Dict, Any, Tuple, List
import pandas as pd
import numpy as np

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from backend.app.parsers.cisco import CiscoParser
from backend.app.parsers.fortinet import FortinetParser
from backend.app.parsers.palo_alto import PaloAltoParser
from backend.app.compliance.engine import ComplianceEngine
from backend.app.features.extractor import extract_features, FEATURE_NAMES
from backend.app.schemas.normalized import NormalizedConfiguration


def compute_ground_truth_risk(cfg: NormalizedConfiguration, seed_idx: int) -> Tuple[float, str]:
    """
    Defensible Cybersecurity Risk Ground Truth Model.
    Evaluates risk based on vulnerability severity, threat exposure, compounding control interactions,
    and defense-in-depth mitigations.
    """
    risk = 0.0

    # 1. Critical Perimeter & Access Control Vulnerabilities
    unres_rules = sum(1 for r in cfg.firewall_rules if r.is_unrestricted)
    if unres_rules > 0:
        risk += 22.0 + (unres_rules - 1) * 5.0

    if cfg.snmp.default_community_used:
        risk += 18.0

    exposed_mgmt = sum(1 for iface in cfg.interfaces if iface.is_management and ("telnet" in iface.management_protocols or "http" in iface.management_protocols))
    if exposed_mgmt > 0:
        risk += 12.0

    # 2. Authentication & Credential Storage Posture
    if cfg.telnet_enabled:
        risk += 14.0
    if not cfg.auth.aaa_enabled:
        risk += 6.0
    if not cfg.passwords.service_encryption:
        risk += 5.0
    if cfg.passwords.weak_algorithm_count > 0:
        risk += 8.0 + min(6.0, cfg.passwords.weak_algorithm_count * 2.0)
    if cfg.passwords.min_length < 8:
        risk += 7.0
    elif cfg.passwords.min_length < 12:
        risk += 3.0

    # 3. Transport & Administrative Management
    if not cfg.ssh.enabled:
        risk += 12.0
    elif cfg.ssh.version < 2:
        risk += 8.0
    if cfg.http_server_enabled:
        risk += 5.0

    # 4. Visibility, Auditing & Forensic Readiness
    if not cfg.logging.enabled:
        risk += 10.0
    elif len(cfg.logging.syslog_servers) == 0:
        risk += 5.0

    if len(cfg.ntp.servers) == 0:
        risk += 4.0
    elif not cfg.ntp.authenticated:
        risk += 2.0

    # 5. Network Access Control Stance
    if not cfg.default_deny:
        risk += 8.0

    # 6. Legacy Services & Operational Hygiene
    if len(cfg.insecure_services) > 0:
        risk += min(6.0, 2.0 * len(cfg.insecure_services))
    if not cfg.auth.login_banner_present:
        risk += 3.0
    if cfg.auth.exec_timeout_minutes == 0:
        risk += 5.0
    elif cfg.auth.exec_timeout_minutes > 15:
        risk += 2.0

    # 7. Compounding Vulnerability Interactions (Multipliers)
    if cfg.telnet_enabled and cfg.passwords.weak_algorithm_count > 0:
        risk += 6.0  # Cleartext protocol + weak credential compounding
    if unres_rules > 0 and (not cfg.logging.enabled or len(cfg.logging.syslog_servers) == 0):
        risk += 6.0  # Permissive perimeter + zero monitoring
    if unres_rules > 0 and not cfg.default_deny:
        risk += 5.0   # Total lack of egress/ingress boundary filtering
    if cfg.snmp.default_community_used and cfg.snmp.v1_v2c_enabled:
        risk += 4.0

    # 8. Defense-in-Depth Mitigations (Reductions)
    if cfg.auth.aaa_enabled and cfg.ssh.version == 2 and cfg.passwords.min_length >= 14:
        risk -= 4.0
    if cfg.default_deny and len(cfg.logging.syslog_servers) >= 2 and unres_rules == 0:
        risk -= 4.0
    if cfg.snmp.v3_enabled and not cfg.snmp.v1_v2c_enabled:
        risk -= 3.0

    # Add realistic environmental borderline variation (+/- 2.5 points based on asset context)
    context_jitter = ((seed_idx * 17) % 11 - 5) * 0.5
    final_score = max(0.0, min(100.0, round(risk + context_jitter, 1)))

    if final_score <= 25.0:
        tier = "LOW"
    elif final_score <= 50.0:
        tier = "MEDIUM"
    elif final_score <= 75.0:
        tier = "HIGH"
    else:
        tier = "CRITICAL"

    return final_score, tier


# -------------------------------------------------------------
# CISCO IOS CONFIG GENERATOR
# -------------------------------------------------------------
def build_cisco_config_varied(target_posture: str, seed: int) -> str:
    rng = random.Random(seed)
    lines = [f"! Cisco IOS Configuration - Sample {seed} ({target_posture})"]
    lines.append(f"hostname cisco-node-{seed:04d}")
    lines.append("version 15.6")

    # Determine parameter probabilities by posture
    if target_posture == "LOW":
        ssh_ver = 2
        telnet = False
        pwd_enc = True
        sec_pwd_len = rng.choice([14, 16])
        secret_algo = rng.choice(["9", "8"])
        aaa = True
        http = False
        https = True
        logging_on = True
        syslog_cnt = rng.choice([1, 2, 3])
        ntp_cnt = rng.choice([1, 2])
        ntp_auth = True
        snmp_mode = "v3"
        banner = True
        timeout = rng.choice([5, 10, 15])
        unrestricted = False
        default_deny = True
        insecure_svcs = []
    elif target_posture == "MEDIUM":
        ssh_ver = 2
        telnet = False
        pwd_enc = rng.choice([True, False])
        sec_pwd_len = rng.choice([8, 10])
        secret_algo = rng.choice(["5", "8"])
        aaa = False
        http = rng.choice([True, False])
        https = True
        logging_on = True
        syslog_cnt = rng.choice([0, 1])
        ntp_cnt = rng.choice([1, 2])
        ntp_auth = False
        snmp_mode = rng.choice(["v3", "v2_custom"])
        banner = rng.choice([True, False])
        timeout = rng.choice([20, 30])
        unrestricted = False
        default_deny = rng.choice([True, False])
        insecure_svcs = rng.sample(["finger"], k=rng.choice([0, 1]))
    elif target_posture == "HIGH":
        ssh_ver = rng.choice([1, 2])
        telnet = rng.choice([True, False])
        pwd_enc = False
        sec_pwd_len = rng.choice([6, 8])
        secret_algo = "7"
        aaa = False
        http = True
        https = False
        logging_on = rng.choice([True, False])
        syslog_cnt = 0
        ntp_cnt = rng.choice([0, 1])
        ntp_auth = False
        snmp_mode = "v2_custom"
        banner = False
        timeout = rng.choice([0, 30])
        unrestricted = False  # Keep false so it stays in HIGH instead of CRITICAL
        default_deny = False
        insecure_svcs = rng.sample(["finger", "source-route"], k=1)
    else:  # CRITICAL
        ssh_ver = rng.choice([0, 1])
        telnet = True
        pwd_enc = False
        sec_pwd_len = rng.choice([0, 4, 6])
        secret_algo = rng.choice(["7", "0"])
        aaa = False
        http = True
        https = False
        logging_on = False
        syslog_cnt = 0
        ntp_cnt = 0
        ntp_auth = False
        snmp_mode = "v2_public"
        banner = False
        timeout = 0
        unrestricted = True
        default_deny = False
        insecure_svcs = ["finger", "bootp", "source-route"]

    # Render syntax
    if pwd_enc:
        lines.append("service password-encryption")
    else:
        lines.append("no service password-encryption")

    if sec_pwd_len > 0:
        lines.append(f"security passwords min-length {sec_pwd_len}")

    if secret_algo in ["9", "8"]:
        lines.append(f"enable secret {secret_algo} $9$shaHash{seed}")
        lines.append(f"username admin algorithm-type sha256 secret 8 $8$adminSha{seed}")
    elif secret_algo == "5":
        lines.append("enable secret 5 $1$md5hashString")
        lines.append("username admin secret 5 $1$userMd5String")
    elif secret_algo == "7":
        lines.append("enable password 7 070C285F4D06")
        lines.append("username admin password 7 070C285F4D06")
    else:
        lines.append("enable password cleartextpass")
        lines.append("username admin password cleartextpass")

    if aaa:
        lines.append("aaa new-model")
        lines.append("aaa authentication login default group tacacs+ local")

    if ssh_ver == 2:
        lines.append("ip ssh version 2")
        lines.append("ip ssh time-out 60")
    elif ssh_ver == 1:
        lines.append("ip ssh version 1")
    else:
        lines.append("no ip ssh")

    if http:
        lines.append("ip http server")
    else:
        lines.append("no ip http server")

    if https:
        lines.append("ip http secure-server")

    for svc in insecure_svcs:
        lines.append(f"service {svc}" if svc != "source-route" else "ip source-route")
    if not insecure_svcs:
        lines.append("no service finger")
        lines.append("no ip source-route")

    if logging_on:
        lvl = rng.choice(["informational", "warnings", "debugging"])
        lines.append(f"logging buffered 64000 {lvl}")
        for s in range(syslog_cnt):
            lines.append(f"logging host 10.100.1.{s+1}")
        lines.append("service timestamps log datetime msec")
    else:
        lines.append("no logging on")

    if ntp_auth:
        lines.append("ntp authenticate")
    for n in range(ntp_cnt):
        lines.append(f"ntp server 10.100.10.{n+1}")

    if snmp_mode == "v3":
        lines.append("snmp-server group SECGROUP v3 priv")
        lines.append("snmp-server user snmpadmin SECGROUP v3 auth sha StrongPass priv aes 128 StrongKey")
    elif snmp_mode == "v2_custom":
        lines.append(f"snmp-server community PrivateCorp_{seed%50} RO")
    elif snmp_mode == "v2_public":
        lines.append("snmp-server community public RW")
        lines.append("snmp-server community private RW")

    if banner:
        lines.append("banner motd ^C Authorized Personnel Only. Activities Logged. ^C")

    lines.append("interface GigabitEthernet0/0")
    lines.append(f" ip address 10.{(seed%150)+1}.1.1 255.255.255.0")

    lines.append("line con 0")
    lines.append(f" exec-timeout {timeout} 0")
    lines.append("line vty 0 4")
    if telnet:
        lines.append(" transport input telnet" if ssh_ver == 0 else " transport input all")
    else:
        lines.append(" transport input ssh")
    lines.append(f" exec-timeout {timeout} 0")

    lines.append("ip access-list extended FILTER-ACL")
    if unrestricted:
        lines.append(" permit ip any any")
    else:
        lines.append(f" permit tcp 10.0.0.0 0.255.255.255 host 10.{(seed%150)+1}.1.1 eq 22")
    if default_deny:
        lines.append(" deny ip any any log")

    return "\n".join(lines)


# -------------------------------------------------------------
# FORTINET FORTIOS CONFIG GENERATOR
# -------------------------------------------------------------
def build_fortinet_config_varied(target_posture: str, seed: int) -> str:
    rng = random.Random(seed)
    lines = [
        f"# Fortinet FortiOS Config - Sample {seed} ({target_posture})",
        f"#config-version=FG-7.2.{(seed%4)+1}:opmode=0",
        "config system global",
        f'    set hostname "fgt-node-{seed:04d}"'
    ]

    if target_posture == "LOW":
        timeout = rng.choice([5, 10, 15])
        ssh_port = 22
        https_redir = True
        banner = True
        min_len = rng.choice([14, 16])
        allow_access = "ping https ssh"
        syslog = True
        ntp_auth = True
        snmp_v3 = True
        unrestricted = False
        default_deny = True
    elif target_posture == "MEDIUM":
        timeout = rng.choice([20, 30])
        ssh_port = 22
        https_redir = False
        banner = rng.choice([True, False])
        min_len = rng.choice([8, 10])
        allow_access = "ping https ssh http"
        syslog = rng.choice([True, False])
        ntp_auth = False
        snmp_v3 = False
        unrestricted = False
        default_deny = True
    elif target_posture == "HIGH":
        timeout = rng.choice([15, 20])
        ssh_port = 22
        https_redir = False
        banner = False
        min_len = rng.choice([6, 8])
        allow_access = rng.choice(["ping https ssh telnet", "ping https ssh http"])
        syslog = False
        ntp_auth = False
        snmp_v3 = False
        unrestricted = False  # Keep false so it remains in HIGH
        default_deny = False
    else:  # CRITICAL
        timeout = 0
        ssh_port = 22
        https_redir = False
        banner = False
        min_len = rng.choice([4, 6])
        allow_access = "ping http telnet"
        syslog = False
        ntp_auth = False
        snmp_v3 = False
        unrestricted = True
        default_deny = False

    lines.append(f"    set admintimeout {timeout}")
    lines.append(f"    set admin-ssh-port {ssh_port}")
    if https_redir:
        lines.append("    set admin-https-redirect enable")
    else:
        lines.append("    set admin-https-redirect disable")
    if banner:
        lines.append("    set pre-login-banner enable")
    lines.append("end")

    # Password policy
    lines += [
        "config system password-policy",
        f"    set min-length {min_len}",
        "    set status enable",
        "end"
    ]

    # Interface
    lines += [
        "config system interface",
        '    edit "port1"',
        f'        set ip 10.{(seed%150)+1}.1.1 255.255.255.0',
        f'        set allowaccess {allow_access}',
        "    next",
        "end"
    ]

    # Syslog
    if syslog:
        lines += [
            "config log syslogd setting",
            "    set status enable",
            f'    set server "10.100.50.{(seed%10)+1}"',
            "end"
        ]

    # NTP
    lines += [
        "config system ntp",
        '    set ntpserver "time.cloudflare.com"',
        f"    set authentication {'enable' if ntp_auth else 'disable'}",
        "end"
    ]

    # SNMP
    if snmp_v3:
        lines += [
            "config system snmp user",
            '    edit "adminv3"',
            "        set security-level auth-priv",
            "    next",
            "end"
        ]
    elif target_posture in ["HIGH", "CRITICAL"]:
        lines += [
            "config system snmp community",
            "    edit 1",
            '        set name "public"',
            "    next",
            "end"
        ]
    else:
        lines += [
            "config system snmp community",
            "    edit 1",
            f'        set name "CorpNet_{seed%50}"',
            "    next",
            "end"
        ]

    # Firewall Policy
    lines.append("config firewall policy")
    if unrestricted:
        lines += [
            "    edit 1",
            '        set srcaddr "all"',
            '        set dstaddr "all"',
            '        set action accept',
            '        set service "ALL"',
            "    next"
        ]
    else:
        lines += [
            "    edit 1",
            f'        set srcaddr "10.{(seed%150)+1}.0.0/24"',
            '        set dstaddr "10.200.0.0/24"',
            '        set action accept',
            '        set service "HTTPS"',
            "    next"
        ]
    if default_deny:
        lines += [
            "    edit 2",
            '        set srcaddr "all"',
            '        set dstaddr "all"',
            '        set action deny',
            "    next"
        ]
    lines.append("end")

    return "\n".join(lines)


# -------------------------------------------------------------
# PALO ALTO PAN-OS CONFIG GENERATOR
# -------------------------------------------------------------
def build_palo_alto_config_varied(target_posture: str, seed: int) -> str:
    rng = random.Random(seed)
    lines = [
        f"# Palo Alto PAN-OS Config - Sample {seed} ({target_posture})",
        f"set deviceconfig system hostname pa-fw-{seed:04d}",
        "set deviceconfig system ip-address 10.1.1.1 netmask 255.255.255.0"
    ]

    if target_posture == "LOW":
        timeout = rng.choice([5, 10, 15])
        banner = True
        min_len = rng.choice([14, 16])
        syslog = True
        ntp = True
        telnet = False
        http = False
        snmp_v2 = False
        unrestricted = False
        default_deny = True
    elif target_posture == "MEDIUM":
        timeout = rng.choice([20, 30])
        banner = rng.choice([True, False])
        min_len = rng.choice([8, 10])
        syslog = False
        ntp = True
        telnet = False
        http = True
        snmp_v2 = False
        unrestricted = False
        default_deny = True
    elif target_posture == "HIGH":
        timeout = rng.choice([20, 30])
        banner = False
        min_len = rng.choice([6, 8])
        syslog = False
        ntp = rng.choice([True, False])
        telnet = True
        http = True
        snmp_v2 = False  # Custom or disabled so it stays in HIGH
        unrestricted = False  # Keep false so it stays in HIGH
        default_deny = False
    else:  # CRITICAL
        timeout = 0
        banner = False
        min_len = rng.choice([4, 6])
        syslog = False
        ntp = False
        telnet = True
        http = True
        snmp_v2 = True
        unrestricted = True
        default_deny = False

    lines.append(f"set deviceconfig system session idle-timeout {timeout}")
    lines.append(f"set mgt-config password-complexity min-password-length {min_len}")

    if banner:
        lines.append('set deviceconfig system login-banner "Authorized Access Only"')

    if ntp:
        lines.append("set deviceconfig system ntp-servers primary-ntp-server-address 10.0.0.1")

    if syslog:
        lines.append(f"set shared log-settings syslog Syslog-Server server 10.100.1.{(seed%10)+1}")

    if telnet:
        lines.append("set deviceconfig system service telnet")
    if http:
        lines.append("set deviceconfig system service disable-http no")

    if snmp_v2:
        if target_posture in ["HIGH", "CRITICAL"]:
            lines.append('set deviceconfig system snmp-setting version v2c community "public"')
        else:
            lines.append(f'set deviceconfig system snmp-setting version v2c community "Corp_{seed%50}"')

    # Security Rules
    if unrestricted:
        lines += [
            "set rulebase security rules ALLOW-ANY from any to any source any destination any application any service any action allow",
        ]
    else:
        lines += [
            f"set rulebase security rules WEB-FILTER from trust to untrust source 10.{(seed%150)+1}.0.0/24 destination any application web-browsing service application-default action allow"
        ]

    if default_deny:
        lines.append("set rulebase security rules DEFAULT-DENY from any to any source any destination any action deny")

    return "\n".join(lines)


# -------------------------------------------------------------
# MAIN GENERATION PIPELINE
# -------------------------------------------------------------
def generate_dataset(output_csv: str = "ml/data/dataset.csv", total_samples: int = 1200):
    os.makedirs(os.path.dirname(output_csv), exist_ok=True)
    cisco_parser = CiscoParser()
    fortinet_parser = FortinetParser()
    palo_parser = PaloAltoParser()
    engine = ComplianceEngine()

    postures = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    vendors = ["Cisco", "Fortinet", "Palo Alto"]
    samples_per_combo = total_samples // (len(postures) * len(vendors))

    records = []
    print(f"Generating {total_samples} diverse configuration samples ({samples_per_combo} per vendor-posture combo)...")

    seed_idx = 1
    for vendor in vendors:
        for posture in postures:
            for _ in range(samples_per_combo):
                if vendor == "Cisco":
                    raw_cfg = build_cisco_config_varied(posture, seed_idx)
                    parsed = cisco_parser.parse(raw_cfg)
                elif vendor == "Fortinet":
                    raw_cfg = build_fortinet_config_varied(posture, seed_idx)
                    parsed = fortinet_parser.parse(raw_cfg)
                else:
                    raw_cfg = build_palo_alto_config_varied(posture, seed_idx)
                    parsed = palo_parser.parse(raw_cfg)

                # Ground truth risk calculation (pure cybersecurity posture evaluation)
                risk_score, risk_class = compute_ground_truth_risk(parsed, seed_idx)

                # Extract 29 raw configuration features (no compliance summary leakage)
                features = extract_features(parsed)

                row = {
                    "sample_id": f"CFG-{seed_idx:05d}",
                    "vendor": vendor,
                    "target_risk_class": risk_class,
                    "target_risk_score": risk_score,
                    **features
                }
                records.append(row)
                seed_idx += 1

    df = pd.DataFrame(records)
    df.to_csv(output_csv, index=False)

    print(f"Dataset successfully generated and saved to {output_csv}")
    print(f"Total Rows: {len(df)}, ML Features: {len(FEATURE_NAMES)}")
    print(f"Unique Feature Vectors: {len(df[FEATURE_NAMES].drop_duplicates())}")
    print("\nClass Distribution:\n", df["target_risk_class"].value_counts())
    print("\nVendor Distribution:\n", df["vendor"].value_counts())

    return df


if __name__ == "__main__":
    generate_dataset()
