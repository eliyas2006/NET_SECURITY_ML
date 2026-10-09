"""
Risk Aggregation Engine.
Combines deterministic compliance findings, severity weights, and ML inference probabilities
using a mathematically transparent, auditable formula.
"""

from typing import List
from backend.app.schemas.normalized import NormalizedConfiguration
from backend.app.schemas.compliance import ComplianceSummary
from backend.app.schemas.risk import MLInferenceResult, RiskAssessment


class RiskEngine:
    @staticmethod
    def calculate_risk(
        cfg: NormalizedConfiguration,
        compliance: ComplianceSummary,
        ml_res: MLInferenceResult
    ) -> RiskAssessment:
        # 1. Deterministic Rule Penalty Calculation
        rule_penalty = (
            (compliance.critical_violations * 25.0) +
            (compliance.high_violations * 15.0) +
            (compliance.medium_violations * 7.0) +
            (compliance.low_violations * 2.0)
        )
        rule_risk_score = min(100.0, round(rule_penalty, 1))

        # 2. ML Probability Expected Risk Value
        probs = ml_res.class_probabilities
        ml_base = (
            (probs.get("LOW", 0.0) * 10.0) +
            (probs.get("MEDIUM", 0.0) * 35.0) +
            (probs.get("HIGH", 0.0) * 70.0) +
            (probs.get("CRITICAL", 0.0) * 95.0)
        )

        # 3. Anomaly Penalty
        anomaly_penalty = 0.0
        if ml_res.is_anomaly:
            anomaly_penalty = min(15.0, round(abs(ml_res.anomaly_score) * 20.0, 1))

        ml_risk_score = min(100.0, round(ml_base, 1))

        # 4. Composite Weighted Score (55% Rule Engine + 45% ML Model + Anomaly Adjustment)
        raw_composite = (0.55 * rule_risk_score) + (0.45 * ml_risk_score) + anomaly_penalty

        # 5. Safety Floor: Critical deterministic controls enforce mandatory minimum risk floors
        safety_override = ""
        if compliance.critical_violations >= 2:
            if raw_composite < 85.0:
                raw_composite = 85.0
                safety_override = " (Safety Floor: Enforced CRITICAL tier due to >=2 Critical violations)"
        elif compliance.critical_violations == 1:
            if raw_composite < 70.0:
                raw_composite = 70.0
                safety_override = " (Safety Floor: Enforced HIGH tier floor due to 1 Critical violation)"

        composite_score = round(max(0.0, min(100.0, raw_composite)), 1)

        # 6. Categorical Risk Tier
        if composite_score <= 25.0:
            tier = "LOW"
        elif composite_score <= 50.0:
            tier = "MEDIUM"
        elif composite_score <= 75.0:
            tier = "HIGH"
        else:
            tier = "CRITICAL"

        # 7. Identify Key Drivers
        drivers: List[str] = []
        if compliance.critical_violations > 0:
            drivers.append(f"{compliance.critical_violations} Critical severity compliance violation(s) present")
        if compliance.high_violations > 0:
            drivers.append(f"{compliance.high_violations} High severity compliance violation(s) present")
        if cfg.telnet_enabled:
            drivers.append("Unencrypted Telnet remote management active")
        if any(r.is_unrestricted for r in cfg.firewall_rules):
            drivers.append("Permissive wildcard any-to-any firewall policy")
        if cfg.passwords.weak_algorithm_count > 0:
            drivers.append(f"{cfg.passwords.weak_algorithm_count} Weak/reversible password hashes stored in configuration")
        if ml_res.is_anomaly:
            drivers.append(f"Atypical configuration posture anomaly detected (Score: {ml_res.anomaly_score})")

        if not drivers:
            drivers.append("Hardened configuration adhering to enterprise cybersecurity baselines")

        formula_text = (
            f"Composite ({composite_score}/100) = [0.55 * RuleScore({rule_risk_score}) + "
            f"0.45 * MLScore({ml_risk_score}) + Anomaly({anomaly_penalty})]{safety_override}"
        )

        return RiskAssessment(
            composite_risk_score=composite_score,
            final_risk_level=tier,
            rule_risk_score=rule_risk_score,
            ml_risk_score=ml_risk_score,
            anomaly_penalty=anomaly_penalty,
            calculation_breakdown=formula_text,
            key_drivers=drivers
        )
