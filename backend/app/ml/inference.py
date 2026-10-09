"""
ML Inference Service.
Loads serialized models and performs risk classification, anomaly detection, and factor explainability.
"""

import os
import json
import joblib
import numpy as np
from typing import Dict, List, Optional
from backend.app.schemas.risk import MLInferenceResult, RiskFactor
from backend.app.features.extractor import FEATURE_NAMES, features_to_vector

FEATURE_DESCRIPTIONS = {
    "unrestricted_rules_count": "Wildcard any-any permit firewall rules detected",
    "weak_password_algorithms_count": "Usage of weak/reversible password encryption (Type 7 / MD5)",
    "telnet_enabled": "Plaintext Telnet remote management protocol enabled",
    "snmp_default_community_used": "Default SNMP community string ('public'/'private') in use",
    "exec_timeout_minutes": "Absence or excessive administrative session inactivity timeout",
    "logging_enabled": "Absence of system event logging",
    "remote_syslog_count": "Lack of remote SIEM / syslog log forwarding",
    "http_server_enabled": "Plaintext HTTP administration server active",
    "default_deny_enforced": "Firewall policy default deny stance enforcement",
    "insecure_services_count": "Legacy diagnostic services enabled (finger, bootp, source-route)",
    "ssh_version": "SSH version posture (0=disabled, 1=v1 deprecated, 2=v2 secure)",
    "password_encryption_enabled": "Global configuration password encryption flag",
    "snmp_v1_v2c_enabled": "Legacy unencrypted SNMPv1/v2c protocol active",
    "snmp_v3_enabled": "Modern encrypted SNMPv3 protocol active",
    "aaa_new_model_enabled": "Centralized AAA authentication framework enforcement",
    "login_banner_configured": "Authorized access security warning banner configured",
    "min_password_length": "Enforced minimum administrative password length",
    "exposed_management_interfaces": "Insecure management services bound to external interfaces",
    "vpn_crypto_modern": "Modern cryptographic cipher suites configured"
}


class MLService:
    def __init__(self, models_dir: Optional[str] = None):
        if models_dir is None:
            # Default to ml/models relative to project root
            base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../ml/models"))
            if not os.path.exists(base_dir):
                base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../ml/models"))
            models_dir = base_dir

        self.models_dir = models_dir
        self.clf = None
        self.anomaly_detector = None
        self.metadata = {}
        self.classes = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        self.load_models()

    def load_models(self):
        clf_file = os.path.join(self.models_dir, "risk_classifier.joblib")
        iso_file = os.path.join(self.models_dir, "anomaly_detector.joblib")
        meta_file = os.path.join(self.models_dir, "metadata.json")

        if os.path.exists(clf_file) and os.path.exists(iso_file):
            self.clf = joblib.load(clf_file)
            self.anomaly_detector = joblib.load(iso_file)
            if os.path.exists(meta_file):
                with open(meta_file, "r") as f:
                    self.metadata = json.load(f)
                    self.classes = self.metadata.get("classes", self.classes)
        else:
            raise FileNotFoundError(f"ML Model artifacts not found in {self.models_dir}. Please run ml/training/train.py first.")

    def predict(self, features: Dict[str, float]) -> MLInferenceResult:
        vec = features_to_vector(features).reshape(1, -1)

        # Predict risk probabilities
        probs = self.clf.predict_proba(vec)[0]
        class_idx = int(np.argmax(probs))
        pred_class = self.classes[class_idx]
        confidence = float(probs[class_idx])

        prob_dict = {cls_name: round(float(probs[i]), 4) for i, cls_name in enumerate(self.classes)}

        # Anomaly scoring
        anomaly_score = float(self.anomaly_detector.decision_function(vec)[0])
        is_anomaly = bool(anomaly_score < 0.0)

        # Explainability: compute feature contributions based on MDI importances
        factors: List[RiskFactor] = []
        if hasattr(self.clf, "feature_importances_"):
            importances = self.clf.feature_importances_
            for i, feat_name in enumerate(FEATURE_NAMES):
                val = float(vec[0][i])
                imp = float(importances[i])
                
                # Risk contribution logic: higher value of dangerous features increases risk
                # Inverted for compliance_pass_ratio, default_deny, logging_enabled, ssh_version
                if feat_name in ["default_deny_enforced", "logging_enabled", "ssh_version", "strong_password_algorithms_count", "password_encryption_enabled", "aaa_new_model_enabled", "snmp_v3_enabled"]:
                    risk_impact = max(0.0, 1.0 - val) * imp
                else:
                    risk_impact = val * imp

                if risk_impact > 0.005 or imp > 0.05:
                    desc = FEATURE_DESCRIPTIONS.get(feat_name, f"Configuration parameter '{feat_name}'")
                    factors.append(RiskFactor(
                        feature_name=feat_name,
                        feature_value=round(val, 2),
                        importance_weight=round(imp, 4),
                        contribution_score=round(risk_impact * 100.0, 2),
                        description=desc
                    ))

        # Sort factors by highest contribution score
        factors.sort(key=lambda x: x.contribution_score, reverse=True)

        return MLInferenceResult(
            predicted_risk_class=pred_class,
            confidence=round(confidence, 3),
            class_probabilities=prob_dict,
            anomaly_score=round(anomaly_score, 3),
            is_anomaly=is_anomaly,
            top_contributing_factors=factors[:5],
            model_version=self.metadata.get("model_type", "Random Forest")
        )


_service_instance: Optional[MLService] = None

def get_ml_service() -> MLService:
    global _service_instance
    if _service_instance is None:
        _service_instance = MLService()
    return _service_instance
