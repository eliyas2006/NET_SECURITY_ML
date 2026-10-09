"""
Controlled Leakage Experiments A through E on Corrected Non-Leaking Dataset.
Evaluates model performance under different feature subsets and cross-vendor generalization.
"""

import os
import sys
import numpy as np
import pandas as pd

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
from sklearn.preprocessing import StandardScaler

from backend.app.features.extractor import FEATURE_NAMES

LABEL_MAP = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
REV_MAP = {0: "LOW", 1: "MEDIUM", 2: "HIGH", 3: "CRITICAL"}
CLASSES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


def evaluate_models_on_features(X, y, feature_subset_name, random_state=42):
    X_train_val, X_test, y_train_val, y_test = train_test_split(
        X, y, test_size=0.15, random_state=random_state, stratify=y
    )
    val_ratio = 0.15 / 0.85
    X_train, X_val, y_train, y_val = train_test_split(
        X_train_val, y_train_val, test_size=val_ratio, random_state=random_state, stratify=y_train_val
    )

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    models = {
        "Logistic Regression": (LogisticRegression(max_iter=1000, random_state=random_state), True),
        "Decision Tree": (DecisionTreeClassifier(max_depth=6, random_state=random_state), False),
        "Random Forest": (RandomForestClassifier(n_estimators=100, max_depth=8, class_weight="balanced", random_state=random_state), False),
        "Gradient Boosting": (GradientBoostingClassifier(n_estimators=100, max_depth=4, random_state=random_state), False)
    }

    print(f"\n==================================================")
    print(f"EXPERIMENT: {feature_subset_name} (Features: {X.shape[1]})")
    print(f"==================================================")

    res_summary = {}
    for name, (clf, use_scaled) in models.items():
        X_tr = X_train_scaled if use_scaled else X_train
        X_te = X_test_scaled if use_scaled else X_test

        clf.fit(X_tr, y_train)
        preds = clf.predict(X_te)

        acc = accuracy_score(y_test, preds)
        prec = precision_score(y_test, preds, average="macro", zero_division=0)
        rec = recall_score(y_test, preds, average="macro", zero_division=0)
        f1 = f1_score(y_test, preds, average="macro", zero_division=0)
        cm = confusion_matrix(y_test, preds)

        crit_to_low = int(np.sum((y_test == 3) & (preds == 0)))
        high_to_low = int(np.sum((y_test == 2) & (preds == 0)))

        res_summary[name] = {
            "accuracy": acc,
            "precision": prec,
            "recall": rec,
            "f1": f1,
            "crit_to_low": crit_to_low,
            "high_to_low": high_to_low,
            "confusion_matrix": cm.tolist()
        }

        print(f"[{name}] Acc: {acc*100:.2f}% | Prec: {prec*100:.2f}% | Rec: {rec*100:.2f}% | F1: {f1*100:.2f}% | CRIT->LOW: {crit_to_low}, HIGH->LOW: {high_to_low}")
        print(f"Confusion Matrix:\n{cm}")

    return res_summary


def run_all_experiments():
    df = pd.read_csv("ml/data/dataset.csv")
    y = df["target_risk_class"].map(LABEL_MAP).values

    # Exp A: Full 29 raw configuration features (including vendor one-hot)
    feats_a = FEATURE_NAMES
    X_a = df[feats_a].values
    evaluate_models_on_features(X_a, y, "Experiment A: Full Corrected Feature Set (29 features)")

    # Exp B: Raw configuration features only (26 features, vendor indicators excluded)
    feats_b = [f for f in FEATURE_NAMES if not f.startswith("vendor_")]
    X_b = df[feats_b].values
    evaluate_models_on_features(X_b, y, "Experiment B: Raw Config Features Only (26 features, No Vendor Indicators)")

    # Exp C: Minimal Core Security Posture (15 high-leverage features: SSH, Telnet, Passwords, AAA, Logging, Firewall)
    feats_c = [
        "ssh_version", "ssh_enabled", "telnet_enabled", "http_server_enabled",
        "weak_password_algorithms_count", "min_password_length", "aaa_new_model_enabled",
        "logging_enabled", "remote_syslog_count", "snmp_default_community_used",
        "snmp_v3_enabled", "insecure_services_count", "unrestricted_rules_count",
        "default_deny_enforced", "exposed_management_interfaces"
    ]
    X_c = df[feats_c].values
    evaluate_models_on_features(X_c, y, "Experiment C: Minimal Core Posture (15 features)")

    # Exp D: Perimeter & Firewall Rules Only (firewall_rules_total, unrestricted_rules_count, default_deny, exposed_mgmt)
    feats_d = ["firewall_rules_total", "unrestricted_rules_count", "default_deny_enforced", "exposed_management_interfaces"]
    X_d = df[feats_d].values
    evaluate_models_on_features(X_d, y, "Experiment D: Boundary & Firewall Only (4 features)")

    # Exp E: Cross-Vendor Generalization (Train on Cisco & Fortinet, Test on Palo Alto)
    print("\n==================================================")
    print("EXPERIMENT E: Cross-Vendor Generalization (Train on Cisco & Fortinet, Test on Palo Alto)")
    print("==================================================")
    train_mask = df["vendor"].isin(["Cisco", "Fortinet"])
    test_mask = df["vendor"] == "Palo Alto"

    X_train_e = df.loc[train_mask, feats_b].values
    y_train_e = y[train_mask]
    X_test_e = df.loc[test_mask, feats_b].values
    y_test_e = y[test_mask]

    rf_e = RandomForestClassifier(n_estimators=100, max_depth=8, class_weight="balanced", random_state=42)
    rf_e.fit(X_train_e, y_train_e)
    preds_e = rf_e.predict(X_test_e)

    acc_e = accuracy_score(y_test_e, preds_e)
    prec_e = precision_score(y_test_e, preds_e, average="macro", zero_division=0)
    rec_e = recall_score(y_test_e, preds_e, average="macro", zero_division=0)
    f1_e = f1_score(y_test_e, preds_e, average="macro", zero_division=0)
    cm_e = confusion_matrix(y_test_e, preds_e)

    crit_to_low_e = int(np.sum((y_test_e == 3) & (preds_e == 0)))
    high_to_low_e = int(np.sum((y_test_e == 2) & (preds_e == 0)))

    print(f"Random Forest (Trained on Cisco+Fortinet [800 samples], Evaluated on Palo Alto [400 samples], Vendor-Agnostic):")
    print(f"Test Acc: {acc_e*100:.2f}% | Prec: {prec_e*100:.2f}% | Rec: {rec_e*100:.2f}% | F1: {f1_e*100:.2f}%")
    print(f"False Negatives: CRIT->LOW: {crit_to_low_e}, HIGH->LOW: {high_to_low_e}")
    print(f"Confusion Matrix on Palo Alto:\n{cm_e}")


if __name__ == "__main__":
    run_all_experiments()
