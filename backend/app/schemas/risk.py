"""
Schemas for ML Inference, Risk Scoring, and Factor Explainability.
"""

from typing import List, Dict, Optional, Any
from pydantic import BaseModel, Field


class RiskFactor(BaseModel):
    feature_name: str
    feature_value: float
    importance_weight: float
    contribution_score: float
    description: str


class MLInferenceResult(BaseModel):
    predicted_risk_class: str  # LOW, MEDIUM, HIGH, CRITICAL
    confidence: float  # 0.0 - 1.0
    class_probabilities: Dict[str, float]
    anomaly_score: float  # -1.0 to +1.0
    is_anomaly: bool
    top_contributing_factors: List[RiskFactor]
    model_version: str


class RiskAssessment(BaseModel):
    composite_risk_score: float  # 0.0 to 100.0
    final_risk_level: str  # LOW, MEDIUM, HIGH, CRITICAL
    rule_risk_score: float
    ml_risk_score: float
    anomaly_penalty: float
    calculation_breakdown: str
    key_drivers: List[str]
