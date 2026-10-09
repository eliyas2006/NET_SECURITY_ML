"""
Automated Tests for Machine Learning Pipeline, Dataset Integrity, and Inference.
Validates dataset schema, 29-feature dimensionality, ordering, class distributions,
artifact loading, and error handling for missing models.
"""

import os
import json
import tempfile
import pytest
import pandas as pd
import numpy as np

from backend.app.features.extractor import FEATURE_NAMES, extract_features, features_to_vector
from backend.app.ml.inference import MLService
from backend.app.parsers.cisco import CiscoParser
from backend.app.schemas.risk import MLInferenceResult


def test_dataset_schema_and_columns():
    """Verify dataset existence, dimensions, columns, and absence of nulls."""
    dataset_path = "ml/data/dataset.csv"
    assert os.path.exists(dataset_path), f"Dataset file {dataset_path} does not exist."

    df = pd.read_csv(dataset_path)
    assert len(df) == 1200, f"Expected 1,200 rows, found {len(df)}"
    assert df.isnull().sum().sum() == 0, "Dataset contains null/NaN values."

    # Required metadata columns
    required_meta = ["sample_id", "vendor", "target_risk_class", "target_risk_score"]
    for col in required_meta:
        assert col in df.columns, f"Missing required column: {col}"

    # Verify all 29 features are in dataset
    for feat in FEATURE_NAMES:
        assert feat in df.columns, f"Feature {feat} missing from dataset."

    # Total columns: 4 metadata + 29 features = 33
    assert len(df.columns) == 33, f"Expected 33 columns, got {len(df.columns)}"


def test_feature_dimensionality_and_ordering():
    """Verify feature extractor has exactly 29 ordered features matching metadata.json."""
    assert len(FEATURE_NAMES) == 29, f"Expected exactly 29 features, got {len(FEATURE_NAMES)}"

    meta_path = "ml/models/metadata.json"
    assert os.path.exists(meta_path), "metadata.json missing"
    with open(meta_path, "r") as f:
        meta = json.load(f)

    meta_features = meta.get("feature_names", [])
    assert meta_features == FEATURE_NAMES, "Feature names or order in extractor do not match metadata.json!"
    assert meta.get("n_features") == 29


def test_dataset_classes_and_vendors():
    """Verify valid risk class labels and balanced vendor coverage."""
    df = pd.read_csv("ml/data/dataset.csv")

    valid_classes = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    actual_classes = set(df["target_risk_class"].unique())
    assert actual_classes.issubset(valid_classes), f"Unexpected classes: {actual_classes - valid_classes}"

    # Verify each vendor has equal representation
    vendor_counts = df["vendor"].value_counts().to_dict()
    assert vendor_counts.get("Cisco") == 400
    assert vendor_counts.get("Fortinet") == 400
    assert vendor_counts.get("Palo Alto") == 400


def test_features_to_vector_shape_and_dtype():
    """Verify features_to_vector produces a 29-element 1D float32 array."""
    dummy_dict = {name: 1.0 for name in FEATURE_NAMES}
    vec = features_to_vector(dummy_dict)
    assert isinstance(vec, np.ndarray)
    assert vec.shape == (29,)
    assert vec.dtype == np.float32


def test_model_artifact_loading():
    """Verify model artifacts load successfully and provide valid classifiers."""
    service = MLService(models_dir="ml/models")
    assert service.clf is not None
    assert service.anomaly_detector is not None
    assert len(service.classes) == 4
    assert hasattr(service.clf, "predict_proba")
    assert hasattr(service.anomaly_detector, "decision_function")


def test_missing_model_artifacts_raises_error():
    """Verify clear FileNotFoundError when model directory is missing or empty."""
    with tempfile.TemporaryDirectory() as empty_dir:
        with pytest.raises(FileNotFoundError) as exc_info:
            MLService(models_dir=empty_dir)
        assert "ML Model artifacts not found" in str(exc_info.value)
        assert "ml/training/train.py" in str(exc_info.value)


def test_inference_output_schema_and_types():
    """Verify inference output produces valid MLInferenceResult with expected attributes."""
    service = MLService(models_dir="ml/models")
    dummy_dict = {name: 0.0 for name in FEATURE_NAMES}
    dummy_dict["vendor_cisco"] = 1.0
    dummy_dict["ssh_version"] = 2.0
    dummy_dict["ssh_enabled"] = 1.0
    dummy_dict["password_encryption_enabled"] = 1.0

    result = service.predict(dummy_dict)
    assert isinstance(result, MLInferenceResult)
    assert result.predicted_risk_class in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    assert 0.0 <= result.confidence <= 1.0
    assert isinstance(result.class_probabilities, dict)
    assert len(result.class_probabilities) == 4
    assert isinstance(result.anomaly_score, float)
    assert isinstance(result.is_anomaly, bool)
    assert isinstance(result.top_contributing_factors, list)


def test_deterministic_feature_extraction_from_config():
    """Verify feature extractor behaves deterministically on a parsed sample."""
    sample_cisco = (
        "version 15.6\n"
        "hostname rtr-test\n"
        "service password-encryption\n"
        "ip ssh version 2\n"
        "no ip http server\n"
        "snmp-server community public RW\n"
    )
    parser = CiscoParser()
    parsed = parser.parse(sample_cisco)
    features1 = extract_features(parsed)
    features2 = extract_features(parsed)

    assert features1 == features2
    assert features1["ssh_version"] == 2.0
    assert features1["ssh_enabled"] == 1.0
    assert features1["password_encryption_enabled"] == 1.0
    assert features1["snmp_default_community_used"] == 1.0
    assert features1["vendor_cisco"] == 1.0
