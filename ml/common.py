"""
Shared utilities for ScamShield ML training, calibration, versioning, and unified inference.
Reuses ml/training/compat.py and ml/training/prepare_datasets.py without duplicating logic.
"""

import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

ML_ROOT = os.path.dirname(os.path.abspath(__file__))
TRAINING_DIR = os.path.join(ML_ROOT, "training")
PIPELINE_DIR = os.path.join(ML_ROOT, "pipeline")

for p in (TRAINING_DIR, PIPELINE_DIR):
    if p not in sys.path:
        sys.path.insert(0, p)

from compat import get_environment_metadata  # noqa: E402

ARTIFACTS_DIR = os.path.join(ML_ROOT, "artifacts")
EXPERIMENTS_DIR = os.path.join(ML_ROOT, "experiments")
REPORTS_DIR = os.path.join(ML_ROOT, "reports")
SPLITS_DIR = os.path.join(ML_ROOT, "datasets", "splits")
MANIFESTS_DIR = os.path.join(ML_ROOT, "datasets", "manifests")
PROCESSED_DIR = os.path.join(ML_ROOT, "datasets", "processed")
RAW_DIR = os.path.join(ML_ROOT, "datasets", "raw")
SOURCE_REGISTRY_PATH = os.path.join(ML_ROOT, "data_sources", "source_registry.json")

for d in (ARTIFACTS_DIR, EXPERIMENTS_DIR, REPORTS_DIR, SPLITS_DIR, MANIFESTS_DIR):
    os.makedirs(d, exist_ok=True)


def compute_sha256(file_path: str) -> str:
    """Compute SHA-256 hex digest for an artifact file."""
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def load_source_registry() -> Dict[str, Any]:
    if not os.path.exists(SOURCE_REGISTRY_PATH):
        return {"sources": {}}
    with open(SOURCE_REGISTRY_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def register_artifact_version(
    task: str,
    version: str,
    artifact_path: str,
    dataset_version: str,
    preprocessing_version: str,
    model_type: str,
    training_config: Dict[str, Any],
    metrics: Dict[str, Any],
    calibration_params: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Record a versioned model artifact in ml/artifacts/registry.json with checksum and rollback support."""
    registry_path = os.path.join(ARTIFACTS_DIR, "registry.json")
    if os.path.exists(registry_path):
        with open(registry_path, "r", encoding="utf-8") as f:
            registry = json.load(f)
    else:
        registry = {"schema_version": "1.0.0", "tasks": {}}

    checksum = compute_sha256(artifact_path)
    entry = {
        "model_version": version,
        "task": task,
        "model_type": model_type,
        "artifact_path": os.path.relpath(artifact_path, ML_ROOT).replace("\\", "/"),
        "artifact_sha256": checksum,
        "artifact_size_bytes": os.path.getsize(artifact_path),
        "dataset_version": dataset_version,
        "preprocessing_version": preprocessing_version,
        "training_config": training_config,
        "metrics": metrics,
        "calibration": calibration_params or {"calibrated": False},
        "dependencies": get_environment_metadata(),
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "production_active": False,  # Never auto-promote to production
    }

    task_reg = registry["tasks"].setdefault(task, {"active_version": None, "previous_version": None, "versions": {}})
    if task_reg.get("active_version") and task_reg["active_version"] != version:
        task_reg["previous_version"] = task_reg["active_version"]
    task_reg["versions"][version] = entry
    task_reg["latest_candidate_version"] = version

    with open(registry_path, "w", encoding="utf-8") as f:
        json.dump(registry, f, indent=2)

    return entry


def build_unified_response(
    *,
    classification: str,
    risk_score: Optional[int],
    model_confidence: Optional[float],
    confidence_calibrated: bool,
    model_version: str,
    detection_method: str = "trained_ml",
    indicators: Optional[List[Dict[str, Any]]] = None,
    status: str = "completed",
    probabilities: Optional[Dict[str, float]] = None,
    limitations: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Build a ScamShield unified ML response contract.
    Never derives model_confidence from risk_score.
    """
    return {
        "classification": classification,
        "risk_score": risk_score,
        "model_confidence": model_confidence,
        "confidence_calibrated": bool(confidence_calibrated and model_confidence is not None),
        "model_version": model_version,
        "detection_method": detection_method,
        "indicators": indicators if indicators is not None else [],
        "status": status,
        "probabilities": probabilities or {},
        "limitations": limitations or [],
    }
