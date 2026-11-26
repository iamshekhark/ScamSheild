"""
ScamShield URL Model Inference API
Returns the unified ScamShield response contract with calibrated model_confidence.
Note: URL ML predictions contribute risk signals and never independently prove maliciousness
without deterministic or threat-intelligence corroboration.
"""

import argparse
import json
import os
import sys
from typing import Any, Dict, Optional

import joblib
import numpy as np

ML_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ML_ROOT not in sys.path:
    sys.path.insert(0, ML_ROOT)

from calibration.calibrate import get_raw_scores_and_probs  # noqa: E402
from common import ARTIFACTS_DIR, build_unified_response  # noqa: E402
from quality_analyzer import normalize_url  # noqa: E402


def predict_url(url: str, artifact_path: Optional[str] = None) -> Dict[str, Any]:
    if artifact_path is None:
        artifact_path = os.path.join(ARTIFACTS_DIR, "url_model_latest.joblib")

    if not os.path.exists(artifact_path):
        return build_unified_response(
            classification="unknown",
            risk_score=None,
            model_confidence=None,
            confidence_calibrated=False,
            model_version="unavailable",
            status="model_unavailable",
            limitations=["URL model artifact not found."],
        )

    if not url or not isinstance(url, str) or not url.strip():
        return build_unified_response(
            classification="unknown",
            risk_score=None,
            model_confidence=None,
            confidence_calibrated=False,
            model_version="url-model-v1.0.0",
            status="invalid_input",
            limitations=["Empty or invalid URL input."],
        )

    norm = normalize_url(url)
    bundle = joblib.load(artifact_path)
    classes = bundle["classes"]
    calibrator = bundle["calibrator"]

    X = bundle["featurizer"]([{"url": norm}])
    logits, raw_probs = get_raw_scores_and_probs(bundle["model"], X, classes)
    probs = calibrator.transform_probs(logits, raw_probs)[0]

    best_idx = int(np.argmax(probs))
    pred_class = classes[best_idx]
    confidence_pct = round(float(probs[best_idx]) * 100.0, 2)

    legit_prob = float(probs[classes.index("legitimate")]) if "legitimate" in classes else 0.0
    threat_prob = 1.0 - legit_prob
    risk_score = int(round(threat_prob * 100))

    is_uncertain = float(probs[best_idx]) < calibrator.uncertainty_threshold
    final_class = "uncertain" if is_uncertain else pred_class

    indicators = []
    if final_class == "malicious":
        indicators.append({
            "indicator_type": "ML_URL_ANOMALY",
            "description": f"URL classifier predicted malicious ({confidence_pct}% calibrated confidence); requires deterministic or threat-intel corroboration before blocking.",
            "severity": "medium",
        })

    return build_unified_response(
        classification=final_class,
        risk_score=risk_score,
        model_confidence=confidence_pct,
        confidence_calibrated=calibrator.method != "none",
        model_version=bundle["model_version"],
        detection_method="trained_ml",
        indicators=indicators,
        status="completed" if not is_uncertain else "uncertain",
        probabilities={c: round(float(probs[i]), 4) for i, c in enumerate(classes)},
    )


def main():
    parser = argparse.ArgumentParser(description="Run local URL prediction.")
    parser.add_argument("--url", type=str, required=True)
    args = parser.parse_args()
    print(json.dumps(predict_url(args.url), indent=2))


if __name__ == "__main__":
    main()
