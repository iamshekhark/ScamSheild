"""
ScamShield Email Model Inference API
Returns the unified ScamShield response contract with calibrated model_confidence.
Handles empty, invalid, and out-of-distribution/low-coverage inputs cautiously.
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
from email_model.preprocessing import preprocess_email_record  # noqa: E402


def predict_email(
    subject: str = "",
    body: str = "",
    sender: str = "",
    artifact_path: Optional[str] = None,
) -> Dict[str, Any]:
    if artifact_path is None:
        artifact_path = os.path.join(ARTIFACTS_DIR, "email_model_latest.joblib")

    if not os.path.exists(artifact_path):
        return build_unified_response(
            classification="unknown",
            risk_score=None,
            model_confidence=None,
            confidence_calibrated=False,
            model_version="unavailable",
            status="model_unavailable",
            limitations=["Email model artifact not found."],
        )

    prep = preprocess_email_record({"subject": subject, "body": body, "sender": sender})
    if not prep["combined_text"]:
        return build_unified_response(
            classification="unknown",
            risk_score=None,
            model_confidence=None,
            confidence_calibrated=False,
            model_version="email-model-v1.0.0",
            status="invalid_input",
            limitations=["Empty email subject and body."],
        )

    bundle = joblib.load(artifact_path)
    classes = bundle["classes"]
    calibrator = bundle["calibrator"]

    X = bundle["featurizer"]([{"subject": subject, "body": body, "sender": sender}])
    # Check vocabulary coverage if TF-IDF is used
    if hasattr(bundle["featurizer"], "vectorizer"):
        vocab_hits = int(bundle["featurizer"].vectorizer.transform([prep["combined_text"]]).nnz)
    else:
        vocab_hits = int(X.nnz) if hasattr(X, "nnz") else int(np.count_nonzero(X))

    if vocab_hits == 0:
        return build_unified_response(
            classification="uncertain",
            risk_score=50,
            model_confidence=None,
            confidence_calibrated=False,
            model_version=bundle["model_version"],
            status="out_of_distribution",
            limitations=["Input has zero overlap with trained vocabulary; confidence unavailable."],
        )

    logits, raw_probs = get_raw_scores_and_probs(bundle["model"], X, classes)
    probs = calibrator.transform_probs(logits, raw_probs)[0]

    best_idx = int(np.argmax(probs))
    pred_class = classes[best_idx]
    confidence_pct = round(float(probs[best_idx]) * 100.0, 2)

    # Compute risk_score separately from threat probability (never equal to model_confidence)
    legit_prob = float(probs[classes.index("legitimate")]) if "legitimate" in classes else 0.0
    threat_prob = 1.0 - legit_prob
    risk_score = int(round(threat_prob * 100))

    is_uncertain = float(probs[best_idx]) < calibrator.uncertainty_threshold
    final_class = "uncertain" if is_uncertain else pred_class

    indicators = []
    if final_class in ("phishing", "spam"):
        indicators.append({
            "indicator_type": f"ML_EMAIL_{final_class.upper()}",
            "description": f"Email classifier predicted {final_class} ({confidence_pct}% calibrated confidence).",
            "severity": "high" if final_class == "phishing" else "medium",
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
    parser = argparse.ArgumentParser(description="Run local email prediction.")
    parser.add_argument("--subject", type=str, default="")
    parser.add_argument("--body", type=str, required=True)
    parser.add_argument("--sender", type=str, default="")
    args = parser.parse_args()
    print(json.dumps(predict_email(args.subject, args.body, args.sender), indent=2))


if __name__ == "__main__":
    main()
