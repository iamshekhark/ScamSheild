"""
ScamShield Email Model Evaluation
Evaluates the trained email model bundle on the held-out TEST split (never used in training/selection).
Computes accuracy, precision, recall, F1, confusion matrix, ROC-AUC, PR-AUC, FPR, FNR, latency, and size.
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict

import joblib
import numpy as np
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    precision_recall_fscore_support,
    roc_auc_score,
)

ML_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ML_ROOT not in sys.path:
    sys.path.insert(0, ML_ROOT)

from calibration.calibrate import compute_calibration_metrics, get_raw_scores_and_probs  # noqa: E402
from common import ARTIFACTS_DIR, REPORTS_DIR, SPLITS_DIR  # noqa: E402


def evaluate_email_model(artifact_path: str = None) -> Dict[str, Any]:
    if artifact_path is None:
        artifact_path = os.path.join(ARTIFACTS_DIR, "email_model_latest.joblib")
    bundle = joblib.load(artifact_path)

    test_path = os.path.join(SPLITS_DIR, "email_test.json")
    with open(test_path, "r", encoding="utf-8") as f:
        test_items = json.load(f)["samples"]

    y_test = [x["label"] for x in test_items]
    classes = bundle["classes"]

    t0 = time.perf_counter()
    X_test = bundle["featurizer"](test_items)
    logits, raw_probs = get_raw_scores_and_probs(bundle["model"], X_test, classes)
    probs = bundle["calibrator"].transform_probs(logits, raw_probs)
    total_ms = (time.perf_counter() - t0) * 1000.0
    latency_ms = round(total_ms / max(len(test_items), 1), 4)

    preds = [classes[i] for i in np.argmax(probs, axis=1)]

    acc = float(accuracy_score(y_test, preds))
    p_mac, r_mac, f1_mac, _ = precision_recall_fscore_support(y_test, preds, average="macro", zero_division=0)
    p_cls, r_cls, f1_cls, sup_cls = precision_recall_fscore_support(y_test, preds, labels=classes, zero_division=0)
    cm = confusion_matrix(y_test, preds, labels=classes).tolist()

    legit_idx = [i for i, y in enumerate(y_test) if y == "legitimate"]
    threat_idx = [i for i, y in enumerate(y_test) if y != "legitimate"]
    fpr = sum(1 for i in legit_idx if preds[i] != "legitimate") / max(len(legit_idx), 1)
    fnr = sum(1 for i in threat_idx if preds[i] == "legitimate") / max(len(threat_idx), 1)

    roc_auc = None
    pr_auc = None
    if "legitimate" in classes and len(test_items) > 1:
        li = classes.index("legitimate")
        y_bin = np.array([0 if y == "legitimate" else 1 for y in y_test])
        if len(np.unique(y_bin)) == 2:
            mal_prob = 1.0 - probs[:, li]
            roc_auc = round(float(roc_auc_score(y_bin, mal_prob)), 4)
            pr_auc = round(float(average_precision_score(y_bin, mal_prob)), 4)

    cal_metrics = compute_calibration_metrics(probs, y_test, classes)
    size_mb = round(os.path.getsize(artifact_path) / (1024 * 1024), 4)

    fp_samples = [
        {"sample": test_items[i]["content"][:160], "predicted": preds[i], "confidence": round(float(np.max(probs[i])), 4)}
        for i in legit_idx if preds[i] != "legitimate"
    ][:10]
    fn_samples = [
        {"sample": test_items[i]["content"][:160], "true": y_test[i], "confidence": round(float(np.max(probs[i])), 4)}
        for i in threat_idx if preds[i] == "legitimate"
    ][:10]

    report = {
        "task": "email",
        "model_version": bundle["model_version"],
        "model_type": bundle["model_type"],
        "calibration_method": bundle["calibrator"].method,
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
        "test_samples": len(test_items),
        "model_size_mb": size_mb,
        "inference_latency_ms_per_sample": latency_ms,
        "metrics": {
            "accuracy": round(acc, 4),
            "macro_precision": round(float(p_mac), 4),
            "macro_recall": round(float(r_mac), 4),
            "macro_f1": round(float(f1_mac), 4),
            "roc_auc": roc_auc,
            "pr_auc": pr_auc,
            "false_positive_rate": round(float(fpr), 4),
            "false_negative_rate": round(float(fnr), 4),
            "brier_score": cal_metrics["brier_score"],
            "ece": cal_metrics["ece"],
        },
        "per_class": {
            c: {"precision": round(float(p_cls[i]), 4), "recall": round(float(r_cls[i]), 4), "f1": round(float(f1_cls[i]), 4), "support": int(sup_cls[i])}
            for i, c in enumerate(classes)
        },
        "confusion_matrix": {"labels": classes, "matrix": cm},
        "false_positives_sample": fp_samples,
        "false_negatives_sample": fn_samples,
    }

    out_json = os.path.join(REPORTS_DIR, "email_model_evaluation.json")
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    md = [
        f"# Email Model Evaluation ({bundle['model_version']})",
        f"- **Model Type:** `{bundle['model_type']}` | **Calibration:** `{bundle['calibrator'].method}`",
        f"- **Test Samples:** {len(test_items)} | **Size:** {size_mb} MB | **Latency:** {latency_ms} ms/sample",
        f"- **Accuracy:** {report['metrics']['accuracy']} | **Macro F1:** {report['metrics']['macro_f1']}",
        f"- **ROC-AUC:** {roc_auc} | **PR-AUC:** {pr_auc}",
        f"- **False Positive Rate:** {report['metrics']['false_positive_rate']:.2%} | **False Negative Rate:** {report['metrics']['false_negative_rate']:.2%}",
        f"- **Brier Score:** {cal_metrics['brier_score']} | **ECE:** {cal_metrics['ece']}",
    ]
    with open(os.path.join(REPORTS_DIR, "email_model_evaluation.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(md))

    print(f"[OK] Email test evaluation: acc={report['metrics']['accuracy']}, macro_f1={report['metrics']['macro_f1']}, fpr={report['metrics']['false_positive_rate']:.2%}")
    return report


def main():
    parser = argparse.ArgumentParser(description="Evaluate trained ScamShield email model on test split.")
    parser.add_argument("--artifact", type=str, default=None)
    args = parser.parse_args()
    evaluate_email_model(args.artifact)


if __name__ == "__main__":
    main()
