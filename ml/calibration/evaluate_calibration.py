"""
ScamShield Calibration Evaluation CLI
Evaluates calibration quality (Brier score, ECE, reliability bins) on held-out test splits
for trained email and URL model artifacts and outputs ml/reports/calibration_report.{json,md}.
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
import joblib

ML_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ML_ROOT not in sys.path:
    sys.path.insert(0, ML_ROOT)

from calibration.calibrate import compute_calibration_metrics, get_raw_scores_and_probs  # noqa: E402
from common import ARTIFACTS_DIR, REPORTS_DIR, SPLITS_DIR  # noqa: E402


def evaluate_task_calibration(task: str) -> dict:
    artifact_path = os.path.join(ARTIFACTS_DIR, f"{task}_model_latest.joblib")
    test_path = os.path.join(SPLITS_DIR, f"{task}_test.json")
    if not os.path.exists(artifact_path) or not os.path.exists(test_path):
        return {"task": task, "status": "skipped", "reason": "Missing artifact or test split"}

    bundle = joblib.load(artifact_path)
    with open(test_path, "r", encoding="utf-8") as f:
        test_items = json.load(f)["samples"]

    X_test = bundle["featurizer"](test_items)
    y_test = [it["label"] for it in test_items]
    classes = bundle["classes"]
    calibrator = bundle["calibrator"]

    logits, raw_probs = get_raw_scores_and_probs(bundle["model"], X_test, classes)
    cal_probs = calibrator.transform_probs(logits, raw_probs)

    uncal_metrics = compute_calibration_metrics(raw_probs, y_test, classes)
    cal_metrics = compute_calibration_metrics(cal_probs, y_test, classes)

    return {
        "task": task,
        "status": "completed",
        "model_version": bundle["model_version"],
        "calibration_method": calibrator.method,
        "validation_selection": bundle.get("calibration_report", {}),
        "test_uncalibrated": uncal_metrics,
        "test_calibrated": cal_metrics,
    }


def main():
    parser = argparse.ArgumentParser(description="Evaluate calibration quality on held-out test splits.")
    parser.add_argument("--task", choices=["email", "url", "all"], default="all")
    args = parser.parse_args()

    tasks = ["email", "url"] if args.task == "all" else [args.task]
    results = {t: evaluate_task_calibration(t) for t in tasks}

    out_json = os.path.join(REPORTS_DIR, "calibration_report.json")
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    lines = [
        "# ScamShield Calibration Evaluation Report",
        f"- **Generated At:** {datetime.now(timezone.utc).isoformat()}",
        "",
    ]
    for t, res in results.items():
        if res.get("status") != "completed":
            lines.append(f"## {t.upper()}: Skipped ({res.get('reason')})\n")
            continue
        u = res["test_uncalibrated"]
        c = res["test_calibrated"]
        lines.extend([
            f"## {t.upper()} (`{res['model_version']}` — method: `{res['calibration_method']}`)",
            f"- **Test Brier Score:** {u['brier_score']} (uncalibrated) -> **{c['brier_score']}** (calibrated)",
            f"- **Test ECE:** {u['ece']} (uncalibrated) -> **{c['ece']}** (calibrated)",
            f"- **Test NLL:** {u['nll']} (uncalibrated) -> **{c['nll']}** (calibrated)",
            "",
            "| Confidence Bin | Count | Avg Confidence | Empirical Accuracy | Gap |",
            "|---|---:|---:|---:|---:|",
        ])
        for b in c.get("reliability_bins", []):
            lines.append(
                f"| {b['bin']} | {b['count']} | {b['avg_confidence']:.4f} | {b['empirical_accuracy']:.4f} | {b['gap']:.4f} |"
            )
        lines.append("")

    with open(os.path.join(REPORTS_DIR, "calibration_report.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    print(f"[OK] Calibration report saved to {out_json}")


if __name__ == "__main__":
    main()
