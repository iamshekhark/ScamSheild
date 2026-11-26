"""
ScamShield URL Model Training & Benchmarking
Trains and compares:
1. Structured Lexical Features + Logistic Regression (Baseline)
2. Structured Lexical Features + Random Forest
3. Structured Lexical Features + HistGradientBoosting
4. Hybrid (Char-TFIDF + Structured Features) + Logistic Regression

Selects best candidate on VALIDATION split, fits probability calibration on
VALIDATION split only, and saves versioned artifacts to ml/artifacts/.
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List

import joblib
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_recall_fscore_support

ML_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ML_ROOT not in sys.path:
    sys.path.insert(0, ML_ROOT)

from calibration.calibrate import fit_best_calibrator  # noqa: E402
from common import (  # noqa: E402
    ARTIFACTS_DIR,
    EXPERIMENTS_DIR,
    MANIFESTS_DIR,
    SPLITS_DIR,
    register_artifact_version,
)
from compat import get_environment_metadata  # noqa: E402
from url_model.feature_extraction import PREPROCESSING_VERSION, UrlHybridFeaturizer  # noqa: E402

MODEL_VERSION = "url-model-v1.0.0"
RANDOM_SEED = 42


def load_split(split_name: str) -> List[Dict[str, Any]]:
    path = os.path.join(SPLITS_DIR, f"url_{split_name}.json")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)["samples"]


def train_url_models(seed: int = RANDOM_SEED, version: str = MODEL_VERSION) -> Dict[str, Any]:
    train_items = load_split("train")
    val_items = load_split("validation")
    y_train = [x["label"] for x in train_items]
    y_val = [x["label"] for x in val_items]

    manifest_path = os.path.join(MANIFESTS_DIR, "url_manifest.json")
    dataset_version = "unknown"
    if os.path.exists(manifest_path):
        with open(manifest_path, "r", encoding="utf-8") as f:
            dataset_version = json.load(f).get("dataset_version", "unknown")

    struct_feat = UrlHybridFeaturizer(use_tfidf=False)
    X_tr_struct = struct_feat.fit_transform(train_items)
    X_va_struct = struct_feat(val_items)

    hybrid_feat = UrlHybridFeaturizer(max_features=4000, use_tfidf=True)
    X_tr_hyb = hybrid_feat.fit_transform(train_items)
    X_va_hyb = hybrid_feat(val_items)

    candidates = []

    def eval_candidate(name: str, model: Any, featurizer: Any, X_tr, X_va):
        t0 = time.perf_counter()
        model.fit(X_tr, y_train)
        train_sec = round(time.perf_counter() - t0, 3)
        preds_val = model.predict(X_va)
        acc = float(accuracy_score(y_val, preds_val))
        prec, rec, f1, _ = precision_recall_fscore_support(y_val, preds_val, average="macro", zero_division=0)
        legit_idx = [i for i, y in enumerate(y_val) if y == "legitimate"]
        fpr = sum(1 for i in legit_idx if preds_val[i] != "legitimate") / max(len(legit_idx), 1)
        candidates.append({
            "name": name,
            "model": model,
            "featurizer": featurizer,
            "X_val": X_va,
            "train_seconds": train_sec,
            "val_metrics": {
                "accuracy": round(acc, 4),
                "macro_precision": round(float(prec), 4),
                "macro_recall": round(float(rec), 4),
                "macro_f1": round(float(f1), 4),
                "val_fpr_legitimate": round(float(fpr), 4),
            },
        })

    eval_candidate(
        "Structured_LogisticRegression_Baseline",
        LogisticRegression(C=1.0, class_weight="balanced", max_iter=1000, random_state=seed),
        struct_feat,
        X_tr_struct,
        X_va_struct,
    )
    eval_candidate(
        "Structured_RandomForest",
        RandomForestClassifier(n_estimators=150, max_depth=16, class_weight="balanced", random_state=seed, n_jobs=-1),
        struct_feat,
        X_tr_struct,
        X_va_struct,
    )
    eval_candidate(
        "Structured_HistGradientBoosting",
        HistGradientBoostingClassifier(max_iter=150, max_depth=8, random_state=seed),
        struct_feat,
        X_tr_struct,
        X_va_struct,
    )
    eval_candidate(
        "Hybrid_CharTFIDF_Structured_LogisticRegression",
        LogisticRegression(C=2.0, class_weight="balanced", max_iter=1000, random_state=seed),
        hybrid_feat,
        X_tr_hyb,
        X_va_hyb,
    )

    best = max(candidates, key=lambda c: (c["val_metrics"]["macro_f1"], -c["val_metrics"]["val_fpr_legitimate"]))
    classes = list(best["model"].classes_)

    calibrator, cal_report = fit_best_calibrator(best["model"], best["X_val"], y_val, classes)

    artifact_path = os.path.join(ARTIFACTS_DIR, f"url_model_{version}.joblib")
    latest_path = os.path.join(ARTIFACTS_DIR, "url_model_latest.joblib")

    bundle = {
        "task": "url",
        "model_version": version,
        "model_type": best["name"],
        "classes": classes,
        "model": best["model"],
        "featurizer": best["featurizer"],
        "calibrator": calibrator,
        "calibration_report": cal_report,
        "dataset_version": dataset_version,
        "preprocessing_version": PREPROCESSING_VERSION,
        "random_seed": seed,
        "train_seconds": best["train_seconds"],
        "dependencies": get_environment_metadata(),
        "trained_at": datetime.now(timezone.utc).isoformat(),
    }
    joblib.dump(bundle, artifact_path, compress=3)
    joblib.dump(bundle, latest_path, compress=3)

    reg_entry = register_artifact_version(
        task="url",
        version=version,
        artifact_path=artifact_path,
        dataset_version=dataset_version,
        preprocessing_version=PREPROCESSING_VERSION,
        model_type=best["name"],
        training_config={"seed": seed, "train_samples": len(train_items), "val_samples": len(val_items)},
        metrics=best["val_metrics"],
        calibration_params=calibrator.to_metadata(),
    )

    experiment_log = {
        "task": "url",
        "model_version": version,
        "selected_model": best["name"],
        "candidates": [
            {"name": c["name"], "train_seconds": c["train_seconds"], "val_metrics": c["val_metrics"]}
            for c in candidates
        ],
        "calibration": cal_report,
        "artifact": reg_entry,
    }
    with open(os.path.join(EXPERIMENTS_DIR, "url_benchmark.json"), "w", encoding="utf-8") as f:
        json.dump(experiment_log, f, indent=2)

    print(f"[OK] URL model trained: {best['name']} ({version}) | val_macro_f1={best['val_metrics']['macro_f1']} | cal={calibrator.method}")
    return experiment_log


def main():
    parser = argparse.ArgumentParser(description="Train and benchmark ScamShield URL classifiers.")
    parser.add_argument("--seed", type=int, default=RANDOM_SEED)
    parser.add_argument("--version", type=str, default=MODEL_VERSION)
    args = parser.parse_args()
    train_url_models(seed=args.seed, version=args.version)


if __name__ == "__main__":
    main()
