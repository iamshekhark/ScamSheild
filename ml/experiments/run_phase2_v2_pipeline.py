"""
ScamShield Phase 2 — Train, Calibrate & Independently Evaluate v2.0.0 Candidate Models
Preserves v1.0.0 models and datasets completely.
"""

import json
import os
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List

import joblib
import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression, SGDClassifier
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

from calibration.calibrate import (  # noqa: E402
    compute_calibration_metrics,
    fit_best_calibrator,
    get_raw_scores_and_probs,
)
from common import ARTIFACTS_DIR, REPORTS_DIR, compute_sha256, register_artifact_version  # noqa: E402
from compat import get_environment_metadata  # noqa: E402
from email_model.predict import predict_email  # noqa: E402
from email_model.preprocessing import (  # noqa: E402
    PREPROCESSING_VERSION as EMAIL_PREP_VER,
    EmailHybridFeaturizer,
    extract_email_structured_features,
)
from url_model.feature_extraction import (  # noqa: E402
    PREPROCESSING_VERSION as URL_PREP_VER,
    STRUCTURED_FEATURE_NAMES,
    UrlHybridFeaturizer,
    extract_single_url_features,
)
from url_model.predict import predict_url  # noqa: E402

SPLITS_V2_DIR = os.path.join(ML_ROOT, "datasets", "splits_v2")
DATASET_VERSION = "2.3.0"
RANDOM_SEED = 42


def load_v2_split(task: str, split: str) -> List[Dict[str, Any]]:
    with open(os.path.join(SPLITS_V2_DIR, f"{task}_{split}.json"), "r", encoding="utf-8") as f:
        return json.load(f)["samples"]


def evaluate_predictions(task: str, bundle: Dict[str, Any], test_items: List[Dict[str, Any]], artifact_path: str) -> Dict[str, Any]:
    classes = bundle["classes"]
    y_test = [x["label"] for x in test_items]

    t0 = time.perf_counter()
    X_test = bundle["featurizer"](test_items)
    logits, raw_probs = get_raw_scores_and_probs(bundle["model"], X_test, classes)
    cal_probs = bundle["calibrator"].transform_probs(logits, raw_probs)
    latency_ms = round(((time.perf_counter() - t0) * 1000.0) / max(len(test_items), 1), 4)

    preds = [classes[i] for i in np.argmax(cal_probs, axis=1)]

    acc = accuracy_score(y_test, preds)
    p_mac, r_mac, f1_mac, _ = precision_recall_fscore_support(y_test, preds, average="macro", zero_division=0)
    _, _, f1_wt, _ = precision_recall_fscore_support(y_test, preds, average="weighted", zero_division=0)
    cm = confusion_matrix(y_test, preds, labels=classes).tolist()

    legit_idx = [i for i, y in enumerate(y_test) if y == "legitimate"]
    threat_idx = [i for i, y in enumerate(y_test) if y != "legitimate"]
    fpr = sum(1 for i in legit_idx if preds[i] != "legitimate") / max(len(legit_idx), 1)
    fnr = sum(1 for i in threat_idx if preds[i] == "legitimate") / max(len(threat_idx), 1)

    li = classes.index("legitimate")
    y_bin = np.array([0 if y == "legitimate" else 1 for y in y_test])
    mal_prob = 1.0 - cal_probs[:, li]
    roc_auc = roc_auc_score(y_bin, mal_prob) if len(np.unique(y_bin)) == 2 else None
    pr_auc = average_precision_score(y_bin, mal_prob) if len(np.unique(y_bin)) == 2 else None

    uncal_cal = compute_calibration_metrics(raw_probs, y_test, classes)
    cal_cal = compute_calibration_metrics(cal_probs, y_test, classes)

    # Metrics by source
    by_source = defaultdict(lambda: {"total": 0, "correct": 0, "fp": 0, "fn": 0})
    for i, it in enumerate(test_items):
        src = it.get("source", "unknown")
        by_source[src]["total"] += 1
        if preds[i] == y_test[i]:
            by_source[src]["correct"] += 1
        elif y_test[i] == "legitimate":
            by_source[src]["fp"] += 1
        elif preds[i] == "legitimate":
            by_source[src]["fn"] += 1

    for src, st in by_source.items():
        st["accuracy"] = round(st["correct"] / max(st["total"], 1), 4)

    # Metrics by URL structure (if url)
    by_structure = {}
    if task == "url":
        buckets = defaultdict(lambda: {"total": 0, "correct": 0, "fp": 0, "fn": 0})
        for i, it in enumerate(test_items):
            feats = dict(zip(STRUCTURED_FEATURE_NAMES, extract_single_url_features(it["content"])))
            scheme_k = "https" if feats["is_https"] == 1.0 else "http"
            path_k = "root" if feats["path_length"] <= 1.0 else "nested"
            key = f"{scheme_k}_{path_k}"
            buckets[key]["total"] += 1
            if preds[i] == y_test[i]:
                buckets[key]["correct"] += 1
            elif y_test[i] == "legitimate":
                buckets[key]["fp"] += 1
            elif preds[i] == "legitimate":
                buckets[key]["fn"] += 1
        for k, st in buckets.items():
            st["accuracy"] = round(st["correct"] / max(st["total"], 1), 4)
        by_structure = dict(buckets)

    return {
        "model_version": bundle["model_version"],
        "model_type": bundle["model_type"],
        "calibration_method": bundle["calibrator"].method,
        "test_samples": len(test_items),
        "model_size_mb": round(os.path.getsize(artifact_path) / (1024 * 1024), 4),
        "inference_latency_ms_per_sample": latency_ms,
        "metrics": {
            "accuracy": round(float(acc), 4),
            "macro_precision": round(float(p_mac), 4),
            "macro_recall": round(float(r_mac), 4),
            "macro_f1": round(float(f1_mac), 4),
            "weighted_f1": round(float(f1_wt), 4),
            "roc_auc": round(float(roc_auc), 4) if roc_auc is not None else None,
            "pr_auc": round(float(pr_auc), 4) if pr_auc is not None else None,
            "false_positive_rate": round(float(fpr), 4),
            "false_negative_rate": round(float(fnr), 4),
            "brier_score": cal_cal["brier_score"],
            "ece": cal_cal["ece"],
            "nll": cal_cal["nll"],
        },
        "test_uncalibrated_calibration": uncal_cal,
        "confusion_matrix": {"labels": classes, "matrix": cm},
        "by_source": dict(by_source),
        "by_structure": by_structure,
    }


def train_and_eval_url_v2():
    train_items = load_v2_split("url", "train")
    val_items = load_v2_split("url", "validation")
    test_items = load_v2_split("url", "test")
    y_train = [x["label"] for x in train_items]
    y_val = [x["label"] for x in val_items]

    struct_feat = UrlHybridFeaturizer(use_tfidf=False)
    X_tr_s = struct_feat.fit_transform(train_items)
    X_va_s = struct_feat(val_items)

    hyb_feat = UrlHybridFeaturizer(max_features=4000, use_tfidf=True)
    X_tr_h = hyb_feat.fit_transform(train_items)
    X_va_h = hyb_feat(val_items)

    candidates = []
    for name, clf, feat, X_tr, X_va in [
        ("Structured_LogisticRegression_Baseline", LogisticRegression(C=1.0, class_weight="balanced", max_iter=1000, random_state=RANDOM_SEED), struct_feat, X_tr_s, X_va_s),
        ("Structured_RandomForest", RandomForestClassifier(n_estimators=150, max_depth=14, class_weight="balanced", random_state=RANDOM_SEED, n_jobs=-1), struct_feat, X_tr_s, X_va_s),
        ("Structured_HistGradientBoosting", HistGradientBoostingClassifier(max_iter=150, max_depth=8, random_state=RANDOM_SEED), struct_feat, X_tr_s, X_va_s),
        ("Hybrid_CharTFIDF_Structured_LogisticRegression", LogisticRegression(C=2.0, class_weight="balanced", max_iter=1000, random_state=RANDOM_SEED), hyb_feat, X_tr_h, X_va_h),
    ]:
        t0 = time.perf_counter()
        clf.fit(X_tr, y_train)
        train_sec = round(time.perf_counter() - t0, 3)
        preds = clf.predict(X_va)
        acc = accuracy_score(y_val, preds)
        _, _, f1, _ = precision_recall_fscore_support(y_val, preds, average="macro", zero_division=0)
        legit_i = [i for i, y in enumerate(y_val) if y == "legitimate"]
        fpr = sum(1 for i in legit_i if preds[i] != "legitimate") / max(len(legit_i), 1)
        candidates.append({
            "name": name,
            "model": clf,
            "featurizer": feat,
            "X_val": X_va,
            "train_seconds": train_sec,
            "val_metrics": {"accuracy": round(float(acc), 4), "macro_f1": round(float(f1), 4), "val_fpr": round(float(fpr), 4)},
        })

    # Prefer Hybrid or lowest FPR + high F1 (do not blindly pick tree overfit)
    best = max(candidates, key=lambda c: (round(c["val_metrics"]["macro_f1"], 3), -c["val_metrics"]["val_fpr"], 1 if "Hybrid" in c["name"] else 0))
    classes = list(best["model"].classes_)
    calibrator, cal_report = fit_best_calibrator(best["model"], best["X_val"], y_val, classes)

    version = "url-model-v2.0.0"
    artifact_path = os.path.join(ARTIFACTS_DIR, f"url_model_{version}.joblib")
    bundle = {
        "task": "url",
        "model_version": version,
        "model_type": best["name"],
        "classes": classes,
        "model": best["model"],
        "featurizer": best["featurizer"],
        "calibrator": calibrator,
        "calibration_report": cal_report,
        "dataset_version": DATASET_VERSION,
        "preprocessing_version": URL_PREP_VER,
        "random_seed": RANDOM_SEED,
        "dependencies": get_environment_metadata(),
        "trained_at": datetime.now(timezone.utc).isoformat(),
    }
    joblib.dump(bundle, artifact_path, compress=3)
    reg_entry = register_artifact_version(
        task="url",
        version=version,
        artifact_path=artifact_path,
        dataset_version=DATASET_VERSION,
        preprocessing_version=URL_PREP_VER,
        model_type=best["name"],
        training_config={"seed": RANDOM_SEED, "train_samples": len(train_items), "val_samples": len(val_items)},
        metrics=best["val_metrics"],
        calibration_params=calibrator.to_metadata(),
    )
    test_eval = evaluate_predictions("url", bundle, test_items, artifact_path)

    # Real-world legitimate & malicious URL regression
    rw_urls = [
        ("https://www.irctc.co.in/nget/train-search", "legitimate"),
        ("https://www.irctc.co.in/nget/booking/check-train-schedule?trainNo=12951", "legitimate"),
        ("https://paytm.com/", "legitimate"),
        ("https://secure.paytmpayments.com/theia/api/v1/showPaymentPage?mid=IRCTC123&orderId=ORD998877", "legitimate"),
        ("https://accounts.paytm.com/oauth2/authorize?client_id=paytm-web&redirect_uri=https%3A%2F%2Fpaytm.com%2Fcallback", "legitimate"),
        ("https://www.google.com/search?q=irctc+pnr+status", "legitimate"),
        ("https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=1234&response_type=code", "legitimate"),
        ("https://github.com/login?return_to=%2Fsettings%2Fprofile", "legitimate"),
        ("https://www.amazon.in/ap/signin?openid.pape.max_auth_age=0&openid.return_to=https%3A%2F%2Fwww.amazon.in%2F", "legitimate"),
        ("https://retail.onlinesbi.sbi/retail/login.htm", "legitimate"),
        ("https://netbanking.hdfcbank.com/netbanking/", "legitimate"),
        ("https://api.razorpay.com/v1/checkout/public?key_id=rzp_live_123456", "legitimate"),
        ("https://xn--pypal-4ve.com/signin", "malicious"),
        ("https://paytrn-security.xyz/verify-kyc", "malicious"),
        ("http://192.168.1.10/login.php", "malicious"),
        ("https://paytm-kyc-update-2026.xyz/", "malicious"),
    ]
    rw_results = []
    for u, expected in rw_urls:
        r = predict_url(u, artifact_path=artifact_path)
        rw_results.append({
            "url": u,
            "expected": expected,
            "predicted": r["classification"],
            "risk_score": r["risk_score"],
            "confidence": r["model_confidence"],
            "status": r["status"],
        })

    return {
        "candidates": [{"name": c["name"], "train_seconds": c["train_seconds"], "val_metrics": c["val_metrics"]} for c in candidates],
        "selected": best["name"],
        "calibration_validation": cal_report,
        "test_evaluation": test_eval,
        "regression": rw_results,
        "artifact": reg_entry,
    }


def train_and_eval_email_v2():
    train_items = load_v2_split("email", "train")
    val_items = load_v2_split("email", "validation")
    test_items = load_v2_split("email", "test")
    y_train = [x["label"] for x in train_items]
    y_val = [x["label"] for x in val_items]

    tfidf_only = EmailHybridFeaturizer(max_features=8000, use_structured=False)
    X_tr_t = tfidf_only.fit_transform(train_items)
    X_va_t = tfidf_only(val_items)

    hyb_feat = EmailHybridFeaturizer(max_features=8000, use_structured=True)
    X_tr_h = hyb_feat.fit_transform(train_items)
    X_va_h = hyb_feat(val_items)

    X_tr_s = extract_email_structured_features(train_items)
    X_va_s = extract_email_structured_features(val_items)

    candidates = []
    for name, clf, feat, X_tr, X_va in [
        ("TFIDF_LogisticRegression_Baseline", LogisticRegression(C=2.0, class_weight="balanced", max_iter=1000, random_state=RANDOM_SEED), tfidf_only, X_tr_t, X_va_t),
        ("TFIDF_LinearSVM", SGDClassifier(loss="hinge", alpha=1e-4, class_weight="balanced", max_iter=1000, random_state=RANDOM_SEED), tfidf_only, X_tr_t, X_va_t),
        ("Hybrid_TFIDF_Structured_LogisticRegression", LogisticRegression(C=2.0, class_weight="balanced", max_iter=1000, random_state=RANDOM_SEED), hyb_feat, X_tr_h, X_va_h),
        ("Structured_RandomForest", RandomForestClassifier(n_estimators=150, max_depth=16, class_weight="balanced", random_state=RANDOM_SEED, n_jobs=-1), extract_email_structured_features, X_tr_s, X_va_s),
    ]:
        t0 = time.perf_counter()
        clf.fit(X_tr, y_train)
        train_sec = round(time.perf_counter() - t0, 3)
        preds = clf.predict(X_va)
        acc = accuracy_score(y_val, preds)
        _, _, f1, _ = precision_recall_fscore_support(y_val, preds, average="macro", zero_division=0)
        legit_i = [i for i, y in enumerate(y_val) if y == "legitimate"]
        fpr = sum(1 for i in legit_i if preds[i] != "legitimate") / max(len(legit_i), 1)
        candidates.append({
            "name": name,
            "model": clf,
            "featurizer": feat,
            "X_val": X_va,
            "train_seconds": train_sec,
            "val_metrics": {"accuracy": round(float(acc), 4), "macro_f1": round(float(f1), 4), "val_fpr": round(float(fpr), 4)},
        })

    best = max(candidates, key=lambda c: (c["val_metrics"]["macro_f1"], -c["val_metrics"]["val_fpr"]))
    classes = list(best["model"].classes_)
    calibrator, cal_report = fit_best_calibrator(best["model"], best["X_val"], y_val, classes)

    version = "email-model-v2.0.0"
    artifact_path = os.path.join(ARTIFACTS_DIR, f"email_model_{version}.joblib")
    bundle = {
        "task": "email",
        "model_version": version,
        "model_type": best["name"],
        "classes": classes,
        "model": best["model"],
        "featurizer": best["featurizer"],
        "calibrator": calibrator,
        "calibration_report": cal_report,
        "dataset_version": DATASET_VERSION,
        "preprocessing_version": EMAIL_PREP_VER,
        "random_seed": RANDOM_SEED,
        "dependencies": get_environment_metadata(),
        "trained_at": datetime.now(timezone.utc).isoformat(),
    }
    joblib.dump(bundle, artifact_path, compress=3)
    reg_entry = register_artifact_version(
        task="email",
        version=version,
        artifact_path=artifact_path,
        dataset_version=DATASET_VERSION,
        preprocessing_version=EMAIL_PREP_VER,
        model_type=best["name"],
        training_config={"seed": RANDOM_SEED, "train_samples": len(train_items), "val_samples": len(val_items)},
        metrics=best["val_metrics"],
        calibration_params=calibrator.to_metadata(),
    )
    test_eval = evaluate_predictions("email", bundle, test_items, artifact_path)

    # Hard-negative email checks
    hn_emails = [
        ("Bank Advisory", "Never share your OTP, PIN, or CVV with anyone, even bank officials.", "legitimate"),
        ("Amazon Order", "Your Amazon.in order #402-192831 has been dispatched and will arrive tomorrow.", "legitimate"),
        ("GitHub Security", "A new personal access token was added to your GitHub account.", "legitimate"),
        ("Phishing KYC", "Your SBI account is suspended. Share OTP at http://sbi-kyc-unblock.xyz immediately.", "phishing"),
    ]
    hn_results = []
    for subj, body, expected in hn_emails:
        r = predict_email(subject=subj, body=body, artifact_path=artifact_path)
        hn_results.append({
            "subject": subj,
            "expected": expected,
            "predicted": r["classification"],
            "risk_score": r["risk_score"],
            "confidence": r["model_confidence"],
            "status": r["status"],
        })

    return {
        "candidates": [{"name": c["name"], "train_seconds": c["train_seconds"], "val_metrics": c["val_metrics"]} for c in candidates],
        "selected": best["name"],
        "calibration_validation": cal_report,
        "test_evaluation": test_eval,
        "hard_negative_checks": hn_results,
        "artifact": reg_entry,
    }


def main():
    url_res = train_and_eval_url_v2()
    email_res = train_and_eval_email_v2()
    out = {"dataset_version": DATASET_VERSION, "url_v2": url_res, "email_v2": email_res}
    out_path = os.path.join(REPORTS_DIR, "phase2_v2_evaluation.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2)
    print(f"[OK] URL v2.0.0 ({url_res['selected']}): acc={url_res['test_evaluation']['metrics']['accuracy']}, fpr={url_res['test_evaluation']['metrics']['false_positive_rate']:.2%}, fnr={url_res['test_evaluation']['metrics']['false_negative_rate']:.2%}")
    print(f"[OK] Email v2.0.0 ({email_res['selected']}): acc={email_res['test_evaluation']['metrics']['accuracy']}, fpr={email_res['test_evaluation']['metrics']['false_positive_rate']:.2%}, fnr={email_res['test_evaluation']['metrics']['false_negative_rate']:.2%}")


if __name__ == "__main__":
    main()
