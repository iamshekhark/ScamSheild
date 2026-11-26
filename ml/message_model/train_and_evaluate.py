"""
ScamShield Track B — Message Scam Detection Training & Evaluation
Trains and benchmarks SMS / WhatsApp / general message classifiers on
ml/datasets/splits_v4/message_{train,validation,test}.json (3 distinct classes:
legitimate, spam, phishing). Computes 95% Wilson upper confidence bound on FPR.
"""

import json
import math
import os
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List

import joblib
import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression, SGDClassifier
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    precision_recall_fscore_support,
)

ML_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ML_ROOT not in sys.path:
    sys.path.insert(0, ML_ROOT)

from calibration.calibrate import compute_calibration_metrics, fit_best_calibrator, get_raw_scores_and_probs  # noqa: E402
from common import ARTIFACTS_DIR, RAW_DIR, REPORTS_DIR, register_artifact_version  # noqa: E402
from message_model.features import MessageHybridFeaturizer, extract_message_structured_features  # noqa: E402
from prepare_datasets import extract_text_group, group_split, scrub_pii  # noqa: E402
from quality_analyzer import normalize_text  # noqa: E402

SPLITS_V4_DIR = os.path.join(ML_ROOT, "datasets", "splits_v4")
os.makedirs(SPLITS_V4_DIR, exist_ok=True)
RANDOM_SEED = 42

CURATED_MESSAGE_HARD_NEGATIVES = [
    # Legitimate bank, OTP, transaction, delivery, personal, business
    {"text": "HDFC Bank: Your A/C XX4821 is debited INR 1,250.00 on 26-11-2026 via UPI Ref 426819284712. Avl Bal INR 42,100.50.", "label": "legitimate", "category": "legit_transaction_alert"},
    {"text": "SBI: 482910 is your OTP for netbanking login. NEVER share your OTP or PIN with anyone, even bank staff.", "label": "legitimate", "category": "legit_otp_message"},
    {"text": "Your Amazon.in package #402-192831 is out for delivery today. Share delivery PIN 4921 only at doorstep.", "label": "legitimate", "category": "legit_delivery"},
    {"text": "Hi, are we still meeting at 4 PM near the metro station? Let me know.", "label": "legitimate", "category": "legit_personal"},
    {"text": "Team reminder: Sprint review moved to 11:00 AM tomorrow in Conference Room B.", "label": "legitimate", "category": "legit_business"},
    {"text": "Paytm Security Advisory: Never enter your UPI PIN to receive cashback or refunds.", "label": "legitimate", "category": "legit_bank_notification"},
    # Malicious phishing & UPI/refund/support/impersonation/urgency scams
    {"text": "Paytm Wallet suspended! Share your 6-digit OTP at http://paytrn-kyc.xyz/verify within 2 hours.", "label": "phishing", "category": "phishing_message"},
    {"text": "Enter your UPI PIN on this collect request to receive Rs 2,500 cashback refund from PhonePe.", "label": "phishing", "category": "upi_payment_scam"},
    {"text": "Flipkart Support: Your refund Rs 1,999 failed. Send Rs 1 verification to refund-desk@ybl to release amount.", "label": "phishing", "category": "fake_refund_scam"},
    {"text": "Customer Care Alert: Install AnyDesk and call +919876543210 to unblock your frozen SBI account.", "label": "phishing", "category": "fake_support_scam"},
    {"text": "URGENT: Your KYC expired today. Update PAN immediately at https://hdfc-kyc-update.top/auth", "label": "phishing", "category": "account_suspension_scam"},
]


def wilson_upper_bound(k: int, n: int, z: float = 1.96) -> float:
    if n == 0:
        return 1.0
    p = k / n
    denom = 1.0 + (z * z) / n
    center = p + (z * z) / (2.0 * n)
    margin = z * math.sqrt((p * (1.0 - p) + (z * z) / (4.0 * n)) / n)
    return round(min(1.0, (center + margin) / denom), 4)


def run_message_track():
    ext_dir = os.path.join(RAW_DIR, "external")
    with open(os.path.join(ext_dir, "sms_samples.json"), "r", encoding="utf-8") as f:
        sms_raw = json.load(f)
    with open(os.path.join(ext_dir, "curated_threats.json"), "r", encoding="utf-8") as f:
        threats_raw = json.load(f)
    with open(os.path.join(RAW_DIR, "verified_samples.json"), "r", encoding="utf-8") as f:
        verified_raw = json.load(f)

    records: List[Dict[str, Any]] = []
    for x in sms_raw:
        txt = scrub_pii(normalize_text(str(x.get("text") or "")))
        lbl = x.get("label", "").lower()
        if txt and lbl in ("legitimate", "spam", "phishing"):
            records.append({"content": txt, "label": lbl, "group": extract_text_group(txt), "source": "uci_sms_spam"})

    for x in threats_raw:
        txt = scrub_pii(normalize_text(str(x.get("text") or "")))
        lbl = "phishing" if x.get("label") in ("scam", "phishing") else "spam"
        if txt:
            records.append({"content": txt, "label": lbl, "group": extract_text_group(txt), "source": "cert_in_i4c_curated"})

    for x in verified_raw:
        if x.get("task") == "text_email":
            txt = scrub_pii(normalize_text(str(x.get("content") or "")))
            raw_lbl = str(x.get("label") or "").lower()
            lbl = "phishing" if raw_lbl in ("scam", "phishing") else ("spam" if raw_lbl == "spam" else "legitimate")
            if txt:
                records.append({"content": txt, "label": lbl, "group": extract_text_group(txt), "source": "verified_review"})

    for x in CURATED_MESSAGE_HARD_NEGATIVES:
        txt = scrub_pii(normalize_text(x["text"]))
        records.append({"content": txt, "label": x["label"], "group": extract_text_group(txt), "source": "scamshield_message_curated"})

    seen = set()
    deduped = []
    for r in records:
        if r["content"] not in seen:
            seen.add(r["content"])
            deduped.append(r)

    _, train_items, val_items, test_items = group_split(deduped, test_ratio=0.15, val_ratio=0.15, seed=RANDOM_SEED)
    for sp, items in (("train", train_items), ("validation", val_items), ("test", test_items)):
        with open(os.path.join(SPLITS_V4_DIR, f"message_{sp}.json"), "w", encoding="utf-8") as f:
            json.dump({"task": "message", "split": sp, "count": len(items), "samples": items}, f, indent=2)

    y_tr = [x["label"] for x in train_items]
    y_va = [x["label"] for x in val_items]
    y_te = [x["label"] for x in test_items]

    hyb = MessageHybridFeaturizer()
    X_tr_h = hyb.fit_transform(train_items)
    X_va_h = hyb(val_items)

    X_tr_s = extract_message_structured_features([x["content"] for x in train_items])
    X_va_s = extract_message_structured_features([x["content"] for x in val_items])

    candidates = []
    for name, clf, feat, Xtr, Xva in [
        ("Hybrid_WordCharTFIDF_Structured_LR", LogisticRegression(C=2.0, class_weight="balanced", max_iter=1000, random_state=RANDOM_SEED), hyb, X_tr_h, X_va_h),
        ("Hybrid_WordCharTFIDF_Structured_LinearSVM", SGDClassifier(loss="hinge", alpha=1e-4, class_weight="balanced", max_iter=1000, random_state=RANDOM_SEED), hyb, X_tr_h, X_va_h),
        ("Structured_HistGradientBoosting", HistGradientBoostingClassifier(max_iter=120, max_depth=8, random_state=RANDOM_SEED), extract_message_structured_features, X_tr_s, X_va_s),
    ]:
        t0 = time.perf_counter()
        clf.fit(Xtr, y_tr)
        train_s = round(time.perf_counter() - t0, 3)
        pv = clf.predict(Xva)
        _, _, f1v, _ = precision_recall_fscore_support(y_va, pv, average="macro", zero_division=0)
        legit_i = [i for i, y in enumerate(y_va) if y == "legitimate"]
        fpr_v = sum(1 for i in legit_i if pv[i] != "legitimate") / max(len(legit_i), 1)
        candidates.append({
            "name": name,
            "model": clf,
            "featurizer": feat,
            "X_val": Xva,
            "train_seconds": train_s,
            "val_metrics": {"accuracy": round(float(accuracy_score(y_va, pv)), 4), "macro_f1": round(float(f1v), 4), "val_fpr": round(float(fpr_v), 4)},
        })

    best = max(candidates, key=lambda c: (c["val_metrics"]["macro_f1"], -c["val_metrics"]["val_fpr"]))
    classes = list(best["model"].classes_)
    calibrator, cal_report = fit_best_calibrator(best["model"], best["X_val"], y_va, classes)

    version = "message-model-v1.0.0"
    art_path = os.path.join(ARTIFACTS_DIR, f"message_model_{version}.joblib")
    bundle = {
        "task": "message",
        "model_version": version,
        "model_type": best["name"],
        "classes": classes,
        "model": best["model"],
        "featurizer": best["featurizer"],
        "calibrator": calibrator,
        "trained_at": datetime.now(timezone.utc).isoformat(),
    }
    joblib.dump(bundle, art_path, compress=3)
    reg = register_artifact_version(
        task="message",
        version=version,
        artifact_path=art_path,
        dataset_version="4.0.0-alpha",
        preprocessing_version="msg-prep-v1.0.0",
        model_type=best["name"],
        training_config={"seed": RANDOM_SEED, "train": len(train_items), "val": len(val_items), "test": len(test_items)},
        metrics=best["val_metrics"],
        calibration_params=calibrator.to_metadata(),
    )

    t0 = time.perf_counter()
    X_te = best["featurizer"](test_items) if best["featurizer"] is hyb else extract_message_structured_features([x["content"] for x in test_items])
    logits_te, raw_te = get_raw_scores_and_probs(best["model"], X_te, classes)
    probs_te = calibrator.transform_probs(logits_te, raw_te)
    lat_ms = round(((time.perf_counter() - t0) * 1000.0) / max(len(test_items), 1), 4)
    preds_te = [classes[i] for i in np.argmax(probs_te, axis=1)]

    p_mac, r_mac, f1_mac, _ = precision_recall_fscore_support(y_te, preds_te, average="macro", zero_division=0)
    p_cls, r_cls, f1_cls, sup_cls = precision_recall_fscore_support(y_te, preds_te, labels=classes, zero_division=0)

    legit_i = [i for i, y in enumerate(y_te) if y == "legitimate"]
    threat_i = [i for i, y in enumerate(y_te) if y != "legitimate"]
    fp_cnt = sum(1 for i in legit_i if preds_te[i] != "legitimate")
    fn_cnt = sum(1 for i in threat_i if preds_te[i] == "legitimate")
    fpr = fp_cnt / max(len(legit_i), 1)
    fnr = fn_cnt / max(len(threat_i), 1)
    fpr_ucb95 = wilson_upper_bound(fp_cnt, len(legit_i))

    li = classes.index("legitimate")
    y_bin = np.array([0 if y == "legitimate" else 1 for y in y_te])
    pr_auc = round(float(average_precision_score(y_bin, 1.0 - probs_te[:, li])), 4) if len(np.unique(y_bin)) == 2 else None

    summary = {
        "splits": {"train": len(train_items), "val": len(val_items), "test": len(test_items), "classes": dict(Counter(x["label"] for x in deduped))},
        "candidates": [{"name": c["name"], "train_seconds": c["train_seconds"], "val_metrics": c["val_metrics"]} for c in candidates],
        "selected": best["name"],
        "calibration_val": cal_report["selected_method"],
        "test_metrics": {
            "accuracy": round(float(accuracy_score(y_te, preds_te)), 4),
            "macro_precision": round(float(p_mac), 4),
            "macro_recall": round(float(r_mac), 4),
            "macro_f1": round(float(f1_mac), 4),
            "pr_auc": pr_auc,
            "fpr": round(float(fpr), 4),
            "fpr_95_upper_bound": fpr_ucb95,
            "fp_count": fp_cnt,
            "legit_test_count": len(legit_i),
            "fnr": round(float(fnr), 4),
            "latency_ms_per_sample": lat_ms,
            "model_size_mb": round(os.path.getsize(art_path) / (1024 * 1024), 4),
            "per_class": {
                c: {"precision": round(float(p_cls[i]), 4), "recall": round(float(r_cls[i]), 4), "f1": round(float(f1_cls[i]), 4), "support": int(sup_cls[i])}
                for i, c in enumerate(classes)
            },
            "confusion_matrix": {"labels": classes, "matrix": confusion_matrix(y_te, preds_te, labels=classes).tolist()},
            "calibration": compute_calibration_metrics(probs_te, y_te, classes),
        },
        "artifact": reg,
    }
    with open(os.path.join(REPORTS_DIR, "phase4_message_eval.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
    print(f"[OK] Message Track B: test_acc={summary['test_metrics']['accuracy']}, test_f1={summary['test_metrics']['macro_f1']}, fpr={summary['test_metrics']['fpr']:.2%} (95% UCB={fpr_ucb95:.2%})")


if __name__ == "__main__":
    run_message_track()
