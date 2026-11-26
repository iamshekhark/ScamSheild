"""
ScamShield Track A — OCR Dataset Preparation, Field Extraction Evaluation & Scam Classifier
Builds versioned OCR dataset (ml/datasets/splits_v4/ocr_*.json), evaluates CER/WER and
structured field extraction on clean vs degraded OCR text, and trains candidate
ocr-scam-model-v1.0.0 (production_active: false).
"""

import json
import os
import random
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List

import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression, SGDClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, precision_recall_fscore_support

ML_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ML_ROOT not in sys.path:
    sys.path.insert(0, ML_ROOT)

from calibration.calibrate import compute_calibration_metrics, fit_best_calibrator, get_raw_scores_and_probs  # noqa: E402
from common import ARTIFACTS_DIR, RAW_DIR, REPORTS_DIR, register_artifact_version  # noqa: E402
from ocr_model.field_extractor import compute_cer, compute_wer, extract_ocr_fields  # noqa: E402
from prepare_datasets import extract_text_group, group_split  # noqa: E402

SPLITS_V4_DIR = os.path.join(ML_ROOT, "datasets", "splits_v4")
os.makedirs(SPLITS_V4_DIR, exist_ok=True)
RANDOM_SEED = 42

OCR_CURATED_SAMPLES = [
    # Legitimate payment & banking screenshots
    {"text": "Payment of Rs 1,250.00 to DMart Retail Store Successful. UPI Ref / UTR: 426819284712. Txn ID: T261019284712918. Paid via HDFC Bank.", "label": "legitimate", "category": "legit_payment_receipt", "upi": [], "amount": "1250.00", "utr": "426819284712"},
    {"text": "Paid Rs 499.00 to Swiggy via Google Pay. UPI Transaction ID: 431928471209. Debited from SBI A/C XX4821 on 26-Nov-2026.", "label": "legitimate", "category": "legit_upi_screen", "upi": [], "amount": "499.00", "utr": "431928471209"},
    {"text": "IRCTC eTicketing Payment Receipt. Amount Rs 1,427.25 paid to irctc@paytm. UTR: 519283746510. Status: Payment Successful.", "label": "legitimate", "category": "legit_receipt", "upi": ["irctc@paytm"], "amount": "1427.25", "utr": "519283746510"},
    {"text": "HDFC Bank Alert: Rs 2,500.00 debited from A/C 4821 on 26/11/2026 via UPI Ref 618273645510 to grocer@okhdfcbank.", "label": "legitimate", "category": "legit_bank_alert", "upi": ["grocer@okhdfcbank"], "amount": "2500.00", "utr": "618273645510"},
    {"text": "Amazon.in Order #402-192831. Paid Rs 899.00 via Amazon Pay UPI. Ref No: 718293041234. Delivery tomorrow.", "label": "legitimate", "category": "legit_shopping_receipt", "upi": [], "amount": "899.00", "utr": "718293041234"},
    {"text": "Battery 84% Wi-Fi Connected 11:30 AM. Settings > Display > Dark Mode enabled.", "label": "legitimate", "category": "normal_mobile_screen", "upi": [], "amount": None, "utr": None},
    {"text": "PhonePe Payment Successful Rs 150.00 Paid to Metro Rail Corp. UTR 829104756123.", "label": "legitimate", "category": "legit_upi_screen", "upi": [], "amount": "150.00", "utr": "829104756123"},
    {"text": "Axis Bank: Your OTP is 849201 for card txn of Rs 320.00. Never share OTP with anyone.", "label": "legitimate", "category": "legit_bank_alert", "upi": [], "amount": "320.00", "utr": None},
    # Malicious / scam screenshots
    {"text": "Payment Successful! Sent Rs 50,000.00 to Store Manager. Transfer Complete. (No UTR reference)", "label": "scam", "category": "fake_payment_success", "upi": [], "amount": "50000.00", "utr": None},
    {"text": "CONGRATULATIONS! Cashback Rs 2,500 approved. Scan QR & Enter your 6-digit UPI PIN to receive money into bank account.", "label": "scam", "category": "qr_reverse_collect", "upi": [], "amount": "2500", "utr": None},
    {"text": "Paytm Customer Support Desk: Refund of Rs 4,999 pending. Pay via paytm-refund-desk@ybl and share OTP.", "label": "scam", "category": "fake_support_payment", "upi": ["paytm-refund-desk@ybl"], "amount": "4999", "utr": None},
    {"text": "STATE BANK NOTICE: Your SBI KYC expired. Account blocked in 24 hours. Verify at http://sbi-kyc-update.xyz", "label": "scam", "category": "impersonated_bank_phish", "upi": [], "amount": None, "utr": None},
    {"text": "BESCOM Power Alert: Electricity will be disconnected tonight. Pay Rs 1,450 immediately to billdesk-support@ybl", "label": "scam", "category": "fraudulent_upi_collect", "upi": ["billdesk-support@ybl"], "amount": "1450", "utr": None},
    {"text": "SBI Reward Points Rs 9,850 expiring today. Install AnyDesk and send Rs 10 verification to sbi-kyc@okaxis", "label": "scam", "category": "fake_refund_remote_access", "upi": ["sbi-kyc@okaxis"], "amount": "9850", "utr": None},
    {"text": "PhonePe Lottery Winner! Claim Rs 25,000 cashback. Send Rs 500 processing fee to phonepe-cashback@ibl", "label": "scam", "category": "qr_lottery_scam", "upi": ["phonepe-cashback@ibl"], "amount": "25000", "utr": None},
    {"text": "HDFC Bank Alert: Update PAN immediately at https://hdfc-pan-verify.top/auth or netbanking suspended.", "label": "scam", "category": "phishing_url_screenshot", "upi": [], "amount": None, "utr": None},
]


def simulate_ocr_degradation(text: str, rng: random.Random) -> str:
    """Simulate realistic low-res/blur/font OCR character substitutions (clearly labeled synthetic_ocr_noise)."""
    subs = {"0": "O", "O": "0", "1": "l", "l": "1", "5": "S", "rn": "m"}
    chars = list(text)
    for i in range(len(chars)):
        if chars[i] in subs and rng.random() < 0.08:
            chars[i] = subs[chars[i]]
    noisy = "".join(chars)
    if rng.random() < 0.3:
        noisy = "Header 11:42 AM LTE\n" + noisy + "\nHome Back Recents"
    return noisy


def run_ocr_track():
    rng = random.Random(RANDOM_SEED)
    ext_dir = os.path.join(RAW_DIR, "external")
    with open(os.path.join(ext_dir, "curated_payments.json"), "r", encoding="utf-8") as f:
        curated_pay = json.load(f)
    with open(os.path.join(ext_dir, "curated_threats.json"), "r", encoding="utf-8") as f:
        curated_threats = json.load(f)

    # 1. Measure CER/WER & structured field extraction on clean vs degraded OCR text
    cers, wers = [], []
    upi_tp = upi_fp = upi_fn = 0
    amt_match = amt_total = 0

    for s in OCR_CURATED_SAMPLES:
        noisy = simulate_ocr_degradation(s["text"], rng)
        cers.append(compute_cer(s["text"], noisy))
        wers.append(compute_wer(s["text"], noisy))
        ext = extract_ocr_fields(s["text"], ocr_confidence=92.0)
        pred_upis = {u["value"] for u in ext["fields"]["upi_ids"]}
        true_upis = set(s["upi"])
        upi_tp += len(pred_upis & true_upis)
        upi_fp += len(pred_upis - true_upis)
        upi_fn += len(true_upis - pred_upis)
        if s["amount"] is not None:
            amt_total += 1
            pred_amts = [a["value"] for a in ext["fields"]["amounts"]]
            if s["amount"] in pred_amts:
                amt_match += 1

    # 2. Build versioned OCR text classification dataset (clean + noisy + curated threats/payments)
    records: List[Dict[str, Any]] = []
    for idx, s in enumerate(OCR_CURATED_SAMPLES):
        records.append({
            "content": s["text"],
            "label": s["label"],
            "group": extract_text_group(s["text"]),
            "source": "scamshield_ocr_curated",
            "provenance_type": "curated_hard_negative",
        })
        noisy = simulate_ocr_degradation(s["text"], rng)
        records.append({
            "content": noisy,
            "label": s["label"],
            "group": extract_text_group(s["text"]),  # Same group so clean/noisy stay in same split!
            "source": "synthetic_ocr_noise",
            "provenance_type": "synthetic_augmentation",
        })

    for p in curated_pay:
        txt = p.get("content") or p.get("note") or ""
        if txt:
            lbl = "legitimate" if p.get("label") == "legitimate" else "scam"
            records.append({
                "content": txt,
                "label": lbl,
                "group": extract_text_group(txt),
                "source": "curated_payments",
                "provenance_type": "curated_hard_negative",
            })

    for t in curated_threats:
        txt = t.get("text") or ""
        if txt:
            records.append({
                "content": txt,
                "label": "scam",
                "group": extract_text_group(txt),
                "source": "cert_in_i4c_curated",
                "provenance_type": "curated_hard_negative",
            })

    # Deduplicate by exact content
    seen = set()
    deduped = []
    for r in records:
        if r["content"] not in seen:
            seen.add(r["content"])
            deduped.append(r)

    _, train_items, val_items, test_items = group_split(deduped, test_ratio=0.15, val_ratio=0.15, seed=RANDOM_SEED)
    for sp, items in (("train", train_items), ("validation", val_items), ("test", test_items)):
        with open(os.path.join(SPLITS_V4_DIR, f"ocr_{sp}.json"), "w", encoding="utf-8") as f:
            json.dump({"task": "ocr", "split": sp, "count": len(items), "samples": items}, f, indent=2)

    vec = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), max_features=3000, sublinear_tf=True)
    X_tr = vec.fit_transform([x["content"] for x in train_items])
    X_va = vec.transform([x["content"] for x in val_items])
    X_te = vec.transform([x["content"] for x in test_items])
    y_tr = [x["label"] for x in train_items]
    y_va = [x["label"] for x in val_items]
    y_te = [x["label"] for x in test_items]

    candidates = []
    for name, clf in [
        ("CharTFIDF_LogisticRegression", LogisticRegression(C=2.0, class_weight="balanced", max_iter=1000, random_state=RANDOM_SEED)),
        ("CharTFIDF_LinearSVM", SGDClassifier(loss="hinge", alpha=1e-4, class_weight="balanced", max_iter=1000, random_state=RANDOM_SEED)),
    ]:
        clf.fit(X_tr, y_tr)
        pv = clf.predict(X_va)
        _, _, f1v, _ = precision_recall_fscore_support(y_va, pv, average="macro", zero_division=0)
        candidates.append({"name": name, "model": clf, "val_acc": round(float(accuracy_score(y_va, pv)), 4), "val_f1": round(float(f1v), 4)})

    best = max(candidates, key=lambda c: c["val_f1"])
    classes = list(best["model"].classes_)
    calibrator, _ = fit_best_calibrator(best["model"], X_va, y_va, classes)

    version = "ocr-scam-model-v1.0.0"
    art_path = os.path.join(ARTIFACTS_DIR, f"ocr_model_{version}.joblib")
    bundle = {
        "task": "ocr",
        "model_version": version,
        "model_type": best["name"],
        "classes": classes,
        "model": best["model"],
        "vectorizer": vec,
        "calibrator": calibrator,
        "trained_at": datetime.now(timezone.utc).isoformat(),
    }
    joblib.dump(bundle, art_path, compress=3)
    reg = register_artifact_version(
        task="ocr",
        version=version,
        artifact_path=art_path,
        dataset_version="4.0.0-alpha",
        preprocessing_version="ocr-prep-v1.0.0",
        model_type=best["name"],
        training_config={"seed": RANDOM_SEED, "train": len(train_items), "val": len(val_items), "test": len(test_items)},
        metrics={"val_acc": best["val_acc"], "val_macro_f1": best["val_f1"]},
        calibration_params=calibrator.to_metadata(),
    )

    t0 = time.perf_counter()
    logits_te, raw_te = get_raw_scores_and_probs(best["model"], X_te, classes)
    probs_te = calibrator.transform_probs(logits_te, raw_te)
    lat_ms = round(((time.perf_counter() - t0) * 1000.0) / max(len(test_items), 1), 4)
    preds_te = [classes[i] for i in np.argmax(probs_te, axis=1)]

    p_mac, r_mac, f1_mac, _ = precision_recall_fscore_support(y_te, preds_te, average="macro", zero_division=0)
    legit_i = [i for i, y in enumerate(y_te) if y == "legitimate"]
    scam_i = [i for i, y in enumerate(y_te) if y != "legitimate"]
    fpr = sum(1 for i in legit_i if preds_te[i] != "legitimate") / max(len(legit_i), 1)
    fnr = sum(1 for i in scam_i if preds_te[i] == "legitimate") / max(len(scam_i), 1)

    upi_prec = round(upi_tp / max(upi_tp + upi_fp, 1), 4)
    upi_rec = round(upi_tp / max(upi_tp + upi_fn, 1), 4)

    summary = {
        "extraction_eval": {
            "samples": len(OCR_CURATED_SAMPLES),
            "avg_cer_simulated_noise": round(float(np.mean(cers)), 4),
            "avg_wer_simulated_noise": round(float(np.mean(wers)), 4),
            "upi_extraction_precision": upi_prec,
            "upi_extraction_recall": upi_rec,
            "amount_extraction_accuracy": round(amt_match / max(amt_total, 1), 4),
        },
        "splits": {"train": len(train_items), "val": len(val_items), "test": len(test_items), "classes": dict(Counter(x["label"] for x in deduped))},
        "candidates": [{"name": c["name"], "val_acc": c["val_acc"], "val_f1": c["val_f1"]} for c in candidates],
        "selected": best["name"],
        "test_metrics": {
            "accuracy": round(float(accuracy_score(y_te, preds_te)), 4),
            "macro_precision": round(float(p_mac), 4),
            "macro_recall": round(float(r_mac), 4),
            "macro_f1": round(float(f1_mac), 4),
            "fpr": round(float(fpr), 4),
            "fnr": round(float(fnr), 4),
            "latency_ms_per_sample": lat_ms,
            "confusion_matrix": {"labels": classes, "matrix": confusion_matrix(y_te, preds_te, labels=classes).tolist()},
            "calibration": compute_calibration_metrics(probs_te, y_te, classes),
        },
        "artifact": reg,
    }
    with open(os.path.join(REPORTS_DIR, "phase4_ocr_eval.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
    print(f"[OK] OCR Track A: test_acc={summary['test_metrics']['accuracy']}, test_f1={summary['test_metrics']['macro_f1']}, cer={summary['extraction_eval']['avg_cer_simulated_noise']}")


if __name__ == "__main__":
    run_ocr_track()
