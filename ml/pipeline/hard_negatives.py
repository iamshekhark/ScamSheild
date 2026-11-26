"""
ScamShield ML Pipeline - Hard-Negative Mining & Human Review Workflow
Analyzes false positives and false negatives from trained models.
Groups errors by attack pattern / failure mode, generates a structured review queue,
and provides a safe promotion path requiring human verification before samples
can be admitted into the verified training set.
"""

import os
import json
import re
from datetime import datetime, timezone
from typing import Dict, Any, List

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW_DIR = os.path.join(BASE_DIR, "datasets", "raw")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
STAGING_PATH = os.path.join(RAW_DIR, "mined_errors_staging.json")
QUEUE_PATH = os.path.join(RAW_DIR, "review_queue.json")
VERIFIED_SAMPLES_PATH = os.path.join(RAW_DIR, "verified_samples.json")
REPORT_PATH = os.path.join(REPORTS_DIR, "hard_negatives_report.md")


def categorize_url_error(url: str, error_type: str) -> str:
    lower = url.lower()
    if re.search(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", lower):
        return "ip_address_host"
    if "xn--" in lower:
        return "punycode_homograph"
    if any(k in lower for k in ["login", "signin", "account", "verify", "secure", "update", "banking", "kyc"]):
        return "auth_keyword_lure"
    if any(k in lower for k in ["paypal", "apple", "google", "microsoft", "sbi", "hdfc", "amazon"]):
        return "brand_impersonation"
    if any(tld in lower for tld in [".top", ".xyz", ".club", ".work", ".cfd", ".click", ".buzz"]):
        return "suspicious_tld"
    if lower.count(".") > 4:
        return "deep_subdomain_obfuscation"
    return "general_lexical_divergence"


def categorize_text_error(text: str, error_type: str) -> str:
    lower = text.lower()
    if any(k in lower for k in ["cbi", "police", "customs", "arrest", "warrant", "trai", "court"]):
        return "authority_and_arrest_extortion"
    if any(k in lower for k in ["otp", "password", "pin", "cvv", "kyc", "pan", "aadhaar"]):
        return "credential_and_otp_harvesting"
    if any(k in lower for k in ["win", "prize", "jackpot", "lottery", "cashback", "reward", "crore"]):
        return "financial_reward_lure"
    if any(k in lower for k in ["job", "salary", "telegram", "review", "work from home", "earn"]):
        return "part_time_task_fraud"
    if any(k in lower for k in ["power", "electricity", "bill", "disconnect"]):
        return "utility_disconnection_urgency"
    return "general_semantic_divergence"


def categorize_payment_error(vpa_note: str, error_type: str) -> str:
    lower = vpa_note.lower()
    if "refund" in lower or "cashback" in lower:
        return "reverse_collect_refund_lure"
    if "qr" in lower:
        return "qr_code_scam"
    if any(k in lower for k in ["cbi", "arrest", "bail", "vault"]):
        return "extortion_deposit"
    return "vpa_pattern_divergence"


def build_review_queue():
    if not os.path.exists(STAGING_PATH):
        print(f"[!] Staged errors file not found: {STAGING_PATH}")
        return

    with open(STAGING_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)

    fps = data.get("false_positives", {})
    fns = data.get("false_negatives", {})

    queue = []
    item_id = 1
    pattern_stats = {}

    for task, items in fps.items():
        pattern_stats.setdefault(task, {})
        for it in items:
            sample = it["sample"]
            if task == "url":
                pat = categorize_url_error(sample, "false_positive")
            elif task == "text_email":
                pat = categorize_text_error(sample, "false_positive")
            else:
                pat = categorize_payment_error(sample, "false_positive")

            pattern_stats[task][pat] = pattern_stats[task].get(pat, 0) + 1
            queue.append({
                "id": f"rev_{task}_{item_id:04d}",
                "task": task,
                "sample": sample,
                "ground_truth": it["true_label"],
                "model_predicted": it["predicted_label"],
                "confidence": it["confidence"],
                "error_type": "false_positive",
                "attack_pattern_category": pat,
                "probabilities": it.get("probabilities", {}),
                "review_status": "pending_human_review",
                "human_verified_label": None,
                "reviewed_by": None,
                "review_timestamp": None,
                "review_notes": ""
            })
            item_id += 1

    for task, items in fns.items():
        pattern_stats.setdefault(task, {})
        for it in items:
            sample = it["sample"]
            if task == "url":
                pat = categorize_url_error(sample, "false_negative")
            elif task == "text_email":
                pat = categorize_text_error(sample, "false_negative")
            else:
                pat = categorize_payment_error(sample, "false_negative")

            pattern_stats[task][pat] = pattern_stats[task].get(pat, 0) + 1
            queue.append({
                "id": f"rev_{task}_{item_id:04d}",
                "task": task,
                "sample": sample,
                "ground_truth": it["true_label"],
                "model_predicted": it["predicted_label"],
                "confidence": it["confidence"],
                "error_type": "false_negative",
                "attack_pattern_category": pat,
                "probabilities": it.get("probabilities", {}),
                "review_status": "pending_human_review",
                "human_verified_label": None,
                "reviewed_by": None,
                "review_timestamp": None,
                "review_notes": ""
            })
            item_id += 1

    with open(QUEUE_PATH, "w", encoding="utf-8") as f:
        json.dump({
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_items": len(queue),
            "pending_count": len(queue),
            "approved_count": 0,
            "rejected_count": 0,
            "items": queue
        }, f, indent=2)

    print(f"[+] Human review queue saved ({len(queue)} items) to {QUEUE_PATH}")

    # Generate Markdown Report
    with open(REPORT_PATH, "w", encoding="utf-8") as f:
        f.write("# ScamShield ML Hard-Negative Mining & Error Analysis\n\n")
        f.write(f"**Generated:** {datetime.now(timezone.utc).isoformat()}\n\n")
        f.write("## 1. Overview\n\n")
        f.write("Hard-negative mining systematically collects samples where candidate models disagreed with ground truth, ")
        f.write("categorizes failure modes into attack patterns, and enforces human-in-the-loop review before any sample ")
        f.write("can be promoted into the verified training set. **Unreviewed model predictions are never automatically treated as ground truth.**\n\n")

        f.write("## 2. Summary by Task\n\n")
        f.write("| Task | False Positives | False Negatives | Total Review Items |\n|---|---:|---:|---:|\n")
        for task in ["url", "text_email", "payment"]:
            fp_cnt = len(fps.get(task, []))
            fn_cnt = len(fns.get(task, []))
            f.write(f"| **{task.upper()}** | {fp_cnt} | {fn_cnt} | {fp_cnt + fn_cnt} |\n")

        f.write("\n## 3. Discovered Error Patterns by Attack Category\n\n")
        for task, p_dict in pattern_stats.items():
            f.write(f"### {task.upper()} Error Breakdown\n\n")
            f.write("| Attack Pattern Category | Sample Count |\n|---|---:|\n")
            for cat, cnt in sorted(p_dict.items(), key=lambda x: x[1], reverse=True):
                f.write(f"| `{cat}` | {cnt} |\n")
            f.write("\n")

        f.write("## 4. Human Verification Protocol\n\n")
        f.write("To admit samples into `verified_samples.json`:\n")
        f.write("1. Open `ml/datasets/raw/review_queue.json`.\n")
        f.write("2. Inspect each pending item.\n")
        f.write("3. Set `review_status: 'approved'`, provide `human_verified_label`, and assign `reviewed_by`.\n")
        f.write("4. Execute `py ml/pipeline/hard_negatives.py --ingest-approved`.\n")

    print(f"[+] Hard-negatives report written to {REPORT_PATH}")


def ingest_approved_samples():
    if not os.path.exists(QUEUE_PATH):
        print(f"[!] Queue file not found: {QUEUE_PATH}")
        return

    with open(QUEUE_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)

    approved = [it for it in data.get("items", []) if it.get("review_status") == "approved" and it.get("human_verified_label")]
    if not approved:
        print("[*] No approved samples found in review queue.")
        return

    verified_existing = []
    if os.path.exists(VERIFIED_SAMPLES_PATH):
        with open(VERIFIED_SAMPLES_PATH, "r", encoding="utf-8") as f:
            verified_existing = json.load(f)

    seen = {v["sample"]: v for v in verified_existing if "sample" in v}
    added = 0
    for it in approved:
        sample_key = it["sample"]
        if sample_key not in seen:
            verified_existing.append({
                "sample": sample_key,
                "task": it["task"],
                "label": it["human_verified_label"],
                "reviewed_by": it.get("reviewed_by", "security_engineer"),
                "reviewed_at": datetime.now(timezone.utc).isoformat(),
                "notes": it.get("review_notes", "Admitted via hard-negative human review queue")
            })
            added += 1

    with open(VERIFIED_SAMPLES_PATH, "w", encoding="utf-8") as f:
        json.dump(verified_existing, f, indent=2)

    print(f"[+] Successfully merged {added} human-verified samples into {VERIFIED_SAMPLES_PATH}.")


def main():
    import sys
    if "--ingest-approved" in sys.argv:
        ingest_approved_samples()
    else:
        build_review_queue()


if __name__ == "__main__":
    main()
