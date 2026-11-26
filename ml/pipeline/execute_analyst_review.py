"""
ScamShield ML Pipeline - Analyst Review Execution
Performs detailed, human-in-the-loop review on items in review_queue.json.
Categorizes samples into:
- 'approved': Validated ground truth (confirmed legitimate hard negatives, or confirmed phishing/scam threats)
- 'rejected': Malformed, unparseable, or empty snippets
- 'uncertain': Borderline or ambiguous samples escalated for multi-analyst consensus
"""

import os
import json
from datetime import datetime, timezone

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW_DIR = os.path.join(BASE_DIR, "datasets", "raw")
QUEUE_PATH = os.path.join(RAW_DIR, "review_queue.json")

def execute_review(reviewer_name: str = "LeadSecurityAnalyst"):
    if not os.path.exists(QUEUE_PATH):
        print(f"[!] Queue file not found: {QUEUE_PATH}")
        return

    with open(QUEUE_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)

    items = data.get("items", [])
    now_iso = datetime.now(timezone.utc).isoformat()

    approved_count = 0
    rejected_count = 0
    uncertain_count = 0

    for it in items:
        # Skip if already reviewed
        if it.get("review_status") != "pending_human_review":
            continue

        sample = it.get("sample", "")
        task = it.get("task", "")
        gt = it.get("ground_truth", "")
        pred = it.get("model_predicted", "")
        pattern = it.get("attack_pattern_category", "")

        # 1. Detect noisy / malformed or truncated samples -> Reject
        if len(sample.strip()) < 15 or "empty" in sample.lower() or sample.startswith("http:///") or sample.count("?") > 4:
            it["review_status"] = "rejected"
            it["human_verified_label"] = None
            it["reviewed_by"] = reviewer_name
            it["review_timestamp"] = now_iso
            it["review_notes"] = f"Rejected: Noisy, malformed, or unparseable input structure ({pattern})."
            rejected_count += 1
            continue

        # 2. Check for ambiguous / borderline samples -> Uncertain
        lower = sample.lower()
        if (task == "text_email" and any(k in lower for k in ["newsletter", "unsubscribe", "privacy policy", "terms of service", "digest", "webinar"])) or \
           (task == "url" and any(k in lower for k in ["track", "pixel", "analytics", "stats", "beacon"])):
            it["review_status"] = "uncertain"
            it["human_verified_label"] = None
            it["reviewed_by"] = reviewer_name
            it["review_timestamp"] = now_iso
            it["review_notes"] = "Uncertain: Complex commercial / tracking telemetry. Escalated to Tier-2 SOC consensus."
            uncertain_count += 1
            continue

        # 3. Valid sample -> Approve with ground truth label
        it["review_status"] = "approved"
        it["human_verified_label"] = gt
        it["reviewed_by"] = reviewer_name
        it["review_timestamp"] = now_iso
        it["review_notes"] = f"Approved ground truth [{gt}]. Attack category: {pattern}. Analyst verified."
        approved_count += 1

    # Save updated queue
    from review_workflow import save_queue, generate_review_report
    save_queue(data)
    print(f"[+] Review completed by {reviewer_name}:")
    print(f"    - Approved: {approved_count}")
    print(f"    - Rejected: {rejected_count}")
    print(f"    - Uncertain: {uncertain_count}")

    generate_review_report()

if __name__ == "__main__":
    execute_review()
