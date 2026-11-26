"""
ScamShield ML Pipeline - Human Review Workflow
Audits, manages, and executes reviewer decisions on the hard-negative review queue.
Supports:
- Viewing sample details, model prediction vs ground truth, confidence, attack pattern.
- Recording reviewer decisions: 'approve', 'reject', 'uncertain'.
- Logging reviewer ID, timestamp, and analyst notes.
- Ingesting approved samples into verified_samples.json with strict deduplication.
- Preserving all metadata without auto-labeling model predictions as ground truth.
- Generating human review status reports (JSON and Markdown).
"""

import os
import sys
import json
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from collections import Counter

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW_DIR = os.path.join(BASE_DIR, "datasets", "raw")
QUEUE_PATH = os.path.join(RAW_DIR, "review_queue.json")
VERIFIED_PATH = os.path.join(RAW_DIR, "verified_samples.json")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
REPORT_JSON = os.path.join(REPORTS_DIR, "human_review_status_report.json")
REPORT_MD = os.path.join(REPORTS_DIR, "human_review_status_report.md")

os.makedirs(REPORTS_DIR, exist_ok=True)


def load_queue() -> Dict[str, Any]:
    if not os.path.exists(QUEUE_PATH):
        return {"generated_at": datetime.now(timezone.utc).isoformat(), "total_items": 0, "items": []}
    with open(QUEUE_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def save_queue(queue_data: Dict[str, Any]):
    items = queue_data.get("items", [])
    counts = Counter(it.get("review_status", "pending_human_review") for it in items)
    queue_data["total_items"] = len(items)
    queue_data["pending_count"] = counts.get("pending_human_review", 0)
    queue_data["approved_count"] = counts.get("approved", 0)
    queue_data["rejected_count"] = counts.get("rejected", 0)
    queue_data["uncertain_count"] = counts.get("uncertain", 0)
    queue_data["updated_at"] = datetime.now(timezone.utc).isoformat()

    with open(QUEUE_PATH, "w", encoding="utf-8") as f:
        json.dump(queue_data, f, indent=2)


def get_queue_summary() -> Dict[str, Any]:
    q = load_queue()
    items = q.get("items", [])
    task_counts = {}
    status_counts = Counter()

    for it in items:
        t = it.get("task", "unknown")
        s = it.get("review_status", "pending_human_review")
        task_counts.setdefault(t, Counter())[s] += 1
        status_counts[s] += 1

    return {
        "total_items": len(items),
        "status_distribution": dict(status_counts),
        "task_breakdown": {t: dict(c) for t, c in task_counts.items()}
    }


def record_review_decision(
    item_id: str,
    decision: str,
    verified_label: Optional[str] = None,
    reviewer: str = "SecurityAnalyst",
    notes: str = ""
) -> bool:
    valid_decisions = {"approved", "rejected", "uncertain", "pending_human_review"}
    if decision not in valid_decisions:
        raise ValueError(f"Invalid decision: {decision}. Must be one of {valid_decisions}")

    q = load_queue()
    target = None
    for it in q.get("items", []):
        if it.get("id") == item_id:
            target = it
            break

    if not target:
        print(f"[!] Item {item_id} not found in review queue.")
        return False

    target["review_status"] = decision
    target["human_verified_label"] = verified_label if verified_label else (target["ground_truth"] if decision == "approved" else None)
    target["reviewed_by"] = reviewer
    target["review_timestamp"] = datetime.now(timezone.utc).isoformat()
    target["review_notes"] = notes or f"Decision [{decision}] recorded by {reviewer}"

    save_queue(q)
    print(f"[+] Item {item_id} marked as [{decision}] by {reviewer}.")
    return True


def ingest_approved_samples() -> int:
    """Ingests only 'approved' samples into verified_samples.json with deduplication."""
    q = load_queue()
    approved = [
        it for it in q.get("items", [])
        if it.get("review_status") == "approved" and it.get("human_verified_label")
    ]

    if not approved:
        print("[*] No approved samples found to ingest.")
        return 0

    verified_existing = []
    if os.path.exists(VERIFIED_PATH):
        with open(VERIFIED_PATH, "r", encoding="utf-8") as f:
            verified_existing = json.load(f)

    seen_samples = {it.get("content") or it.get("sample"): it for it in verified_existing}
    added_count = 0

    for it in approved:
        content_key = it.get("sample")
        if content_key and content_key not in seen_samples:
            new_entry = {
                "id": f"verified_{it['task']}_{len(verified_existing) + 1:04d}",
                "task": it["task"],
                "content": content_key,
                "label": it["human_verified_label"],
                "source": "human_review_queue",
                "category": it.get("attack_pattern_category", "HARD_NEGATIVE_AUDIT"),
                "reviewer": it.get("reviewed_by", "SecurityAnalyst"),
                "reviewed_at": it.get("review_timestamp") or datetime.now(timezone.utc).isoformat(),
                "description": it.get("review_notes", "Verified via analyst review queue")
            }
            verified_existing.append(new_entry)
            seen_samples[content_key] = new_entry
            added_count += 1

    with open(VERIFIED_PATH, "w", encoding="utf-8") as f:
        json.dump(verified_existing, f, indent=2)

    print(f"[+] Successfully merged {added_count} approved samples into {VERIFIED_PATH}.")
    return added_count


def generate_review_report() -> Dict[str, Any]:
    summary = get_queue_summary()
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_items": summary["total_items"],
        "status_distribution": summary["status_distribution"],
        "task_breakdown": summary["task_breakdown"]
    }

    with open(REPORT_JSON, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    with open(REPORT_MD, "w", encoding="utf-8") as f:
        f.write("# ScamShield Human Review Status Report\n\n")
        f.write(f"**Generated:** {report['generated_at']}\n\n")
        f.write("## 1. Summary of Human Review Queue\n\n")
        f.write(f"- **Total Review Queue Items:** {report['total_items']}\n")
        f.write(f"- **Pending Inspection:** {report['status_distribution'].get('pending_human_review', 0)}\n")
        f.write(f"- **Approved (Verified Ground Truth):** {report['status_distribution'].get('approved', 0)}\n")
        f.write(f"- **Rejected (Discarded / Corrupt):** {report['status_distribution'].get('rejected', 0)}\n")
        f.write(f"- **Uncertain (Escalated to Tier-2 SOC):** {report['status_distribution'].get('uncertain', 0)}\n\n")

        f.write("## 2. Breakdown by Classification Task\n\n")
        f.write("| Task | Pending | Approved | Rejected | Uncertain | Total |\n|---|---:|---:|---:|---:|---:|\n")
        for task, s_dict in report["task_breakdown"].items():
            p = s_dict.get("pending_human_review", 0)
            a = s_dict.get("approved", 0)
            r = s_dict.get("rejected", 0)
            u = s_dict.get("uncertain", 0)
            f.write(f"| **{task.upper()}** | {p} | {a} | {r} | {u} | {p + a + r + u} |\n")

    print(f"[+] Review status report written to {REPORT_JSON} and {REPORT_MD}")
    return report


def main():
    import argparse
    parser = argparse.ArgumentParser(description="ScamShield Human Review Queue Workflow")
    parser.add_argument("--summary", action="store_true", help="Print summary counts of review queue")
    parser.add_argument("--report", action="store_true", help="Generate JSON and Markdown status reports")
    parser.add_argument("--ingest", action="store_true", help="Ingest approved samples into verified_samples.json")
    parser.add_argument("--item", type=str, help="Item ID to review")
    parser.add_argument("--decision", type=str, choices=["approved", "rejected", "uncertain", "pending_human_review"], help="Decision")
    parser.add_argument("--label", type=str, help="Human verified label")
    parser.add_argument("--reviewer", type=str, default="SeniorAnalyst", help="Reviewer identity")
    parser.add_argument("--notes", type=str, default="", help="Review notes")

    args = parser.parse_args()

    if args.item and args.decision:
        record_review_decision(args.item, args.decision, args.label, args.reviewer, args.notes)
        generate_review_report()
    elif args.ingest:
        ingest_approved_samples()
        generate_review_report()
    elif args.report:
        generate_review_report()
    else:
        summary = get_queue_summary()
        print(json.dumps(summary, indent=2))
        generate_review_report()


if __name__ == "__main__":
    main()
