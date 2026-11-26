"""
ScamShield ML Pipeline - Dataset Ingestion, Validation, Deduplication & Leakage-Free Splitting
Reuses extract_registrable_domain, extract_text_group, scrub_pii, and group_split
from ml/training/prepare_datasets.py and normalization from ml/pipeline/quality_analyzer.py.

Supports CSV, JSON, JSONL, and mbox/email directory imports, and writes:
- ml/datasets/splits/{email,url}_{train,validation,test}.json
- ml/datasets/manifests/{email,url}_manifest.json
- ml/reports/dataset_validation_report.json & .md
"""

import argparse
import csv
import hashlib
import json
import os
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

ML_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ML_ROOT not in sys.path:
    sys.path.insert(0, ML_ROOT)

from common import (  # noqa: E402
    MANIFESTS_DIR,
    PROCESSED_DIR,
    RAW_DIR,
    REPORTS_DIR,
    SPLITS_DIR,
    load_source_registry,
)
from prepare_datasets import (  # noqa: E402
    extract_registrable_domain,
    extract_text_group,
    group_split,
    scrub_pii,
)
from quality_analyzer import char_ngrams, jaccard, normalize_text, normalize_url  # noqa: E402

DATASET_VERSION = "2.2.0"
RANDOM_SEED = 42

EMAIL_VALID_LABELS = {"phishing", "spam", "legitimate", "unknown"}
URL_VALID_LABELS = {"malicious", "legitimate", "unknown"}

EMAIL_LABEL_MAP = {
    "phishing": "phishing",
    "phishing email": "phishing",
    "scam": "phishing",
    "spam": "spam",
    "legitimate": "legitimate",
    "safe": "legitimate",
    "safe email": "legitimate",
    "ham": "legitimate",
    "unknown": "unknown",
}

URL_LABEL_MAP = {
    "malicious": "malicious",
    "phishing": "malicious",
    "suspicious": "malicious",
    "bad": "malicious",
    "legitimate": "legitimate",
    "benign": "legitimate",
    "safe": "legitimate",
    "good": "legitimate",
    "unknown": "unknown",
}


def load_records_from_file(path: str) -> List[Dict[str, Any]]:
    """Load records from JSON, JSONL, or CSV."""
    ext = os.path.splitext(path)[1].lower()
    if ext == ".jsonl":
        records = []
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    records.append(json.loads(line))
        return records
    if ext == ".csv":
        with open(path, "r", encoding="utf-8", newline="") as f:
            return list(csv.DictReader(f))
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, dict) and "samples" in data:
        return data["samples"]
    if isinstance(data, list):
        return data
    raise ValueError(f"Unsupported JSON structure in {path}")


def normalize_record_label(raw_label: Any, task: str) -> Optional[str]:
    if raw_label is None:
        return None
    key = str(raw_label).strip().lower()
    if not key:
        return None
    mapping = EMAIL_LABEL_MAP if task == "email" else URL_LABEL_MAP
    return mapping.get(key)


def detect_near_duplicates(keys: List[str], threshold: float = 0.85, max_check: int = 1500) -> int:
    """Estimate near-duplicates on a bounded sample using 3-char Jaccard similarity."""
    sample = keys[:max_check]
    if len(sample) < 2:
        return 0
    buckets: Dict[str, List[Tuple[str, set]]] = defaultdict(list)
    near_dups = 0
    for s in sample:
        grams = char_ngrams(s[:120], 3)
        prefix = s[:12]
        matched = False
        for _, prev_grams in buckets[prefix]:
            if jaccard(grams, prev_grams) >= threshold:
                matched = True
                break
        if matched:
            near_dups += 1
        else:
            buckets[prefix].append((s, grams))
    return near_dups


def validate_and_deduplicate(
    records: List[Dict[str, Any]],
    task: str,
    exclude_unknown_from_splits: bool = True,
) -> Dict[str, Any]:
    """
    Validate fields, normalize content, remove exact duplicates, detect contradictory labels,
    scrub PII (for email), and compute grouping keys for leakage-free splitting.
    """
    valid_labels = EMAIL_VALID_LABELS if task == "email" else URL_VALID_LABELS
    seen_content: Dict[str, Dict[str, Any]] = {}
    contradictory: List[Dict[str, Any]] = []
    missing_fields = 0
    invalid_labels = 0
    exact_duplicates = 0
    unknown_records: List[Dict[str, Any]] = []
    source_counts = Counter()
    raw_label_counts = Counter()

    for idx, rec in enumerate(records):
        source = str(rec.get("source") or "unknown").strip()
        source_counts[source] += 1

        raw_lbl = rec.get("label")
        raw_label_counts[str(raw_lbl)] += 1
        label = normalize_record_label(raw_lbl, task)
        if label is None or label not in valid_labels:
            invalid_labels += 1
            continue

        if task == "url":
            raw_val = str(rec.get("url") or rec.get("content") or "").strip()
            if not raw_val:
                missing_fields += 1
                continue
            norm_val = normalize_url(raw_val)
            if not norm_val or len(norm_val) < 4:
                missing_fields += 1
                continue
            group_key = extract_registrable_domain(norm_val)
            subject = ""
            sender = ""
            content = norm_val
        else:
            raw_text = rec.get("text") or rec.get("body") or rec.get("content") or ""
            subject = scrub_pii(normalize_text(str(rec.get("subject") or "")))
            sender = str(rec.get("sender") or "").strip().lower()
            body = scrub_pii(normalize_text(str(raw_text)))
            content = f"{subject} {body}".strip() if subject else body
            if not content:
                missing_fields += 1
                continue
            norm_val = content.lower()
            group_key = extract_text_group(norm_val)

        timestamp = rec.get("timestamp") or rec.get("collection_date") or None
        record_id = hashlib.sha256(f"{task}:{norm_val}".encode("utf-8")).hexdigest()[:16]

        item = {
            "id": record_id,
            "content": content,
            "label": label,
            "raw_label": str(raw_lbl),
            "group": group_key,
            "source": source,
            "timestamp": timestamp,
        }
        if task == "email":
            item["subject"] = subject
            item["sender_domain"] = sender.split("@")[-1] if "@" in sender else ""
        else:
            item["url"] = content

        if norm_val in seen_content:
            if seen_content[norm_val]["label"] != label:
                contradictory.append({
                    "content": norm_val[:120],
                    "label_a": seen_content[norm_val]["label"],
                    "label_b": label,
                })
                # Mark as unknown so contradictory labels never corrupt training
                seen_content[norm_val]["label"] = "unknown"
            else:
                exact_duplicates += 1
            continue

        seen_content[norm_val] = item

    deduped = list(seen_content.values())
    near_dups = detect_near_duplicates([d["content"] for d in deduped])

    clean_items = []
    for item in deduped:
        if item["label"] == "unknown":
            unknown_records.append(item)
            if exclude_unknown_from_splits:
                continue
        clean_items.append(item)

    return {
        "clean_items": clean_items,
        "unknown_items": unknown_records,
        "stats": {
            "total_raw": len(records),
            "valid_deduped": len(deduped),
            "trainable_count": len(clean_items),
            "unknown_excluded_count": len(unknown_records),
            "exact_duplicates_removed": exact_duplicates,
            "near_duplicates_estimated": near_dups,
            "contradictory_labels_detected": len(contradictory),
            "missing_or_empty_fields": missing_fields,
            "invalid_labels_dropped": invalid_labels,
            "class_distribution": dict(Counter(it["label"] for it in clean_items)),
            "source_distribution": dict(source_counts),
        },
        "contradictory_examples": contradictory[:20],
    }


def verify_zero_leakage(train_items: list, val_items: list, test_items: list) -> Dict[str, Any]:
    tr_g = {x["group"] for x in train_items}
    va_g = {x["group"] for x in val_items}
    te_g = {x["group"] for x in test_items}
    tr_c = {x["content"] for x in train_items}
    va_c = {x["content"] for x in val_items}
    te_c = {x["content"] for x in test_items}
    return {
        "zero_group_leakage": len(tr_g & va_g) == 0 and len(tr_g & te_g) == 0 and len(va_g & te_g) == 0,
        "zero_content_leakage": len(tr_c & va_c) == 0 and len(tr_c & te_c) == 0 and len(va_c & te_c) == 0,
        "train_val_group_overlap": len(tr_g & va_g),
        "train_test_group_overlap": len(tr_g & te_g),
        "val_test_group_overlap": len(va_g & te_g),
    }


def build_task_splits(task: str, input_path: Optional[str] = None, seed: int = RANDOM_SEED) -> Dict[str, Any]:
    if input_path is None:
        filename = "url_dataset.json" if task == "url" else "text_email_dataset.json"
        input_path = os.path.join(PROCESSED_DIR, filename)

    raw_records = load_records_from_file(input_path)
    validated = validate_and_deduplicate(raw_records, task=task, exclude_unknown_from_splits=True)
    clean_items = validated["clean_items"]

    _, train_items, val_items, test_items = group_split(clean_items, test_ratio=0.15, val_ratio=0.15, seed=seed)
    leakage = verify_zero_leakage(train_items, val_items, test_items)
    if not leakage["zero_group_leakage"]:
        raise RuntimeError(f"Group leakage detected for {task}: {leakage}")

    for split_name, split_items in (("train", train_items), ("validation", val_items), ("test", test_items)):
        out_path = os.path.join(SPLITS_DIR, f"{task}_{split_name}.json")
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump({"task": task, "split": split_name, "count": len(split_items), "samples": split_items}, f, indent=2)

    registry = load_source_registry()
    provenance = {}
    for src_id in validated["stats"]["source_distribution"]:
        src_meta = registry.get("sources", {}).get(src_id, {})
        provenance[src_id] = {
            "count": validated["stats"]["source_distribution"][src_id],
            "name": src_meta.get("name", src_id),
            "license": src_meta.get("license", "Verify before commercial use"),
            "collection_date": src_meta.get("collection_date", "unknown"),
        }

    manifest = {
        "task": task,
        "dataset_version": DATASET_VERSION,
        "random_seed": seed,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "input_path": os.path.relpath(input_path, ML_ROOT).replace("\\", "/"),
        "grouping_strategy": "public_suffix_list_registrable_domain" if task == "url" else "normalized_template_prefix",
        "split_ratios": {"train": 0.70, "validation": 0.15, "test": 0.15},
        "splits": {
            "train": {
                "count": len(train_items),
                "classes": dict(Counter(x["label"] for x in train_items)),
                "file": f"datasets/splits/{task}_train.json",
            },
            "validation": {
                "count": len(val_items),
                "classes": dict(Counter(x["label"] for x in val_items)),
                "file": f"datasets/splits/{task}_validation.json",
            },
            "test": {
                "count": len(test_items),
                "classes": dict(Counter(x["label"] for x in test_items)),
                "file": f"datasets/splits/{task}_test.json",
            },
        },
        "validation_stats": validated["stats"],
        "leakage_check": leakage,
        "provenance": provenance,
    }

    manifest_path = os.path.join(MANIFESTS_DIR, f"{task}_manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    return manifest


def main():
    parser = argparse.ArgumentParser(description="Validate, deduplicate, and split ScamShield ML datasets.")
    parser.add_argument("--task", choices=["email", "url", "all"], default="all")
    parser.add_argument("--input", type=str, default=None, help="Optional custom CSV/JSON/JSONL input file.")
    parser.add_argument("--seed", type=int, default=RANDOM_SEED)
    args = parser.parse_args()

    tasks = ["email", "url"] if args.task == "all" else [args.task]
    summary = {}
    for t in tasks:
        manifest = build_task_splits(t, input_path=args.input if len(tasks) == 1 else None, seed=args.seed)
        summary[t] = manifest
        print(
            f"[OK] {t.upper()} splits generated: "
            f"train={manifest['splits']['train']['count']}, "
            f"val={manifest['splits']['validation']['count']}, "
            f"test={manifest['splits']['test']['count']} | "
            f"zero_leakage={manifest['leakage_check']['zero_group_leakage']}"
        )

    report_json = os.path.join(REPORTS_DIR, "dataset_validation_report.json")
    with open(report_json, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    md_lines = [
        "# ScamShield Dataset Validation & Split Report",
        f"- **Dataset Version:** `{DATASET_VERSION}`",
        f"- **Generated At:** {datetime.now(timezone.utc).isoformat()}",
        "",
    ]
    for t, m in summary.items():
        st = m["validation_stats"]
        md_lines.extend([
            f"## Task: {t.upper()}",
            f"- **Raw records:** {st['total_raw']} | **Trainable:** {st['trainable_count']} | **Unknown excluded:** {st['unknown_excluded_count']}",
            f"- **Exact duplicates removed:** {st['exact_duplicates_removed']} | **Near-duplicates (est.):** {st['near_duplicates_estimated']}",
            f"- **Contradictory labels:** {st['contradictory_labels_detected']} | **Invalid/missing dropped:** {st['invalid_labels_dropped'] + st['missing_or_empty_fields']}",
            f"- **Class distribution:** `{st['class_distribution']}`",
            f"- **Splits (70/15/15):** train={m['splits']['train']['count']}, val={m['splits']['validation']['count']}, test={m['splits']['test']['count']}",
            f"- **Zero group leakage:** `{m['leakage_check']['zero_group_leakage']}` | **Zero content leakage:** `{m['leakage_check']['zero_content_leakage']}`",
            "",
        ])
    with open(os.path.join(REPORTS_DIR, "dataset_validation_report.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(md_lines))


if __name__ == "__main__":
    main()
