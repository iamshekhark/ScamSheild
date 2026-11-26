"""
ScamShield ML Pipeline - Data Quality Analyzer
Audits raw and ingested datasets for:
- Exact duplicate samples
- Near-duplicate samples (Jaccard similarity on 3-character n-grams)
- Conflicting labels on identical or near-identical inputs
- Missing / malformed values
- Label validity against schema
- Class distribution and imbalance ratios
- Provenance and source distribution
Outputs:
- ml/reports/data_quality_report.json
- ml/reports/data_quality_report.md
"""

import os
import json
import re
import unicodedata
from urllib.parse import urlparse
from collections import Counter, defaultdict
from datetime import datetime, timezone

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW_DIR = os.path.join(BASE_DIR, "datasets", "raw")
EXTERNAL_DIR = os.path.join(RAW_DIR, "external")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
os.makedirs(REPORTS_DIR, exist_ok=True)

VALID_LABELS = {
    "url": {"phishing", "malicious", "suspicious", "legitimate"},
    "text_email": {"scam", "phishing", "spam", "legitimate"},
    "payment": {"fraudulent", "suspicious", "legitimate"}
}

def normalize_text(text: str) -> str:
    if not isinstance(text, str):
        return ""
    text = unicodedata.normalize("NFKC", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text

def normalize_url(url: str) -> str:
    if not isinstance(url, str):
        return ""
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    try:
        parsed = urlparse(url)
        netloc = parsed.netloc.lower()
        path = parsed.path or "/"
        query = ("?" + parsed.query) if parsed.query else ""
        return f"{parsed.scheme.lower()}://{netloc}{path}{query}"
    except Exception:
        return url.lower()

def char_ngrams(s: str, n: int = 3) -> set:
    s = s.lower()
    return {s[i:i+n] for i in range(len(s) - n + 1)} if len(s) >= n else {s}

def jaccard(set1: set, set2: set) -> float:
    if not set1 or not set2:
        return 0.0
    return len(set1 & set2) / len(set1 | set2)

def analyze_task_data(task_name: str, records: list) -> dict:
    total_records = len(records)
    valid_labels = VALID_LABELS[task_name]
    
    seen_exact = {}
    duplicates_count = 0
    conflicts = []
    malformed_count = 0
    invalid_label_count = 0
    clean_records = []
    
    class_dist = Counter()
    source_dist = Counter()
    
    for r in records:
        source = r.get("source", "unknown")
        source_dist[source] += 1
        
        # Check label
        raw_label = r.get("label", "").strip().lower()
        # Normalize legacy payment labels if applicable
        label_aliases = {
            "fraudulent_request": "fraudulent",
            "fraudulent payment request": "fraudulent",
            "suspicious_request": "suspicious",
            "suspicious payment request": "suspicious",
            "legitimate_request": "legitimate",
            "legitimate payment request": "legitimate"
        }
        label = label_aliases.get(raw_label, raw_label)
        if label not in valid_labels:
            invalid_label_count += 1
            continue
            
        # Get content
        if task_name == "url":
            content = r.get("url", "")
            norm_content = normalize_url(content)
        elif task_name == "payment":
            vpa = r.get("vpa", "").strip().lower()
            note = r.get("note", "").strip()
            amount = str(r.get("amount", 0))
            content = f"{vpa} | {amount} | {note}"
            norm_content = normalize_text(content)
        else:
            content = r.get("text", "")
            norm_content = normalize_text(content)
            
        if not norm_content:
            malformed_count += 1
            continue
            
        if norm_content in seen_exact:
            duplicates_count += 1
            existing_label = seen_exact[norm_content]
            if existing_label != label:
                conflicts.append({
                    "sample": norm_content[:120],
                    "labels": [existing_label, label],
                    "source": source
                })
            continue
            
        seen_exact[norm_content] = label
        class_dist[label] += 1
        clean_records.append({**r, "normalized_content": norm_content, "label": label})

    # Near duplicate detection on a sampled subset if large
    near_duplicates_sample = []
    sample_for_near_dup = clean_records[:1500]  # sample first 1500 for pairwise n-gram comparison
    ngram_cache = [(i, char_ngrams(rec["normalized_content"]), rec["label"], rec["normalized_content"]) for i, rec in enumerate(sample_for_near_dup)]
    
    for i in range(len(ngram_cache)):
        if len(near_duplicates_sample) >= 20:
            break
        for j in range(i + 1, min(i + 40, len(ngram_cache))):
            sim = jaccard(ngram_cache[i][1], ngram_cache[j][1])
            if 0.82 < sim < 0.999:
                near_duplicates_sample.append({
                    "sample_a": ngram_cache[i][3][:80],
                    "sample_b": ngram_cache[j][3][:80],
                    "similarity": round(sim, 3),
                    "label_a": ngram_cache[i][2],
                    "label_b": ngram_cache[j][2]
                })
                break

    # Imbalance ratio
    max_count = max(class_dist.values()) if class_dist else 0
    min_count = min(class_dist.values()) if class_dist else 0
    imbalance_ratio = round(max_count / min_count, 2) if min_count > 0 else 0.0

    return {
        "task": task_name,
        "total_input_records": total_records,
        "clean_records_count": len(clean_records),
        "exact_duplicates_removed": duplicates_count,
        "conflicting_labels_detected": len(conflicts),
        "conflicts": conflicts[:10],
        "malformed_or_empty": malformed_count,
        "invalid_labels": invalid_label_count,
        "class_distribution": dict(class_dist),
        "imbalance_ratio_max_to_min": imbalance_ratio,
        "source_distribution": dict(source_dist),
        "near_duplicate_examples": near_duplicates_sample
    }

def main():
    print("=" * 70)
    print("ScamShield ML Pipeline - Data Quality Audit")
    print("=" * 70)

    # 1. URL Datasets
    url_records = []
    # Existing raw
    with open(os.path.join(RAW_DIR, "urls_raw.json"), "r", encoding="utf-8") as f:
        url_records.extend(json.load(f))
    # Staged external
    for fn in ["phishing_urls.json", "legitimate_urls.json"]:
        path = os.path.join(EXTERNAL_DIR, fn)
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                url_records.extend(json.load(f))

    # 2. Text / Email Datasets
    text_records = []
    with open(os.path.join(RAW_DIR, "text_email_raw.json"), "r", encoding="utf-8") as f:
        text_records.extend(json.load(f))
    for fn in ["sms_samples.json", "email_samples.json", "curated_threats.json"]:
        path = os.path.join(EXTERNAL_DIR, fn)
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                text_records.extend(json.load(f))

    # 3. Payment Datasets
    payment_records = []
    with open(os.path.join(RAW_DIR, "payments_raw.json"), "r", encoding="utf-8") as f:
        payment_records.extend(json.load(f))
    path = os.path.join(EXTERNAL_DIR, "curated_payments.json")
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            payment_records.extend(json.load(f))

    # Load verified samples if present
    verified_path = os.path.join(RAW_DIR, "verified_samples.json")
    if os.path.exists(verified_path):
        with open(verified_path, "r", encoding="utf-8") as f:
            v_samples = json.load(f)
            for v in v_samples:
                t = v.get("task")
                if t == "url":
                    url_records.append(v)
                elif t == "text_email":
                    text_records.append({"text": v.get("content", ""), "label": v.get("label", ""), "source": v.get("source", "verified_review")})
                elif t == "payment":
                    payment_records.append({"content": v.get("content", ""), "label": v.get("label", ""), "source": v.get("source", "verified_review")})

    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tasks": {
            "url": analyze_task_data("url", url_records),
            "text_email": analyze_task_data("text_email", text_records),
            "payment": analyze_task_data("payment", payment_records)
        }
    }

    # Save JSON report
    json_path = os.path.join(REPORTS_DIR, "data_quality_report.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(f"[+] Data quality report written to {json_path}")

    # Generate Markdown Report
    md_path = os.path.join(REPORTS_DIR, "data_quality_report.md")
    with open(md_path, "w", encoding="utf-8") as f:
        f.write("# ScamShield Dataset Quality Audit Report\n\n")
        f.write(f"**Audit Generated:** {report['timestamp']}\n\n")
        f.write("## 1. Executive Summary\n\n")
        f.write("| Task | Raw Records | Clean Deduplicated | Duplicates Removed | Conflicts | Max:Min Imbalance |\n")
        f.write("|---|---:|---:|---:|---:|---:|\n")
        for task, data in report["tasks"].items():
            f.write(f"| **{task.upper()}** | {data['total_input_records']} | {data['clean_records_count']} | {data['exact_duplicates_removed']} | {data['conflicting_labels_detected']} | {data['imbalance_ratio_max_to_min']}:1 |\n")
        
        f.write("\n## 2. Per-Task Class Distributions\n\n")
        for task, data in report["tasks"].items():
            f.write(f"### {task.upper()} Classification\n")
            f.write("```json\n" + json.dumps(data["class_distribution"], indent=2) + "\n```\n")
            f.write(f"- **Data Sources:** {json.dumps(data['source_distribution'])}\n")
            f.write(f"- **Near-Duplicate Patterns Detected:** {len(data['near_duplicate_examples'])}\n\n")

    print(f"[+] Markdown summary written to {md_path}")
    print("=" * 70)

if __name__ == "__main__":
    main()
