"""
ScamShield ML Pipeline - Dataset Preparation & Public Suffix List Group-Aware Splitting
Strictly implements:
- Public Suffix List-aware registrable domain extraction (RFC 6265)
- Documented grouping fallback (IPv4/IPv6, localhost, single labels)
- Zero data leakage: groups partitioned 100% disjointly between train and test
- Schema compatibility: samples[] array, metadata.split_info, standard CSVs
- Ingestion and normalization of human-reviewed verified samples
- Synchronized dataset_manifest.json
"""

import os
import json
import csv
import re
import unicodedata
from urllib.parse import urlparse
from collections import Counter
import numpy as np

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW_DIR = os.path.join(BASE_DIR, "datasets", "raw")
EXTERNAL_DIR = os.path.join(RAW_DIR, "external")
PROCESSED_DIR = os.path.join(BASE_DIR, "datasets", "processed")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
VERIFIED_PATH = os.path.join(RAW_DIR, "verified_samples.json")

os.makedirs(PROCESSED_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)

RANDOM_SEED = 42

# Public Suffix List multi-part ccTLDs and common hosted service suffixes (RFC 6265)
PUBLIC_SUFFIXES = {
    # United Kingdom
    "co.uk", "org.uk", "gov.uk", "ac.uk", "net.uk", "me.uk", "ltd.uk", "plc.uk", "sch.uk",
    # India
    "co.in", "net.in", "org.in", "gen.in", "ind.in", "firm.in", "gov.in", "mil.in", "ac.in", "edu.in", "res.in",
    # Australia
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "asn.au", "id.au",
    # New Zealand
    "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz", "geek.nz", "school.nz",
    # South Africa
    "co.za", "org.za", "net.za", "gov.za", "ac.za", "web.za",
    # Japan
    "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp", "ed.jp", "lg.jp",
    # Brazil
    "com.br", "net.br", "org.br", "gov.br", "edu.br", "art.br", "inf.br",
    # Singapore
    "com.sg", "edu.sg", "gov.sg", "net.sg", "org.sg", "per.sg",
    # Mexico
    "com.mx", "gob.mx", "edu.mx", "net.mx", "org.mx",
    # China
    "com.cn", "net.cn", "gov.cn", "org.cn", "edu.cn", "ah.cn", "bj.cn",
    # Hong Kong
    "com.hk", "org.hk", "gov.hk", "edu.hk", "net.hk", "idv.hk",
    # Taiwan
    "com.tw", "org.tw", "gov.tw", "edu.tw", "net.tw", "idv.tw",
    # South Korea
    "co.kr", "ne.kr", "or.kr", "re.kr", "pe.kr", "go.kr", "mil.kr", "ac.kr",
    # Canada
    "gc.ca",
    # Nigeria
    "com.ng", "org.ng", "gov.ng", "edu.ng",
    # Kenya
    "co.ke", "or.ke", "go.ke", "ac.ke",
    # UAE
    "co.ae", "net.ae", "gov.ae", "ac.ae", "org.ae",
    # Pakistan
    "com.pk", "org.pk", "net.pk", "edu.pk", "gov.pk",
    # Multi-tenant and hosted service domains
    "appspot.com", "github.io", "pages.dev", "firebaseapp.com",
    "wcomhost.com", "web.app", "vercel.app", "azurewebsites.net",
    "cloudfront.net", "s3.amazonaws.com"
}


def extract_registrable_domain(url_or_netloc: str) -> str:
    """
    Public Suffix List-aware registrable domain extraction (eTLD+1).
    Correctly handles:
    - example.com -> example.com
    - example.co.uk -> example.co.uk
    - example.com.au -> example.com.au
    - subdomain.example.co.in -> example.co.in
    - suspicious-example.com -> suspicious-example.com
    - Raw IPv4 / IPv6 addresses -> IP address literal
    Fallback: Unparseable, single-label (e.g. localhost) or malformed hostnames
    fallback to netloc string or 'unknown_domain'.
    """
    if not url_or_netloc or not isinstance(url_or_netloc, str):
        return "unknown_domain"

    clean_str = url_or_netloc.strip().lower()
    if clean_str.startswith(("http://", "https://")):
        try:
            parsed = urlparse(clean_str)
            netloc = (parsed.netloc or "").split(":")[0].strip(".")
        except Exception:
            netloc = clean_str.split("/")[0].split(":")[0].strip(".")
    else:
        netloc = clean_str.split("/")[0].split(":")[0].strip(".")

    if not netloc:
        return "unknown_domain"

    # IPv4 address literal check
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", netloc):
        return netloc

    # IPv6 address literal check
    if ":" in netloc:
        return netloc

    parts = netloc.split(".")
    if len(parts) <= 1:
        # Documented fallback: Single-label domain (e.g. localhost or intranet host)
        return parts[0] if parts[0] else "unknown_domain"

    # Check 3-part public suffixes (e.g., s3.amazonaws.com)
    if len(parts) >= 4:
        three_suffix = ".".join(parts[-3:])
        if three_suffix in PUBLIC_SUFFIXES:
            return f"{parts[-4]}.{three_suffix}"

    # Check 2-part public suffixes (e.g., co.uk, com.au, co.in)
    if len(parts) >= 3:
        two_suffix = ".".join(parts[-2:])
        if two_suffix in PUBLIC_SUFFIXES:
            return f"{parts[-3]}.{two_suffix}"

    # Standard single-part TLD (e.g., example.com, suspicious-example.com)
    return f"{parts[-2]}.{parts[-1]}"


def extract_text_group(text: str) -> str:
    """Group text messages by normalized semantic/template prefix."""
    cleaned = re.sub(r"[^a-zA-Z0-9]", "", text.lower())
    return cleaned[:30] if len(cleaned) >= 30 else (cleaned or "generic_text")


def extract_payment_group(vpa: str) -> str:
    """Group payments by payee provider handle or category."""
    if "@" in vpa:
        return vpa.split("@")[-1].lower().strip()
    return "p2p_generic"


def scrub_pii(text: str) -> str:
    """Mask personal identifiers (emails, phones, card/account numbers) while preserving URLs/domains."""
    if not text:
        return ""
    masked = re.sub(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", "[EMAIL]", text)
    masked = re.sub(r"(?<!\d)(?:\+?\d{1,3}[\s-]?)?(?:\(?\d{3,4}\)?[\s-]?)\d{3,4}[\s-]?\d{4}(?!\d)", "[PHONE]", masked)
    masked = re.sub(r"\b(?:\d[ -]?){12,16}\b", "[ACCOUNT_NUM]", masked)
    return masked


def group_split(items: list, test_ratio: float = 0.15, val_ratio: float = 0.15, seed: int = RANDOM_SEED):
    """
    Guarantees 100% disjoint groups across train, validation, and test splits.
    Zero group leakage.
    """
    rng = np.random.RandomState(seed)
    group_map = {}
    for item in items:
        g = item["group"]
        group_map.setdefault(g, []).append(item)

    groups = sorted(list(group_map.keys()))
    rng.shuffle(groups)

    total_samples = len(items)
    target_test_count = int(total_samples * test_ratio)
    target_val_count = int(total_samples * val_ratio)

    train_samples = []
    val_samples = []
    test_samples = []
    current_test_count = 0
    current_val_count = 0

    for g in groups:
        grp_items = group_map[g]
        if current_test_count < target_test_count and (len(test_samples) + len(grp_items) <= target_test_count * 1.25 or not test_samples):
            for it in grp_items:
                it["split"] = "test"
            test_samples.extend(grp_items)
            current_test_count += len(grp_items)
        elif current_val_count < target_val_count and (len(val_samples) + len(grp_items) <= target_val_count * 1.25 or not val_samples):
            for it in grp_items:
                it["split"] = "validation"
            val_samples.extend(grp_items)
            current_val_count += len(grp_items)
        else:
            for it in grp_items:
                it["split"] = "train"
            train_samples.extend(grp_items)

    if not test_samples and len(train_samples) > 5:
        last_group = groups[-1]
        grp_items = group_map[last_group]
        for it in grp_items:
            it["split"] = "test"
        train_samples = [it for it in train_samples if it["group"] != last_group]
        test_samples = grp_items

    if not val_samples and len(train_samples) > 5:
        val_group = next((it["group"] for it in reversed(train_samples)), None)
        if val_group:
            grp_items = group_map[val_group]
            for it in grp_items:
                it["split"] = "validation"
            train_samples = [it for it in train_samples if it["group"] != val_group]
            val_samples = grp_items

    all_samples = train_samples + val_samples + test_samples
    return all_samples, train_samples, val_samples, test_samples


def load_verified_samples(task_filter: str) -> list:
    if not os.path.exists(VERIFIED_PATH):
        return []
    try:
        with open(VERIFIED_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        return [it for it in data if it.get("task") == task_filter]
    except Exception as e:
        print(f"[!] Warning: Could not read verified samples: {e}")
        return []


def prepare_url_data():
    print("[*] Processing URL dataset with PSL-aware domain grouping...")
    raw = []
    with open(os.path.join(RAW_DIR, "urls_raw.json"), "r", encoding="utf-8") as f:
        raw.extend(json.load(f))
    for fn in ["phishing_urls.json", "legitimate_urls.json"]:
        p = os.path.join(EXTERNAL_DIR, fn)
        if os.path.exists(p):
            with open(p, "r", encoding="utf-8") as f:
                raw.extend(json.load(f))

    # Add verified review overlay
    verified = load_verified_samples("url")
    for v in verified:
        raw.append({
            "url": v["content"],
            "label": v["label"],
            "source": v.get("source", "verified_review")
        })

    valid_labels = {"phishing", "malicious", "suspicious", "legitimate"}
    seen = {}
    clean = []
    duplicates_count = 0

    for r in raw:
        url = (r.get("url") or r.get("content") or "").strip()
        label = (r.get("label") or "").strip().lower()
        if label not in valid_labels:
            continue
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        try:
            parsed = urlparse(url)
            netloc = parsed.netloc.lower()
            if not netloc or netloc == "/":
                continue
            norm_url = f"{parsed.scheme.lower()}://{netloc}{parsed.path or '/'}"
            if parsed.query:
                norm_url += f"?{parsed.query}"
        except Exception:
            continue

        if norm_url in seen:
            duplicates_count += 1
            continue
        seen[norm_url] = label

        group = extract_registrable_domain(norm_url)
        clean.append({
            "content": norm_url,
            "url": norm_url,
            "label": label,
            "group": group,
            "source": r.get("source", "raw")
        })

    samples, train, val, test = group_split(clean, test_ratio=0.15, val_ratio=0.15)
    print(f"    Clean URL samples: {len(samples)} (Train: {len(train)}, Val: {len(val)}, Test: {len(test)}) | Duplicates: {duplicates_count}")

    class_dist = Counter(x["label"] for x in samples)
    max_c = max(class_dist.values()) if class_dist else 1
    min_c = min(class_dist.values()) if class_dist else 1

    manifest_task = {
        "cleaning_stats": {
            "total_raw": len(raw),
            "valid_count": len(samples),
            "removed_duplicates": duplicates_count
        },
        "overall_distribution": {
            "total_samples": len(samples),
            "imbalance_ratio": round(max_c / min_c, 2),
            "classes": dict(class_dist)
        },
        "splits": {
            "train": len(train),
            "validation": len(val),
            "test": len(test),
            "grouping_strategy": "public_suffix_list_registrable_domain"
        }
    }

    return samples, manifest_task, []


def prepare_text_data():
    print("[*] Processing Text / Email dataset with campaign hash grouping...")
    raw = []
    with open(os.path.join(RAW_DIR, "text_email_raw.json"), "r", encoding="utf-8") as f:
        raw.extend(json.load(f))
    for fn in ["sms_samples.json", "email_samples.json", "curated_threats.json"]:
        p = os.path.join(EXTERNAL_DIR, fn)
        if os.path.exists(p):
            with open(p, "r", encoding="utf-8") as f:
                raw.extend(json.load(f))

    # Add verified review overlay
    verified = load_verified_samples("text_email")
    for v in verified:
        raw.append({
            "text": v["content"],
            "label": v["label"],
            "source": v.get("source", "verified_review")
        })

    valid_labels = {"scam", "phishing", "spam", "legitimate"}
    seen = {}
    clean = []
    duplicates_count = 0

    for r in raw:
        text = unicodedata.normalize("NFKC", (r.get("text") or r.get("content") or "")).strip()
        text = scrub_pii(re.sub(r"\s+", " ", text))
        label = (r.get("label") or "").strip().lower()
        if label not in valid_labels or len(text) < 4:
            continue
        if text in seen:
            duplicates_count += 1
            continue
        seen[text] = label

        group = extract_text_group(text)
        clean.append({
            "content": text,
            "text": text,
            "label": label,
            "group": group,
            "source": r.get("source", "raw")
        })

    samples, train, val, test = group_split(clean, test_ratio=0.15, val_ratio=0.15)
    print(f"    Clean Text samples: {len(samples)} (Train: {len(train)}, Val: {len(val)}, Test: {len(test)}) | Duplicates: {duplicates_count}")

    class_dist = Counter(x["label"] for x in samples)
    max_c = max(class_dist.values()) if class_dist else 1
    min_c = min(class_dist.values()) if class_dist else 1

    manifest_task = {
        "cleaning_stats": {
            "total_raw": len(raw),
            "valid_count": len(samples),
            "removed_duplicates": duplicates_count
        },
        "overall_distribution": {
            "total_samples": len(samples),
            "imbalance_ratio": round(max_c / min_c, 2),
            "classes": dict(class_dist)
        },
        "splits": {
            "train": len(train),
            "validation": len(val),
            "test": len(test),
            "grouping_strategy": "template_hash"
        }
    }

    return samples, manifest_task, []


def prepare_payment_data():
    print("[*] Processing Payment dataset with VPA handle grouping...")
    raw = []
    with open(os.path.join(RAW_DIR, "payments_raw.json"), "r", encoding="utf-8") as f:
        raw.extend(json.load(f))
    p = os.path.join(EXTERNAL_DIR, "curated_payments.json")
    if os.path.exists(p):
        with open(p, "r", encoding="utf-8") as f:
            raw.extend(json.load(f))

    # Add verified review overlay
    verified = load_verified_samples("payment")
    for v in verified:
        raw.append({
            "content": v["content"],
            "label": v["label"],
            "source": v.get("source", "verified_review")
        })

    label_map = {
        "fraudulent_request": "fraudulent",
        "suspicious_request": "suspicious",
        "legitimate_request": "legitimate",
        "fraudulent payment request": "fraudulent",
        "suspicious payment request": "suspicious",
        "legitimate payment request": "legitimate",
        "fraudulent": "fraudulent",
        "suspicious": "suspicious",
        "legitimate": "legitimate"
    }

    seen = {}
    clean = []
    duplicates_count = 0

    for r in raw:
        vpa = (r.get("vpa") or "").strip().lower()
        note = unicodedata.normalize("NFKC", (r.get("note") or "")).strip()
        amount = float(r.get("amount", 0.0))
        raw_label = (r.get("label") or "").strip().lower()
        label = label_map.get(raw_label)

        content = r.get("content")
        if not content:
            content = f"{vpa} | {amount} | {note}" if vpa else ""
        if not label or not content:
            continue

        if content in seen:
            duplicates_count += 1
            continue
        seen[content] = label

        group = extract_payment_group(vpa) if vpa else "generic_payment"
        clean.append({
            "content": content,
            "vpa": vpa,
            "amount": amount,
            "note": note,
            "label": label,
            "group": group,
            "source": r.get("source", "raw")
        })

    samples, train, val, test = group_split(clean, test_ratio=0.15, val_ratio=0.15)
    print(f"    Clean Payment samples: {len(samples)} (Train: {len(train)}, Val: {len(val)}, Test: {len(test)}) | Duplicates: {duplicates_count}")

    class_dist = Counter(x["label"] for x in samples)
    max_c = max(class_dist.values()) if class_dist else 1
    min_c = min(class_dist.values()) if class_dist else 1

    manifest_task = {
        "cleaning_stats": {
            "total_raw": len(raw),
            "valid_count": len(samples),
            "removed_duplicates": duplicates_count
        },
        "overall_distribution": {
            "total_samples": len(samples),
            "imbalance_ratio": round(max_c / min_c, 2),
            "classes": dict(class_dist)
        },
        "splits": {
            "train": len(train),
            "validation": len(val),
            "test": len(test),
            "grouping_strategy": "vpa_handle_provider"
        }
    }

    return samples, manifest_task, []


def save_task_dataset(task_name: str, samples: list, fallback_classes: list):
    json_path = os.path.join(PROCESSED_DIR, f"{task_name}_dataset.json")
    payload = {
        "task": task_name,
        "samples": samples,
        "metadata": {
            "split_info": {
                "fallback_stratified_classes": fallback_classes
            }
        }
    }
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

    csv_path = os.path.join(PROCESSED_DIR, f"{task_name}_dataset.csv")
    with open(csv_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["content", "label", "group", "split"])
        for s in samples:
            clean_content = s["content"].replace("\n", " ").replace("\r", " ")
            writer.writerow([clean_content, s["label"], s["group"], s["split"]])


def main():
    print("=" * 70)
    print("ScamShield ML Pipeline - Preparing Processed Datasets (PSL Group-Aware)")
    print("=" * 70)

    url_samples, url_meta, url_fb = prepare_url_data()
    save_task_dataset("url", url_samples, url_fb)

    text_samples, text_meta, text_fb = prepare_text_data()
    save_task_dataset("text_email", text_samples, text_fb)

    pay_samples, pay_meta, pay_fb = prepare_payment_data()
    save_task_dataset("payment", pay_samples, pay_fb)

    manifest = {
        "random_seed": RANDOM_SEED,
        "created_at": "2026-10-31T22:35:00Z",
        "tasks": {
            "url": url_meta,
            "text_email": text_meta,
            "payment": pay_meta
        }
    }

    manifest_path = os.path.join(PROCESSED_DIR, "dataset_manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    print(f"\n[+] Manifest generated at: {manifest_path}")
    print("=" * 70)


if __name__ == "__main__":
    main()
