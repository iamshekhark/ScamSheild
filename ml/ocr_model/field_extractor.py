"""
ScamShield Track A — Structured OCR Field Extraction & Text Error Metrics
Extracts UPI IDs, amounts, 12-digit UTR/RRN references, merchant/payee names,
phone numbers, URLs, bank names, payment status, dates/timestamps, and QR payloads.

Note: OCR output is NEVER treated as verified ground truth or proof of bank settlement.
"""

import re
from typing import Any, Dict, List, Optional

UPI_RE = re.compile(r"\b([a-zA-Z0-9.\-_]{2,64}@[a-zA-Z0-9.\-]{2,32})\b")
AMOUNT_RE = re.compile(r"(?:rs\.?|inr|₹)\s*([0-9]{1,3}(?:,[0-9]{2,3})*(?:\.[0-9]{1,2})?|[0-9]+(?:\.[0-9]{1,2})?)", re.IGNORECASE)
UTR_RE = re.compile(r"(?:utr|upi\s*ref|rrn|ref\s*no|txn\s*id|transaction\s*id)[:\s#-]*([a-zA-Z0-9]{10,22})", re.IGNORECASE)
STANDALONE_12D_RE = re.compile(r"\b(\d{12})\b")
PHONE_RE = re.compile(r"(?:\+?91[\s-]?)?([6-9]\d{9})\b")
URL_RE = re.compile(r"(https?://[^\s<>\"']+|wa\.me/[^\s<>\"']+)", re.IGNORECASE)
DATE_RE = re.compile(r"\b(\d{1,2}[-/ ](?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec|\d{1,2})[-/ ]\d{2,4})\b", re.IGNORECASE)
BANK_RE = re.compile(r"\b(sbi|state bank of india|hdfc|icici|axis|kotak|pnb|bank of baroda|yes bank|paytm|phonepe|gpay|google pay|bhim)\b", re.IGNORECASE)
STATUS_RE = re.compile(r"\b(payment\s+successful|sent\s+successfully|paid\s+to|transfer\s+complete|failed|pending|declined)\b", re.IGNORECASE)
MERCHANT_RE = re.compile(r"(?:paid\s+to|payment\s+to|sent\s+to|to)\s+([A-Za-z0-9 &.\-]{3,45}?)(?:\s+on|\s+via|\s+successful|\.|\n|$)", re.IGNORECASE)


def extract_ocr_fields(text: str, qr_payload: Optional[str] = None, ocr_confidence: float = 0.0) -> Dict[str, Any]:
    """Extract structured payment & threat fields from OCR text with per-field confidence and validation."""
    raw = str(text or "")
    fields: Dict[str, List[Dict[str, Any]]] = {
        "upi_ids": [],
        "amounts": [],
        "transaction_refs": [],
        "merchants": [],
        "phone_numbers": [],
        "urls": [],
        "bank_names": [],
        "payment_status": [],
        "dates": [],
        "qr_payloads": [],
    }
    base_conf = round(max(0.0, min(1.0, float(ocr_confidence) / 100.0 if ocr_confidence > 1.0 else float(ocr_confidence))), 4)

    for m in UPI_RE.finditer(raw):
        val = m.group(1).lower()
        # Exclude obvious email domains if needed, keep UPI handles
        if not val.endswith((".com", ".org", ".net", ".in", ".edu")):
            fields["upi_ids"].append({
                "value": val,
                "confidence": base_conf or 0.75,
                "region": "ocr_full_text",
                "extraction_method": "regex_upi_vpa",
                "validation_result": "format_valid_unverified_recipient",
            })

    for m in AMOUNT_RE.finditer(raw):
        fields["amounts"].append({
            "value": m.group(1).replace(",", ""),
            "confidence": base_conf or 0.75,
            "region": "ocr_full_text",
            "extraction_method": "regex_currency_inr",
            "validation_result": "parsed_numeric_unverified",
        })

    seen_refs = set()
    for m in UTR_RE.finditer(raw):
        ref = m.group(1)
        seen_refs.add(ref)
        fields["transaction_refs"].append({
            "value": ref,
            "confidence": base_conf or 0.75,
            "region": "ocr_full_text",
            "extraction_method": "regex_utr_labeled",
            "validation_result": "syntax_present_settlement_unverified",
        })
    for m in STANDALONE_12D_RE.finditer(raw):
        ref = m.group(1)
        if ref not in seen_refs:
            fields["transaction_refs"].append({
                "value": ref,
                "confidence": base_conf or 0.65,
                "region": "ocr_full_text",
                "extraction_method": "regex_12digit_utr_candidate",
                "validation_result": "candidate_12digit_unverified",
            })

    for m in MERCHANT_RE.finditer(raw):
        fields["merchants"].append({
            "value": m.group(1).strip(),
            "confidence": base_conf or 0.65,
            "region": "ocr_full_text",
            "extraction_method": "regex_payee_phrase",
            "validation_result": "extracted_unverified",
        })

    for m in PHONE_RE.finditer(raw):
        fields["phone_numbers"].append({
            "value": "[REDACTED_PHONE]",  # Privacy-safe redaction in logs/artifacts
            "confidence": base_conf or 0.75,
            "region": "ocr_full_text",
            "extraction_method": "regex_in_mobile",
            "validation_result": "redacted_pii",
        })

    for m in URL_RE.finditer(raw):
        fields["urls"].append({
            "value": m.group(1),
            "confidence": base_conf or 0.8,
            "region": "ocr_full_text",
            "extraction_method": "regex_url",
            "validation_result": "extracted_requires_url_scan",
        })

    for m in BANK_RE.finditer(raw):
        fields["bank_names"].append({
            "value": m.group(1).upper(),
            "confidence": base_conf or 0.75,
            "region": "ocr_full_text",
            "extraction_method": "lexicon_bank_match",
            "validation_result": "claimed_brand_unverified",
        })

    for m in STATUS_RE.finditer(raw):
        fields["payment_status"].append({
            "value": m.group(1).lower(),
            "confidence": base_conf or 0.75,
            "region": "ocr_full_text",
            "extraction_method": "lexicon_status_phrase",
            "validation_result": "unverified_screenshot_claim",
        })

    for m in DATE_RE.finditer(raw):
        fields["dates"].append({
            "value": m.group(1),
            "confidence": base_conf or 0.7,
            "region": "ocr_full_text",
            "extraction_method": "regex_date",
            "validation_result": "parsed_unverified",
        })

    if qr_payload:
        fields["qr_payloads"].append({
            "value": qr_payload,
            "confidence": 1.0,
            "region": "qr_code_matrix",
            "extraction_method": "jsqr_decoder",
            "validation_result": "decoded_untrusted_payload",
        })

    return {
        "fields": fields,
        "settlement_verified": False,
        "note": "OCR extracted fields are unverified and do not prove payment settlement.",
    }


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i]
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            curr.append(min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost))
        prev = curr
    return prev[-1]


def compute_cer(reference: str, hypothesis: str) -> float:
    ref = str(reference or "")
    hyp = str(hypothesis or "")
    if not ref:
        return 0.0 if not hyp else 1.0
    return round(levenshtein(ref, hyp) / len(ref), 4)


def compute_wer(reference: str, hypothesis: str) -> float:
    ref_w = str(reference or "").split()
    hyp_w = str(hypothesis or "").split()
    if not ref_w:
        return 0.0 if not hyp_w else 1.0
    # Word-level Levenshtein
    prev = list(range(len(hyp_w) + 1))
    for i, rw in enumerate(ref_w, 1):
        curr = [i]
        for j, hw in enumerate(hyp_w, 1):
            cost = 0 if rw == hw else 1
            curr.append(min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost))
        prev = curr
    return round(prev[-1] / len(ref_w), 4)
