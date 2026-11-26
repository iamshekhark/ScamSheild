"""
ScamShield Track C — UPI ID Verifier Benchmark & Evaluation
Tests format validation, handle registry lookup, unknown-handle neutrality,
Unicode homoglyph detection, impersonation detection, and reputation corroboration rules.
"""

import json
import os
import sys
import time
from typing import Any, Dict, List

ML_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ML_ROOT not in sys.path:
    sys.path.insert(0, ML_ROOT)

from common import REPORTS_DIR  # noqa: E402
from upi_verifier.verifier import ReputationStore, verify_upi_id  # noqa: E402

UPI_BENCHMARK_CASES = [
    # Legitimate known handles
    {"vpa": "grocery.store@okhdfcbank", "expected_format": True, "expected_supported": True, "expected_suspicious": False, "cat": "legit_known"},
    {"vpa": "irctc@paytm", "expected_format": True, "expected_supported": True, "expected_suspicious": False, "cat": "legit_known"},
    {"vpa": "swiggy.order@icici", "expected_format": True, "expected_supported": True, "expected_suspicious": False, "cat": "legit_known"},
    {"vpa": "bookshop@okaxis", "expected_format": True, "expected_supported": True, "expected_suspicious": False, "cat": "legit_known"},
    {"vpa": "merchant.123@ybl", "expected_format": True, "expected_supported": True, "expected_suspicious": False, "cat": "legit_known"},
    # Unknown valid handles (must NOT be labeled malicious)
    {"vpa": "merchant@newbankpsp", "expected_format": True, "expected_supported": False, "expected_suspicious": False, "cat": "unknown_valid"},
    {"vpa": "shop42@fintechupi", "expected_format": True, "expected_supported": False, "expected_suspicious": False, "cat": "unknown_valid"},
    # Deprecated handle
    {"vpa": "user@pingpay", "expected_format": True, "expected_supported": False, "expected_suspicious": False, "cat": "deprecated_handle"},
    # Malformed syntax
    {"vpa": "not-a-upi-id", "expected_format": False, "expected_supported": False, "expected_suspicious": True, "cat": "malformed"},
    {"vpa": "user@@ybl", "expected_format": False, "expected_supported": False, "expected_suspicious": True, "cat": "malformed"},
    {"vpa": "@okhdfcbank", "expected_format": False, "expected_supported": False, "expected_suspicious": True, "cat": "malformed"},
    {"vpa": "a@ybl", "expected_format": False, "expected_supported": False, "expected_suspicious": True, "cat": "malformed"},
    # Impersonation & lure patterns
    {"vpa": "paytm-refund-desk@ybl", "expected_format": True, "expected_supported": True, "expected_suspicious": True, "cat": "impersonation"},
    {"vpa": "sbi-kyc-verify@okhdfcbank", "expected_format": True, "expected_supported": True, "expected_suspicious": True, "cat": "impersonation"},
    {"vpa": "phonepe-cashback-support@ibl", "expected_format": True, "expected_supported": True, "expected_suspicious": True, "cat": "impersonation"},
    {"vpa": "lottery-winner@okaxis", "expected_format": True, "expected_supported": True, "expected_suspicious": True, "cat": "lure"},
    {"vpa": "scammer@evil.xyz", "expected_format": True, "expected_supported": False, "expected_suspicious": True, "cat": "anomalous_psp"},
    # Unicode homoglyph
    {"vpa": "paytm\u0430@ybl", "expected_format": False, "expected_supported": False, "expected_suspicious": True, "cat": "unicode_homoglyph"},
]


def evaluate_upi_verifier() -> Dict[str, Any]:
    rep_store = ReputationStore()
    # Single unverified user report must NOT trigger fraud
    rep_store.add_signal("single.report@ybl", source="user_1", verified=False, confidence=0.5, reason="unverified report")
    # Corroborated 2-source report MUST trigger fraud
    rep_store.add_signal("corroborated.scam@ybl", source="user_1", verified=False, confidence=0.6, reason="scam report 1")
    rep_store.add_signal("corroborated.scam@ybl", source="user_2", verified=False, confidence=0.7, reason="scam report 2")

    t0 = time.perf_counter()
    passed = 0
    results: List[Dict[str, Any]] = []
    for c in UPI_BENCHMARK_CASES:
        res = verify_upi_id(c["vpa"], reputation_store=rep_store)
        ok = (
            res["format_valid"] == c["expected_format"]
            and res["handle_supported"] == c["expected_supported"]
            and res["suspicious_pattern"] == c["expected_suspicious"]
            and res["recipient_verified"] is False
        )
        if ok:
            passed += 1
        results.append({**c, "ok": ok, "states": res["states"], "risk_assessment": res["risk_assessment"]})

    single_res = verify_upi_id("single.report@ybl", reputation_store=rep_store)
    corrob_res = verify_upi_id("corroborated.scam@ybl", reputation_store=rep_store)
    latency_ms = round(((time.perf_counter() - t0) * 1000.0) / (len(UPI_BENCHMARK_CASES) + 2), 4)

    summary = {
        "total_cases": len(UPI_BENCHMARK_CASES),
        "passed": passed,
        "accuracy": round(passed / len(UPI_BENCHMARK_CASES), 4),
        "single_unverified_report_protected": single_res["suspicious_pattern"] is False,
        "corroborated_report_flagged": corrob_res["suspicious_pattern"] is True,
        "recipient_verified_always_false_offline": all(r["ok"] for r in results),
        "latency_ms_per_check": latency_ms,
        "cases": results,
    }
    with open(os.path.join(REPORTS_DIR, "phase4_upi_eval.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
    print(f"[OK] UPI Track C: passed={passed}/{len(UPI_BENCHMARK_CASES)}, single_report_protected={summary['single_unverified_report_protected']}, corrob_flagged={summary['corroborated_report_flagged']}")
    return summary


if __name__ == "__main__":
    evaluate_upi_verifier()
