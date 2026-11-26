"""
ScamShield Track C — UPI ID Validation, Handle Registry & Reputation Assessment
Strictly separates:
  FORMAT_VALID, HANDLE_SUPPORTED, PROVIDER_LOOKUP_AVAILABLE,
  RECIPIENT_VERIFIED, REPUTATION_SIGNAL_AVAILABLE, SUSPICIOUS_PATTERN, UNKNOWN

Invariants:
- Valid UPI syntax NEVER implies verified or trusted recipient.
- Unknown handles are labeled UNKNOWN, never malicious.
- Single unverified user report NEVER classifies a UPI ID as fraudulent.
- No payment initiation or UPI PIN collection.
"""

import hashlib
import json
import os
import re
import unicodedata
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

UPI_DIR = os.path.dirname(os.path.abspath(__file__))
REGISTRY_PATH = os.path.join(UPI_DIR, "handle_registry.json")

USER_PART_RE = re.compile(r"^[a-zA-Z0-9.\-_]{2,64}$")
PSP_PART_RE = re.compile(r"^[a-zA-Z0-9.\-]{2,32}$")
PAYMENT_BRANDS = ("paytm", "phonepe", "gpay", "googlepay", "sbi", "hdfc", "icici", "axis", "amazonpay", "bhim", "irctc")
IMPERSONATION_TERMS = ("refund", "support", "care", "help", "helpdesk", "desk", "nodal", "kyc", "verify", "verification", "claim", "reward", "official", "cashback")
LURE_TERMS = ("lottery", "winner", "jackpot", "freebonus", "electricity-bill", "billdesk-support", "prize-claim")


def load_handle_registry(path: str = REGISTRY_PATH) -> Dict[str, Any]:
    if not os.path.exists(path):
        return {"handles": {}}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


class ReputationStore:
    """
    Privacy-conscious, provenance-tracked UPI reputation store.
    Requires >= 2 independent corroborated reports or 1 verified threat-intel record;
    single unverified user report never marks an identifier fraudulent.
    """

    def __init__(self):
        self._records: Dict[str, List[Dict[str, Any]]] = {}

    @staticmethod
    def hash_vpa(vpa: str) -> str:
        return hashlib.sha256(vpa.strip().lower().encode("utf-8")).hexdigest()

    def add_signal(
        self,
        vpa: str,
        *,
        source: str,
        verified: bool,
        confidence: float,
        reason: str,
        timestamp: Optional[str] = None,
        expires_at: Optional[str] = None,
    ) -> None:
        key = self.hash_vpa(vpa)
        self._records.setdefault(key, []).append({
            "source": source,
            "verified": bool(verified),
            "confidence": round(float(confidence), 4),
            "reason": reason,
            "timestamp": timestamp or datetime.now(timezone.utc).isoformat(),
            "expires_at": expires_at,
        })

    def lookup(self, vpa: str) -> Dict[str, Any]:
        key = self.hash_vpa(vpa)
        signals = self._records.get(key, [])
        now_iso = datetime.now(timezone.utc).isoformat()
        active = [s for s in signals if not s.get("expires_at") or s["expires_at"] > now_iso]
        if not active:
            return {"reputation_signal_available": False, "is_corroborated_fraud": False, "signals": []}

        verified_sigs = [s for s in active if s["verified"] and s["confidence"] >= 0.8]
        distinct_sources = {s["source"] for s in active}
        corroborated = len(verified_sigs) >= 1 or len(distinct_sources) >= 2
        return {
            "reputation_signal_available": True,
            "is_corroborated_fraud": corroborated,
            "signals": active,
        }


def has_non_ascii_homoglyph(s: str) -> bool:
    return any(ord(ch) > 127 for ch in s)


def verify_upi_id(
    raw_vpa: str,
    reputation_store: Optional[ReputationStore] = None,
    registry: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Evaluate a UPI ID across all 7 independent verification states.
    Never equates syntax validity with recipient trustworthiness.
    """
    reg = registry if registry is not None else load_handle_registry()
    handles_map = reg.get("handles", {})

    raw = str(raw_vpa or "").strip()
    nfkc = unicodedata.normalize("NFKC", raw).lower()

    states: List[str] = []
    evidence: List[Dict[str, Any]] = []

    # 1. Check Unicode homoglyphs before normalization hides them
    if has_non_ascii_homoglyph(raw):
        states.append("SUSPICIOUS_PATTERN")
        evidence.append({
            "indicator_type": "UNICODE_HOMOGLYPH",
            "description": "UPI identifier contains non-ASCII Unicode characters that may impersonate ASCII handles.",
            "severity": "high",
        })

    # 2. Format validation
    if not nfkc or "@" not in nfkc or nfkc.count("@") != 1:
        return {
            "normalized_vpa": None,
            "states": ["UNKNOWN"] if not nfkc else ["SUSPICIOUS_PATTERN"],
            "format_valid": False,
            "handle_supported": False,
            "handle_status": "invalid_syntax",
            "provider_name": None,
            "provider_lookup_available": False,
            "recipient_verified": False,
            "reputation_signal_available": False,
            "suspicious_pattern": True,
            "risk_assessment": "invalid_format",
            "evidence": [{
                "indicator_type": "UPI_SYNTAX_INVALID",
                "description": "UPI ID must contain exactly one '@' separating user handle and PSP suffix.",
                "severity": "medium",
            }],
        }

    user_part, psp_part = nfkc.split("@", 1)
    format_valid = bool(USER_PART_RE.match(user_part) and PSP_PART_RE.match(psp_part))
    if format_valid:
        states.append("FORMAT_VALID")
    else:
        states.append("SUSPICIOUS_PATTERN")
        evidence.append({
            "indicator_type": "UPI_CHARACTER_CONSTRAINT_VIOLATION",
            "description": "UPI user or PSP handle violates length or allowed character constraints.",
            "severity": "medium",
        })

    # 3. Handle / Provider Registry Lookup (non-authoritative)
    handle_info = handles_map.get(psp_part)
    handle_supported = False
    handle_status = "unknown"
    provider_name = None
    if handle_info:
        handle_status = handle_info.get("status", "unknown")
        provider_name = handle_info.get("provider_name")
        if handle_status == "supported":
            handle_supported = True
            states.append("HANDLE_SUPPORTED")
        elif handle_status == "deprecated":
            states.append("UNKNOWN")
            evidence.append({
                "indicator_type": "DEPRECATED_PSP_HANDLE",
                "description": f"PSP handle '@{psp_part}' ({provider_name}) is marked deprecated.",
                "severity": "low",
            })
    else:
        states.append("UNKNOWN")

    # 4. Suspicious Pattern Checks (impersonation, lures, anomalous PSP, or invalid chars/homoglyphs)
    suspicious_pattern = (not format_valid) or has_non_ascii_homoglyph(raw)
    for brand in PAYMENT_BRANDS:
        if brand in user_part and any(term in user_part for term in IMPERSONATION_TERMS):
            suspicious_pattern = True
            states.append("SUSPICIOUS_PATTERN")
            evidence.append({
                "indicator_type": "UPI_BRAND_IMPERSONATION",
                "description": f"Handle '{user_part}' combines brand '{brand}' with support/refund/KYC pretext terms.",
                "severity": "critical",
            })
            break

    if any(lure in user_part for lure in LURE_TERMS):
        suspicious_pattern = True
        if "SUSPICIOUS_PATTERN" not in states:
            states.append("SUSPICIOUS_PATTERN")
        evidence.append({
            "indicator_type": "DECEPTIVE_PAYEE_HANDLE",
            "description": f"Handle '{user_part}' contains financial lure keywords.",
            "severity": "high",
        })

    if "." in psp_part and not psp_part.startswith("ok") and not psp_part.endswith("bank"):
        suspicious_pattern = True
        if "SUSPICIOUS_PATTERN" not in states:
            states.append("SUSPICIOUS_PATTERN")
        evidence.append({
            "indicator_type": "SUSPICIOUS_PSP_DOMAIN",
            "description": f"PSP suffix '@{psp_part}' resembles an arbitrary web domain rather than a standard bank/PSP handle.",
            "severity": "high",
        })

    # 5. Reputation Lookup (separate from syntax/handle)
    rep = reputation_store.lookup(nfkc) if reputation_store else {"reputation_signal_available": False, "is_corroborated_fraud": False, "signals": []}
    if rep["reputation_signal_available"]:
        states.append("REPUTATION_SIGNAL_AVAILABLE")
        if rep["is_corroborated_fraud"]:
            suspicious_pattern = True
            evidence.append({
                "indicator_type": "CORROBORATED_UPI_REPUTATION_FRAUD",
                "description": "Corroborated fraud intelligence matched this UPI identifier.",
                "severity": "critical",
            })

    # Risk assessment (never claims recipient verified)
    if any(e["severity"] == "critical" for e in evidence):
        risk_assessment = "high_risk_suspicious"
    elif suspicious_pattern:
        risk_assessment = "suspicious"
    elif format_valid and handle_supported:
        risk_assessment = "format_valid_unverified_recipient"
    else:
        risk_assessment = "unverified_unknown_handle"

    return {
        "normalized_vpa": nfkc,
        "states": list(dict.fromkeys(states)),
        "format_valid": format_valid,
        "handle_supported": handle_supported,
        "handle_status": handle_status,
        "provider_name": provider_name,
        "provider_lookup_available": False,  # No live NPCI/PSP API integrated
        "recipient_verified": False,         # Never true without authorized PSP lookup
        "reputation_signal_available": rep["reputation_signal_available"],
        "suspicious_pattern": suspicious_pattern,
        "risk_assessment": risk_assessment,
        "evidence": evidence,
    }
