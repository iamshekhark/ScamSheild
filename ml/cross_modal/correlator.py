"""
ScamShield Track D — Cross-Modal Evidence Interface & Correlator (Design Prototype)
Correlates independent evidence envelopes from OCR, Message, URL, and UPI Verifier
while enforcing:
- Strict model-task-modality compatibility (rejects mismatched model outputs)
- Full provenance preservation
- Deduplication of correlated signals (no double-counting)
- Explicit distinction between UNKNOWN/UNVERIFIED and MALICIOUS
- Model confidence is NEVER treated as overall scam probability
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

ALLOWED_MODALITIES = {
    "url_model": {"url"},
    "email_model": {"email"},
    "message_model": {"sms", "whatsapp", "message", "ocr_text"},
    "ocr_model": {"ocr_text", "qr_image"},
    "upi_verifier": {"upi_id", "qr_upi_uri"},
    "deterministic_rules": {"url", "email", "sms", "whatsapp", "message", "webpage", "ocr_text", "upi_id", "qr_upi_uri"},
}


@dataclass
class EvidenceEnvelope:
    source_model: str
    task: str
    target_modality: str
    classification: str  # legitimate | suspicious | malicious | unknown | uncertain
    confidence: Optional[float]  # 0.0-1.0 calibrated class confidence or None
    calibrated: bool
    model_version: str
    evidence_items: List[Dict[str, Any]] = field(default_factory=list)
    provenance: Dict[str, Any] = field(default_factory=dict)
    status: str = "completed"


def correlate_evidence(envelopes: List[EvidenceEnvelope]) -> Dict[str, Any]:
    """
    Safely aggregate compatible evidence envelopes without double-counting
    correlated findings or letting incompatible models affect the verdict.
    """
    accepted: List[EvidenceEnvelope] = []
    rejected_incompatible: List[Dict[str, str]] = []

    for env in envelopes:
        allowed = ALLOWED_MODALITIES.get(env.source_model, set())
        if env.target_modality not in allowed:
            rejected_incompatible.append({
                "source_model": env.source_model,
                "target_modality": env.target_modality,
                "reason": f"Model '{env.source_model}' is incompatible with modality '{env.target_modality}'",
            })
            continue
        accepted.append(env)

    # Deduplicate evidence by (indicator_type, normalized_target), keeping highest severity
    sev_rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    dedup_map: Dict[tuple, Dict[str, Any]] = {}
    for env in accepted:
        for item in env.evidence_items:
            key = (str(item.get("indicator_type", "")), str(item.get("target", "")))
            cur_sev = str(item.get("severity", "low")).lower()
            enriched = {
                **item,
                "source_model": env.source_model,
                "model_version": env.model_version,
                "provenance": env.provenance,
            }
            if key not in dedup_map:
                dedup_map[key] = enriched
            else:
                prev_sev = str(dedup_map[key].get("severity", "low")).lower()
                if sev_rank.get(cur_sev, 0) > sev_rank.get(prev_sev, 0) or env.source_model == "deterministic_rules":
                    dedup_map[key] = enriched
    unique_evidence: List[Dict[str, Any]] = list(dedup_map.values())

    has_critical_det = any(
        ev.get("source_model") == "deterministic_rules" and ev.get("severity") == "critical"
        for ev in unique_evidence
    )
    has_high_det = any(
        ev.get("source_model") == "deterministic_rules" and ev.get("severity") in ("high", "critical")
        for ev in unique_evidence
    )
    malicious_modalities = {
        env.target_modality for env in accepted if env.classification in ("malicious", "phishing", "scam")
    }
    unknown_only = len(accepted) > 0 and all(env.classification in ("unknown", "uncertain") for env in accepted)

    if has_critical_det:
        overall_verdict = "critical_threat"
    elif has_high_det or len(malicious_modalities) >= 2:
        overall_verdict = "high_risk"
    elif len(malicious_modalities) == 1 or any(ev.get("severity") == "medium" for ev in unique_evidence):
        overall_verdict = "suspicious"
    elif unknown_only:
        overall_verdict = "unknown_unverified"
    else:
        overall_verdict = "no_threat_detected"

    return {
        "overall_verdict": overall_verdict,
        "accepted_modalities": [e.target_modality for e in accepted],
        "rejected_incompatible_models": rejected_incompatible,
        "correlated_evidence": unique_evidence,
        "evidence_count": len(unique_evidence),
        "payment_settlement_verified": False,
    }
