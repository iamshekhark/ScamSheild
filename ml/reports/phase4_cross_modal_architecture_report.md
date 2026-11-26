# ScamShield Phase 4 — Track D: Cross-Modal Intelligence Architecture Report

**Date:** 2026-11-26  
**Module:** `ml/cross_modal/correlator.py` (`EvidenceEnvelope`, `correlate_evidence`)  
**Decision:** **`READY FOR INTEGRATION REVIEW`** (design prototype verified; not yet wired into production)

---

## 1. Common Evidence Interface (`EvidenceEnvelope`)
Every detector emits a standardized envelope preserving:
- `source_model`, `task`, `target_modality`, `classification`, `confidence` (calibrated class confidence or `None`), `calibrated`, `model_version`, `evidence_items`, `provenance`, `status`.

---

## 2. Safety & Correlation Invariants
1. **Strict Model-Task-Modality Compatibility**: `ALLOWED_MODALITIES` rejects incompatible pairs (e.g., `email_model` outputting on `target_modality="webpage"` is recorded in `rejected_incompatible_models` and excluded from verdict aggregation).
2. **No Double-Counting**: `correlate_evidence` deduplicates findings by `(indicator_type, target)`, retaining the highest severity and authoritative `deterministic_rules` provenance when both rules and ML flag the same target.
3. **Unknown != Malicious**: When all compatible envelopes return `unknown` or `uncertain`, `overall_verdict` is `"unknown_unverified"`, never `"no_threat_detected"` or `"critical_threat"`.
4. **Confidence != Scam Probability**: Individual model `confidence` is never summed or equated to overall scam probability; `critical_threat` requires deterministic `critical` evidence, and `high_risk` requires deterministic `high` evidence or `>= 2` independent malicious modalities.
5. **Payment Settlement Invariant**: `payment_settlement_verified` is always `false`.

---

## 3. Verification Output
Executed `correlate_evidence` with 3 envelopes (`email_model` on `webpage`, `upi_verifier` on `upi_id`, `deterministic_rules` on `upi_id`):
- Rejected `1` incompatible envelope (`email_model` on `webpage`).
- Deduplicated `2` matching `UPI_BRAND_IMPERSONATION` findings into `1` evidence item.
- Returned `overall_verdict: "critical_threat"` with `payment_settlement_verified: false`.

---

## 4. Remaining Integration Requirements
- Port `EvidenceEnvelope` normalization and `ALLOWED_MODALITIES` check into `extension/background.js` (`mergeLayeredResults`) and `supabase/functions/_shared/detectionEngine.ts` in a future approved release phase.
- Keep `production_active: false` for all Phase 4 candidate artifacts until `ocr-scam-model` and `message-model` meet the `FPR <= 0.10%` statistical threshold on `>= 3,000` independent legitimate samples.
