# ScamShield Phase 4 — Track C: UPI ID Verifier Report

**Date:** 2026-11-26  
**Module:** `ml/upi_verifier/` (`verifier.py`, `handle_registry.json`, `evaluate_upi.py`)  
**Decision:** **`READY FOR INTEGRATION REVIEW`** (as a deterministic syntax + handle-registry + corroborated-reputation verifier; live recipient lookup remains unavailable)

---

## 1. Architecture & 7-State Separation (`ml/upi_verifier/verifier.py`)
Implements strict separation between:
1. `FORMAT_VALID` — syntax (`^[a-zA-Z0-9.\-_]{2,64}@[a-zA-Z0-9.\-]{2,32}$`)
2. `HANDLE_SUPPORTED` — PSP suffix exists in `handle_registry.json` (`34` NPCI/bank handles with provider, source, `last_verified`, `status`, `evidence_quality`)
3. `PROVIDER_LOOKUP_AVAILABLE` — explicitly `false` (no live NPCI/PSP API integrated)
4. `RECIPIENT_VERIFIED` — explicitly `false` (valid syntax NEVER implies trusted recipient)
5. `REPUTATION_SIGNAL_AVAILABLE` — `ReputationStore` using SHA-256 hashed VPAs, provenance, timestamps, expiration, and corroboration (`>= 2` independent sources or `>= 1` verified threat-intel match)
6. `SUSPICIOUS_PATTERN` — brand+support/refund impersonation, financial lures, domain-like PSP, Unicode homoglyphs, or invalid syntax
7. `UNKNOWN` — unfamiliar or deprecated handles (never labeled malicious solely for being unfamiliar)

---

## 2. Live Recipient Verification Investigation (Section C4)
- **Status**: No authorized live NPCI/PSP `ValidateAddress` API is integrated in this extension/backend. Authoritative recipient name verification requires a licensed NPCI/PSP partner API (e.g., Razorpay/Cashfree/Paytm/Bank VPA validation endpoint) with server-side credentials, rate limiting, and explicit user consent.
- **Safety**: ScamShield never initiates payments or collects UPI PINs.

---

## 3. Evaluation Results (`ml/reports/phase4_upi_eval.json`)
- **Format, Impersonation & Handle Checks**: `15/18` exact-match on all 3 flags (`format_valid`, `handle_supported`, `suspicious_pattern`); the 3 partial mismatches (`@okhdfcbank`, `a@ybl`, `paytmа@ybl`) correctly flagged `format_valid=false` and `suspicious_pattern=true` while independently reporting `handle_supported=true` for the `@okhdfcbank`/`@ybl` PSP suffix.
- **False-Report Protection**: `single_unverified_report_protected = true` (1 unverified report did NOT flag `single.report@ybl`); `corroborated_report_flagged = true` (2 independent sources flagged `corroborated.scam@ybl`).
- **Recipient Invariant**: `recipient_verified` was `false` across 100% of offline checks.
- **Latency**: `0.4236 ms/check`.
