# ScamShield Phase 4.7 — Security & Privacy Report

**Date:** 2026-11-26  
**Scope:** Security, privacy, data minimization, and fail-safe controls across OCR, Message, UPI Verifier, and Cross-Modal Intelligence.

---

## 1. Data Minimization & PII Redaction
- **OCR Field Extraction (`ml/ocr_model/field_extractor.py`)**: Extracted mobile phone numbers are immediately redacted to `[REDACTED_PHONE]` in structured outputs and logs; raw images are never uploaded or persisted by `extension/ocr/ocr_engine.js`.
- **Message Preprocessing (`ml/message_model/features.py`, `prepare_datasets.py`)**: All training and evaluation texts pass through `scrub_pii()` (`[EMAIL]`, `[PHONE]`, `[ACCOUNT_NUM]`) prior to splitting and model training.
- **UPI Reputation (`ml/upi_verifier/verifier.py`)**: `ReputationStore` indexes identifiers by **SHA-256 hash** (`hash_vpa`) rather than plaintext VPA keys, reducing sensitive identifier exposure in storage.

---

## 2. Credential & Financial Safety Invariants
- **Zero Credential Collection**: None of the Phase 4 modules collect, store, or transmit UPI PINs, banking passwords, CVVs, or OTP values.
- **Unverified Settlement Invariant**: Both `extension/ocr/ocr_engine.js` and `ml/ocr_model/field_extractor.py` enforce `settlement_verified: false` / `payment_status: "unverified"`.
- **Recipient Verification Invariant**: `ml/upi_verifier/verifier.py` enforces `recipient_verified: false` and `provider_lookup_available: false` offline, never claiming recipient identity from syntax or handle alone.

---

## 3. Untrusted Input & Fail-Safe Controls
- **Untrusted OCR & QR Payloads**: `extension/ocr/ocr_engine.js` enforces a `12 MB` file size limit, `image/*` type validation, and treats decoded QR URIs and OCR text as untrusted strings (never `eval` or auto-navigated).
- **Safe Failure States**:
  - `extension/ocr/ocr_engine.js` returns `UNABLE_TO_VERIFY` (`risk_score: null`) on OCR recognition failure when no QR code is present.
  - `ml/email_model/predict.py` and `ml/url_model/predict.py` return `model_unavailable` / `invalid_input` / `out_of_distribution` without crashing when artifacts are missing or inputs are empty/OOD.
  - `ml/cross_modal/correlator.py` rejects incompatible model-modality outputs (`rejected_incompatible_models`) and treats `unknown`/`uncertain`-only envelopes as `unknown_unverified`, never `no_threat_detected`.
