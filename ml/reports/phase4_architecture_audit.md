# ScamShield Phase 4.1 — Complete Architecture Audit

**Date:** 2026-11-26  
**Scope:** Full audit of `ml/`, `extension/`, and `supabase/functions/` prior to Phase 4 candidate development.

---

## 1. Existing Models & Versions
- **Production/Extension Models (Preserved, `is_production_ready: false`, shadow-gated)**:
  - `extension/models/url_classifier.json` (`v2.1.0`, char_wb 3–5 TF-IDF + Logistic Regression)
  - `extension/models/text_email_classifier.json` (`v2.1.0`, char_wb 3–5 TF-IDF + Logistic Regression)
  - `extension/models/payment_classifier.json` (`v2.1.0`, char_wb 3–5 TF-IDF + Logistic Regression)
- **Phase 1–2 Candidate Artifacts (`ml/artifacts/registry.json`, `production_active: false`)**:
  - `email-model-v1.0.0`, `url-model-v1.0.0`, `email-model-v2.0.0`, `url-model-v2.0.0`.

---

## 2. Existing OCR & Image Processing (`extension/ocr/ocr_engine.js`)
- **Engine**: Tesseract.js (`tesseract-core-lstm.wasm.js`) with English-only `eng.traineddata.gz` + `jsQR.js` for QR decoding.
- **Capabilities & Gaps**:
  - Extracts raw text and QR payloads 100% locally in WebAssembly; enforces `12 MB` max file size, `image/*` MIME check, and permanent `payment_status: "unverified"` disclaimer.
  - Lacks image preprocessing (grayscale/thresholding/upscaling), lacks multi-language Indian traineddata, lacks structured field extraction (UPI IDs, amounts, UTRs, dates), and lacked a dedicated OCR scam classifier.

---

## 3. Existing Message & Email Detection
- **Extension**: `extension/rules.js` (`analyzeText`, `analyzeEmail`, `scanText`, `scanEmail`) + `extension/ml_inference.js`.
- **Backend**: `supabase/functions/_shared/detectionEngine.ts`, `supabase/functions/analyze-scam/index.ts`, `supabase/functions/scan-email/index.ts`.
- **Gap**: Previously, SMS/WhatsApp/general messages shared `text_email` without a dedicated message-specific feature extractor (`URL`/`UPI`/`phone` extraction + OTP-negation + coercion features) or dedicated `splits_v4/message_*.json` splits.

---

## 4. Existing UPI & Payment Verification
- **Extension & Backend**: `extension/rules.js` (`analyzeUpi`, `analyzeQrCode`, `analyzePaymentMessage`, `analyzePaymentScreenshot`) and `supabase/functions/verify-payment-risk/index.ts`.
- **Gap**: Lacked explicit 7-state separation (`FORMAT_VALID`, `HANDLE_SUPPORTED`, `PROVIDER_LOOKUP_AVAILABLE`, `RECIPIENT_VERIFIED`, `REPUTATION_SIGNAL_AVAILABLE`, `SUSPICIOUS_PATTERN`, `UNKNOWN`), lacked a provenance-tracked handle registry, and lacked a corroborated `ReputationStore` resistant to single unverified user reports.

---

## 5. Existing Security & Privacy Controls
- `extension/content_guard.js` extracts sanitized visible text only (never `document.cookie` or input values).
- `ml/training/prepare_datasets.py` (`scrub_pii`) masks emails, phone numbers, and account numbers before dataset storage.
- `extension/rules.js` + `extension/background.js` enforce deterministic authority for blocking (`hasStrongDeterministicEvidence`).
