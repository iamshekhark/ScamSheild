# ScamShield Phase 4 — Track A: OCR Scam Detection Report

**Date:** 2026-11-26  
**Candidate Model:** `ocr-scam-model-v1.0.0` (`CharTFIDF_LinearSVM`, `production_active: false`)  
**Decision:** **`NEEDS MORE DATA`**

---

## 1. Existing OCR Architecture Audit (`extension/ocr/ocr_engine.js`)
- **OCR Engine**: Tesseract.js (`tesseract-core-lstm.wasm.js`, LSTM neural OCR) with English-only `eng.traineddata.gz` (no Devanagari/Hindi traineddata bundled).
- **QR Decoder**: `jsQR` (`extension/ocr/jsQR.js`).
- **Image Preprocessing**: None (raw canvas `getContext("2d")` without grayscale, thresholding, upscaling, or deskewing).
- **Classification**: No dedicated OCR ML model or image-forgery model existed; extracted text was forwarded to `ScamEngine.scanPayment(..., "screenshot")` and `ScamEngine.scanText(...)`.
- **Fail-Safe Gap**: On OCR recognition failure with no QR code (`ocr_engine.js` L252–268), it returns `risk_level: "SAFE"` (`0/100`) rather than `UNABLE_TO_VERIFY`.
- **Security Invariant**: `payment_status` is strictly `"unverified"` with permanent disclaimer.

---

## 2. Dataset Provenance, Cleaning & Splits (`splits_v4/ocr_*.json`)
- **Sources**: `scamshield_ocr_curated` (`16` curated payment/scam screenshots), `synthetic_ocr_noise` (`16` degraded OCR perturbations simulating blur/low-res `0/O`, `1/l`, `5/S` errors), `curated_payments` (`44`), `cert_in_i4c_curated` (`44`).
- **Grouped Splits (`extract_text_group`)**: `train=80`, `validation=16`, `test=17` (`legitimate=36`, `scam=77` total after deduplication; clean and noisy variants share group keys to prevent leakage).
- **Privacy**: Phone numbers are redacted (`[REDACTED_PHONE]`) during structured field extraction (`ml/ocr_model/field_extractor.py`).

---

## 3. Extraction & Classification Evaluation (`ml/reports/phase4_ocr_eval.json`)
- **Text Degradation & Field Extraction (`n=16` curated pairs)**:
  - Average CER (simulated OCR noise): `0.0798` (`7.98%`) | Average WER: `0.1294` (`12.94%`)
  - UPI ID Extraction Precision / Recall: `1.0000` / `1.0000`
  - Amount Extraction Accuracy: `1.0000`
- **Scam Classifier (`ocr-scam-model-v1.0.0`, `n=17` test)**:
  - Validation: `CharTFIDF_LinearSVM` `0.8750` macro F1 vs `CharTFIDF_LogisticRegression` `0.7333`
  - Test Accuracy: `0.9412` | Macro F1: `0.9244` | FPR: `20.00%` (1/5) | FNR: `0.00%` (0/12)
  - Calibration (`none` selected on small val): Brier `0.1461`, ECE `0.1330`, NLL `0.2392`
  - Size: `0.031 MB` (`32,756` bytes, SHA-256 `ae24da09a6ff2a0a5aaccf97a8a81bd03cce1bd6a39aa0d760bb0a94ea1bdc34`) | Latency: `0.0286 ms/sample`

---

## 4. Limitations, Privacy & Blockers
- **Why `NEEDS MORE DATA`**: Only `17` test samples (`5` legitimate), `0` real-world multilingual/cropped mobile screenshots (no Hindi `hin.traineddata`), and `20%` test FPR (far above the `<= 0.10%` target). Real Tesseract.js WASM image-to-text benchmarking on real screenshots was not executed in Python (`pytesseract` not installed).
- **Next Steps**: Collect >= 3,000 real/consent-verified legitimate & scam screenshots across English and Indian languages, add canvas contrast/upscaling preprocessing, and fix `SAFE` fallback on OCR failure to `UNABLE_TO_VERIFY`.
