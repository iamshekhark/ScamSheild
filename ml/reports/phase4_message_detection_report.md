# ScamShield Phase 4 — Track B: Message Scam Detection Report

**Date:** 2026-11-26  
**Candidate Model:** `message-model-v1.0.0` (`Hybrid_WordCharTFIDF_Structured_LinearSVM`, `production_active: false`)  
**Decision:** **`SHADOW TEST READY`** (for spam/legitimate filtering; `phishing` class needs more SMS/WhatsApp samples)

---

## 1. Existing Architecture & Task Separation
- Previously, `ScamEngine.scanText` routed both SMS/messages and webpage DOM text into `text_email`. Webpage isolation was fixed in `extension/rules.js`, while Track B introduces a dedicated `ml/message_model/` pipeline for SMS/WhatsApp/general messages (`ml/message_model/features.py`, `train_and_evaluate.py`).
- Combines word n-grams (`1–2`), char_wb n-grams (`3–5`), and 12 structured features (URLs, UPI IDs, phone numbers, OTP-negation awareness, coercion keywords, payment demand, brand mentions, contextual prize-to-payment link).

---

## 2. Dataset Provenance & Splits (`splits_v4/message_*.json`)
- **Sources**: `uci_sms_spam` (`5,574` raw: `4,827` legitimate, `747` spam), `cert_in_i4c_curated` (`44` Indian scam/phishing), `verified_review` (`verified_samples.json`), `scamshield_message_curated` (`11` legitimate/scam hard-negatives).
- **PII Scrubbing & Deduplication**: Normalized + PII-scrubbed (`[EMAIL]`, `[PHONE]`, `[ACCOUNT_NUM]`), deduplicated (`5,297` unique records: `legitimate=4,578`, `spam=643`, `phishing=76`).
- **Template-Grouped Splits**: `train=3,709`, `validation=794`, `test=794` (`zero leakage`).

---

## 3. Model Benchmarks & Held-Out Test Evaluation (`ml/reports/phase4_message_eval.json`)
- **Validation Comparison**:
  - `Hybrid_WordCharTFIDF_Structured_LinearSVM` (**selected**): `val_acc=0.9811`, `val_macro_f1=0.8906`, `val_fpr=0.44%`
  - `Hybrid_WordCharTFIDF_Structured_LR`: `val_acc=0.9773`, `val_macro_f1=0.8296`, `val_fpr=0.73%`
  - `Structured_HistGradientBoosting`: `val_acc=0.9610`, `val_macro_f1=0.7361`, `val_fpr=1.31%`
- **Held-Out Test (`n=794`)**:
  - Accuracy: `0.9773` | Macro Precision: `0.7651` | Macro Recall: `0.7090` | Macro F1: `0.7313` | PR-AUC: `0.9463`
  - **FPR (legitimate)**: `0.44%` (`3/682`, **95% Wilson upper bound: `1.29%`** — does not yet meet `<= 0.10%` statistical target)
  - **FNR (threat)**: `10.71%` (`12/112`)
  - **Per-Class Test F1**: `legitimate` `0.9891` (`n=682`), `spam` `0.9548` (`n=102`), `phishing` `0.2500` (`n=10`: `2` TP, `7` missed as legitimate, `1` spam)
  - **Calibration (`isotonic` on val)**: Brier `0.0434`, ECE `0.0099`, NLL `0.1471`
  - **Artifact**: `0.285 MB`, SHA-256 `ae573056...` (recorded in `ml/artifacts/registry.json`), Latency `0.158 ms/sample`.

---

## 4. Limitations & Blockers
- `phishing` class has only `76` total samples (`10` in test), yielding `20%` phishing recall in the pure ML model (deterministic rules in `rules.js` remain essential for `OTP_REQUEST`, `REVERSE_COLLECT_FRAUD`, and `DIGITAL_ARREST_EXTORTION`).
- Legitimate evaluation sample size (`n=682`) gives a 95% Wilson upper bound of `1.29%` (`>= 3,000` zero-error legitimate samples are needed to statistically support `FPR <= 0.10%`).

---

## 5. Cross-Domain 5,518-Sample Legitimate FPR Check (Strict Task Boundary Proof)
Evaluating `message-model-v1.0.0` on `5,518` strictly unseen legitimate samples (`682` SMS test + `4,836` long-form legitimate emails from `email_samples.json`):
- **Total Unseen Legitimate Samples**: `5,518`
- **False Positives**: `4,452` (**FPR: `80.6814%`**, 95% Wilson UCB: `81.7016%`)
- **Root Cause**: `message-model-v1.0.0` was trained on short SMS messages (`uci_sms_spam`), so long-form emails trigger extreme scaled length/word-count values in `MessageHybridFeaturizer`.
- **Conclusion**: Confirms strict task separation—`message-model-v1.0.0` is strictly an **SMS-only** shadow candidate (`SHADOW TEST READY` for SMS only, `REJECT` for cross-domain email/web use) and remains `production_active: false`.
