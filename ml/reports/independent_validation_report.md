# ScamShield — Independent ML Model Validation & Benchmark Verification Report

**Audit Date:** 2026-11-26  
**Scope:** Independent verification of candidate models `email-model-v1.0.0` (`TFIDF_LinearSVM`) and `url-model-v1.0.0` (`Structured_RandomForest`) without modifying code, datasets, or artifacts.

---

## 1. Executive Summary

- **Metric Reproducibility (`VERIFIED`)**: All previously reported held-out test metrics for both `email-model-v1.0.0` (Accuracy `96.34%`, Macro F1 `94.20%`, FPR `2.34%`) and `url-model-v1.0.0` (Accuracy `99.73%`, Macro F1 `99.73%`, FPR `0.21%`) are **100% reproducible** on the existing test splits (`n=1,967` and `n=1,850`) with zero discrepancies.
- **Split & Leakage Integrity (`VERIFIED`)**: Zero exact content overlap, zero normalized content overlap, and zero group/domain overlap (`eTLD+1` for URLs; 50-char normalized prefix for emails) exist across train, validation, and test splits.
- **URL Model Real-World Generalization (`FAILED`)**: Despite `99.73%` test accuracy, `url-model-v1.0.0` **fails real-world generalization** due to severe dataset-collection bias. Because **100.0% of legitimate URLs in `tranco_top_1m` (`n=6,000`) are root-only `https://<domain>/` (`path_length = 1`, `is_https = 1.0`)**, while `94.38%` of malicious URLs have `path_length > 1` and `mitchellkrogza_phishing` has `is_https = 0.0`, the Random Forest learned to classify **any realistic legitimate URL with a path, query string, or auth token** as `malicious` (**9 of 12** realistic legitimate URLs misclassified as `malicious`, 1 as `uncertain`, including IRCTC, `secure.paytmpayments.com`, Microsoft, GitHub, Amazon, HDFC, and Razorpay).
- **Email Model Generalization (`CONCERN`)**: `email-model-v1.0.0` generalizes substantially better (`96.34%` accuracy, calibrated ECE `0.0118`), but exhibits source-skew (`spam` is `98.7%` from `uci_sms_spam`, `phishing` is `97.6%` from `huggingface_phishing_email`) and a `2.34%` FPR that includes legitimate security advisories and transactional order alerts.
- **Recommendation**: **Do NOT promote `url-model-v1.0.0` to production or integration testing** until legitimate URL training data includes realistic subpaths, query parameters, and OAuth/checkout flows. `email-model-v1.0.0` is **suitable for controlled shadow/integration testing only** alongside deterministic rules.

---

## 2. Audit Methodology

1. Independently inspected split files (`ml/datasets/splits/*.json`), manifests (`ml/datasets/manifests/*.json`), and artifact registry (`ml/artifacts/registry.json`).
2. Executed an isolated read-only Python verification script against `email_model_latest.joblib` and `url_model_latest.joblib` without altering any repository code, data, or artifacts.
3. Recomputed all classification, confusion matrix, ROC-AUC, PR-AUC, and calibration metrics (Brier score, ECE, NLL) on `test` and `validation` splits.
4. Audited all 16 URL features across labels and data sources, and tested 15 safe, offline real-world legitimate and synthetic malicious URLs.
5. Verified SHA-256 checksums and file sizes against `ml/artifacts/registry.json`.

---

## 3. Dataset Integrity Findings (`VERIFIED`)

| Task | Train | Validation | Test | Total | Grouping Strategy |
|---|---:|---:|---:|---:|---|
| **Email** | 9,185 | 1,967 | 1,967 | 13,119 | `normalized_template_prefix` |
| **URL** | 8,635 | 1,850 | 1,850 | 12,335 | `public_suffix_list_registrable_domain` |

- **Email Class Distribution**:
  - Train: `legitimate=6,676`, `phishing=2,082`, `spam=427`
  - Validation: `legitimate=1,377`, `phishing=481`, `spam=109`
  - Test: `legitimate=1,409`, `phishing=459`, `spam=99`
- **URL Class Distribution**:
  - Train: `legitimate=4,084`, `malicious=4,551`
  - Validation: `legitimate=998`, `malicious=852`
  - Test: `legitimate=932`, `malicious=918`

---

## 4. Leakage Findings (`VERIFIED`)

| Check | Email (`train/val/test`) | URL (`train/val/test`) | Status |
|---|---:|---:|---|
| Exact content overlap | `0 / 0 / 0` | `0 / 0 / 0` | **VERIFIED** |
| Normalized content overlap | `0 / 0 / 0` | `0 / 0 / 0` | **VERIFIED** |
| Manifest `group` overlap | `0 / 0 / 0` | `0 / 0 / 0` | **VERIFIED** |
| Independent `eTLD+1` / 50-char prefix overlap | `0 / 0 / 0` | `0 / 0 / 0` | **VERIFIED** |

- Near-duplicate cross-split leakage across all pairs was **NOT TESTED** exhaustively (within-dataset near-duplicate estimation was previously bounded to 1,500 items).

---

## 5. Independently Recomputed Email Metrics (`VERIFIED`)

- **Model**: `email-model-v1.0.0` (`TFIDF_LinearSVM`, isotonic calibration, `n=1,967`)
- **Accuracy**: `0.9634` (`96.34%`)
- **Macro Precision / Recall / F1**: `0.9439` / `0.9401` / `0.9420`
- **Weighted F1**: `0.9634`
- **ROC-AUC**: `0.9882` | **PR-AUC**: `0.9760`
- **False Positive Rate (legitimate)**: `0.0234` (`2.34%`, 33/1,409)
- **False Negative Rate (threat)**: `0.0645` (`6.45%`, 36/558)
- **Confusion Matrix** (`[legitimate, phishing, spam]`):
  - `legitimate`: `[1376, 27, 6]`
  - `phishing`: `[28, 429, 2]`
  - `spam`: `[8, 1, 90]`
- **Uncertain predictions (`< 0.55` confidence)**: `15` | **Mean confidence**: `0.9655`

---

## 6. Independently Recomputed URL Metrics (`VERIFIED`)

- **Model**: `url-model-v1.0.0` (`Structured_RandomForest`, isotonic calibration, `n=1,850`)
- **Accuracy**: `0.9973` (`99.73%`)
- **Macro Precision / Recall / F1 / Weighted F1**: `0.9973`
- **ROC-AUC**: `0.9978` | **PR-AUC**: `0.9973`
- **False Positive Rate (legitimate)**: `0.0021` (`0.21%`, 2/932)
- **False Negative Rate (malicious)**: `0.0033` (`0.33%`, 3/918)
- **Confusion Matrix** (`[legitimate, malicious]`):
  - `legitimate`: `[930, 2]`
  - `malicious`: `[3, 915]`
- **Uncertain predictions (`< 0.55` confidence)**: `0` | **Mean confidence**: `0.9997`

---

## 7. Metric Discrepancies (`VERIFIED`)

- **Zero discrepancies** found between independently recomputed metrics and `ml/reports/email_model_evaluation.json` / `ml/reports/url_model_evaluation.json`.

---

## 8. Dataset Bias Investigation (`CONCERN` / `FAILED`)

### URL Dataset Source & Collection Bias (`FAILED`)
- **Source-to-Label Coupling**:
  - `legitimate`: `6,000 / 6,014` (`99.77%`) come from `tranco_top_1m`.
  - `malicious`: `5,998 / 6,321` (`94.89%`) come from `mitchellkrogza_phishing`; `299` (`4.73%`) from `openphish_feed`.
- **Structural Collection Artifact**:
  - **100.00%** of `tranco_top_1m` URLs are synthesized root URLs (`https://<domain>/`) with `path_length = 1.0`, `query_length = 0.0`, `is_https = 1.0`, `is_ip_host = 0.0`, `suspicious_token_hits = 0.0020`.
  - Conversely, `mitchellkrogza_phishing` has `is_https = 0.0`, `is_ip_host = 0.6891`, mean `path_length = 48.57`, mean `query_length = 23.27`, and `url_length = 96.09`.
  - Only `5.62%` of malicious URLs have `path_length <= 1`.

### Email Dataset Source Skew (`CONCERN`)
- `spam` (`n=635`): `627` (`98.7%`) originate from `uci_sms_spam` (short SMS format), creating a format-to-class correlation.
- `phishing` (`n=3,022`): `2,949` (`97.6%`) originate from `huggingface_phishing_email`.

---

## 9. Email Model Generalization Analysis (`CONCERN`)

- The `TFIDF_LinearSVM` model generalizes well within the held-out test split (`96.34%` accuracy, `0.9882` ROC-AUC), with consistent error rates across `huggingface_phishing_email` (`21` FP, `26` FN) and `uci_sms_spam` (`8` FP, `8` FN).
- **Weakness**: `2.34%` FPR is still above the `1.0%` production gate target, and legitimate security advisories (e.g., bank warnings saying *"Never share your password"*) and transactional order alerts are occasionally misclassified due to bag-of-words n-gram overlap without negation/context awareness.

---

## 10. URL Model Generalization Analysis (`FAILED`)

- Random Forest feature importances confirm the model relies primarily on collection artifacts rather than phishing semantics:
  - `is_https`: `0.3391`
  - `path_length`: `0.1828`
  - `url_length`: `0.1401`
  - `digit_ratio_url`: `0.1326`
  - `dot_count_host`: `0.1016`
  - `is_ip_host`: `0.0366`
  - `is_risky_tld`: `0.0004`
- Because real-world legitimate websites have paths, query parameters, subdomains, and authentication/payment tokens (`login`, `secure`), the `99.73%` test accuracy does **not** generalize outside the synthetic root-URL distribution.

---

## 11. Calibration Verification (`VERIFIED` for Email, `CONCERN` for URL)

- **Split Isolation (`VERIFIED`)**: Both calibrators were fitted strictly on `validation` splits and evaluated on `test` splits (`ml/reports/calibration_report.json` compares `test_uncalibrated` vs `test_calibrated` cleanly, without mixing validation and test metrics).
- **Email Calibration (`VERIFIED`)**: Isotonic calibration substantially improved test calibration:
  - Brier: `0.0844 -> 0.0614` | ECE: `0.1095 -> 0.0118` | NLL: `0.2073 -> 0.1443`.
- **URL Calibration (`CONCERN`)**: Because `Structured_RandomForest` achieved `100.0%` validation accuracy, isotonic calibration overfit to extreme `1.0` probabilities, slightly **degrading** test calibration:
  - Brier: `0.0042 -> 0.0049` | ECE: `0.0021 -> 0.0024` | NLL: `0.0080 -> 0.0357` (misclassified test URLs received `100.0%` confidence).

---

## 12. Legitimate URL Regression Results (`FAILED` on Non-Root Legitimate URLs)

Tested offline via `predict_url()` (`url-model-v1.0.0`):

| URL | Expected | Predicted | Risk Score | Confidence | Status |
|---|---|---|---:|---:|---|
| `https://paytm.com/` | legitimate | `legitimate` | 0 | 100.0% | completed |
| `https://www.google.com/search?q=irctc+pnr+status` | legitimate | `legitimate` | 0 | 100.0% | completed |
| `https://retail.onlinesbi.sbi/retail/login.htm` | legitimate | `uncertain` | 52 | 51.61% | uncertain |
| `https://www.irctc.co.in/nget/train-search` | legitimate | **`malicious`** | 58 | 58.06% | completed |
| `https://www.irctc.co.in/nget/booking/check-train-schedule?trainNo=12951` | legitimate | **`malicious`** | 100 | 100.0% | completed |
| `https://secure.paytmpayments.com/theia/api/v1/showPaymentPage?mid=IRCTC123&orderId=ORD998877` | legitimate | **`malicious`** | 100 | 100.0% | completed |
| `https://accounts.paytm.com/oauth2/authorize?client_id=paytm-web&redirect_uri=...` | legitimate | **`malicious`** | 100 | 100.0% | completed |
| `https://login.microsoftonline.com/common/oauth2/v2.0/authorize?...` | legitimate | **`malicious`** | 100 | 100.0% | completed |
| `https://github.com/login?return_to=%2Fsettings%2Fprofile` | legitimate | **`malicious`** | 100 | 100.0% | completed |
| `https://www.amazon.in/ap/signin?...` | legitimate | **`malicious`** | 100 | 100.0% | completed |
| `https://netbanking.hdfcbank.com/netbanking/` | legitimate | **`malicious`** | 100 | 100.0% | completed |
| `https://api.razorpay.com/v1/checkout/public?key_id=rzp_live_123456` | legitimate | **`malicious`** | 100 | 100.0% | completed |
| `http://xn--pypal-4ve.com/signin` | malicious | `malicious` | 100 | 100.0% | completed |
| `http://paytrn-security.xyz/verify-kyc` | malicious | `malicious` | 100 | 100.0% | completed |
| `http://192.168.1.10/login.php` | malicious | `malicious` | 100 | 100.0% | completed |

---

## 13. Error Analysis

- **URL Test Errors (`n=5`)**:
  - **2 False Positives** (`administracionelectronica.gob.es`, `browser-intake-us5-datadoghq.com`): long domain names / hyphens / digits triggered `host_length` and `digit_ratio_url` thresholds.
  - **3 False Negatives** (`couriersplease.addlik.com`, `tokevim-cdn-hk0.homes`, `client.tkchost.com`): all 3 are `https://` root-only phishing URLs (`path_length = 1`), mimicking the `tranco_top_1m` collection pattern.
- **Email Test Errors (`n=69`: `33` FP, `36` FN)**:
  - **False Positives**: Promotional newsletters (e.g., *"Special Bonus... Free"*), security awareness advisories containing *"password"* / *"ATM/SMS PIN"*, and legitimate transactional order SMS containing *"order"* + domain links.
  - **False Negatives**: Short conversational/obfuscated messages lacking standard phishing keywords.

---

## 14. Artifact Integrity (`VERIFIED`)

| Artifact Key | Exists | SHA-256 Match | Size (bytes) | `production_active` |
|---|---|---|---:|---|
| `email:email-model-v1.0.0` | True | **True** | 259,796 | `false` |
| `url:url-model-v1.0.0` | True | **True** | 266,351 | `false` |

All checksums, sizes, and `production_active: false` flags match `ml/artifacts/registry.json`.

---

## 15. Limitations

- Live browsing and real-time Chrome extension E2E inference against `url-model-v1.0.0` were **NOT TESTED** (by design, per audit restrictions).
- Temporal generalization across newer phishing campaigns was **NOT TESTED** due to missing per-record event timestamps in the staged datasets.

---

## 16. Risk Assessment

- **High Risk (URL Model)**: Deploying `url-model-v1.0.0` would cause widespread false positives (`~75%` on tested realistic legitimate URLs) across banking, payment, and OAuth flows.
- **Moderate Risk (Email Model)**: `2.34%` FPR on legitimate emails/messages requires deterministic safeguards and user-friendly caution states rather than hard blocking.

---

## 17. Recommended Next Phase

1. **Fix URL Dataset Bias (Priority 1)**: Enrich legitimate URLs with realistic HTTPS paths, query parameters, OAuth callbacks, and checkout URLs (e.g., CommonCrawl / sitemap URLs from Tranco domains) AND add HTTPS root-only phishing URLs so `is_https` and `path_length = 1` are not shortcuts.
2. **Re-evaluate URL Calibration**: Prefer Platt/Temperature scaling or cross-validated calibration when validation accuracy approaches `100%` to avoid `1.0` probability overfitting.
3. **Email Negation & Hard-Negative Mining**: Add legitimate security advisories and transactional order notifications to the email training/review set to lower FPR below `1.0%`.
