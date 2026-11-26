# ScamShield Phase 2 — Hard-Negative Dataset Reconstruction & Candidate Model Report

**Date:** 2026-11-26  
**Dataset Version:** `2.3.0` (`ml/datasets/splits_v2/`, `ml/datasets/manifests/{url,email}_v2_manifest.json`)  
**Candidate Models:** `url-model-v2.0.0`, `email-model-v2.0.0` (`production_active: false`; `v1.0.0` preserved)

---

## 1. Dataset Versions
- **v1.0/v2.2.0 (Preserved)**: `ml/datasets/splits/` (`url_manifest.json`, `email_manifest.json`)
- **v2.3.0 (New)**: `ml/datasets/splits_v2/` (`url_v2_manifest.json`, `email_v2_manifest.json`)

---

## 2–4. Source Inventory, Licenses & Provenance

| Source ID | Provenance Type | License | Content |
|---|---|---|---|
| `tranco_top_1m` | Verified public data | Open Research Data | Legitimate root domains (subsampled `1,500`) |
| `mitchellkrogza_phishing` | Verified public data | MIT | HTTP/IP phishing URLs (subsampled `1,500`) |
| `openphish_feed` | Verified public data | CC-BY-NC 4.0 | Active phishing URLs (`299`, incl. `163` HTTPS) |
| `verified_review` | Verified human-reviewed | ScamShield Open Source | Human-reviewed URLs & emails (`verified_samples.json`) |
| `huggingface_phishing_email` | Verified public data | Open Cybersecurity Research | Safe & phishing emails (`6,000` sampled) |
| `uci_sms_spam` | Verified public data | Open Data Commons / CC-BY | Ham & spam SMS (`3,000` sampled) |
| `cert_in_i4c_curated` | Curated hard-negative | ScamShield Open Source | Indian cyber fraud & Digital Arrest patterns |
| `scamshield_curated_legit_urls` | Curated hard-negative | ScamShield Open Source | `67` realistic legitimate auth/OAuth/payment/API URLs |
| `scamshield_curated_malicious_urls` | Curated hard-negative | ScamShield Open Source | `26` HTTPS root/nested/OAuth/punycode/IP phishing URLs |
| `scamshield_curated_legit_emails` | Curated hard-negative | ScamShield Open Source | `14` legitimate bank advisories, receipts, OTPs, resets |
| `scamshield_curated_malicious_emails` | Curated hard-negative | ScamShield Open Source | `10` short/obfuscated/fake-payment/impersonation emails |

---

## 5–8. Dataset Sizes, Class Distributions & Structure Breakdown

### URL v2.3.0 (`total = 3,430` after deduplication)
- **Splits (70/15/15, `public_suffix_list_registrable_domain` grouped)**:
  - `train`: `2,399` (`malicious=1,326`, `legitimate=1,073`)
  - `validation`: `514` (`legitimate=258`, `malicious=256`)
  - `test`: `517` (`malicious=276`, `legitimate=241`)
- **Test URL Structure Breakdown**:
  - `http_root`: `18` | `https_root`: `243` | `http_nested`: `239` | `https_nested`: `17`

### Email v2.3.0 (`total = 8,917` after deduplication)
- **Splits (70/15/15, `normalized_template_prefix` grouped)**:
  - `train`: `6,243` (`legitimate=4,398`, `phishing=1,580`, `spam=265`)
  - `validation`: `1,337` (`legitimate=918`, `phishing=354`, `spam=65`)
  - `test`: `1,337` (`legitimate=923`, `phishing=365`, `spam=49`)

---

## 9–10. Source-to-Label Bias & Leakage Analysis
- **Bias Control**: Subsampling `mitchellkrogza_phishing` (`6,000 -> 1,500`) and `tranco_top_1m` (`6,000 -> 1,500`) reduced the `20:1` dominance of HTTP/IP phishing over HTTPS phishing, and adding `scamshield_curated_legit_urls` / `scamshield_curated_malicious_urls` introduced nested HTTPS paths and query strings into both classes.
- **Zero Leakage Verified**: `zero_group_leakage = true` and `zero_content_leakage = true` for both URL v2 and Email v2 across all split boundaries.

---

## 11–12. Model Benchmark Comparison & Independent Test Metrics

### URL Candidates (Validation) & Selected `url-model-v2.0.0`
| Model | Train (s) | Val Accuracy | Val Macro F1 | Val FPR |
|---|---:|---:|---:|---:|
| `Structured_LogisticRegression_Baseline` | 0.022 | 0.9844 | 0.9844 | 1.16% |
| `Structured_RandomForest` | 0.222 | 0.9942 | 0.9942 | 0.78% |
| `Structured_HistGradientBoosting` (**selected**) | 0.196 | 0.9981 | 0.9981 | 0.39% |
| `Hybrid_CharTFIDF_Structured_LogisticRegression` | 0.060 | 0.9883 | 0.9883 | 0.78% |

- **URL v2.0.0 Held-Out Test (`n=517`)**:
  - Accuracy: `0.9845` | Macro Precision: `0.9841` | Macro Recall: `0.9850` | Macro F1: `0.9845` | Weighted F1: `0.9845`
  - ROC-AUC: `0.9850` | PR-AUC: `0.9827` | **FPR**: `0.83%` (2/241) | **FNR**: `2.17%` (6/276)
  - Size: `0.1563 MB` | Latency: `0.0358 ms/sample`
  - **By Structure**: `http_root` `100%` (18/18), `https_root` `98.77%` (240/243), `http_nested` `100%` (239/239), `https_nested` `70.59%` (12/17).

### Email Candidates (Validation) & Selected `email-model-v2.0.0`
| Model | Train (s) | Val Accuracy | Val Macro F1 | Val FPR |
|---|---:|---:|---:|---:|
| `TFIDF_LogisticRegression_Baseline` (**selected**) | 0.275 | 0.9544 | 0.9247 | 2.61% |
| `TFIDF_LinearSVM` | 0.042 | 0.9551 | 0.9180 | 1.85% |
| `Hybrid_TFIDF_Structured_LogisticRegression` | 0.790 | 0.9491 | 0.9177 | 3.27% |
| `Structured_RandomForest` | 0.274 | 0.8168 | 0.7898 | 15.25% |

- **Email v2.0.0 Held-Out Test (`n=1,337`)**:
  - Accuracy: `0.9521` | Macro Precision: `0.9173` | Macro Recall: `0.9018` | Macro F1: `0.9094` | Weighted F1: `0.9519`
  - ROC-AUC: `0.9863` | PR-AUC: `0.9705` | **FPR**: `2.60%` (24/923) | **FNR**: `8.45%` (35/414)
  - Size: `0.2594 MB` | Latency: `0.1653 ms/sample`

---

## 13. Calibration Comparison
- **Email v2.0.0**: Isotonic calibration improved test Brier (`0.0946 -> 0.0757`), ECE (`0.0875 -> 0.0057`), and NLL (`0.2048 -> 0.1616`).
- **URL v2.0.0**: On validation, isotonic achieved `0.0` Brier/ECE/NLL (vs. temperature `0.0017`/`0.0017`/`0.0024`, platt `0.0018`/`0.0034`/`0.0040`), but on test isotonic slightly degraded Brier (`0.0279 -> 0.0309`) and NLL (`0.0717 -> 0.2494`) due to extreme `1.0` predictions on 8 test errors. Temperature/Platt scaling should be preferred for URL calibration in the next iteration.

---

## 14–18. Regression Results & False-Positive / False-Negative Changes

### Legitimate URL Regression (`11/12` fixed vs. `2/12` in `v1.0.0`)
- **Fixed (`legitimate`, `risk_score=0`)**: `https://www.irctc.co.in/nget/train-search`, `https://www.irctc.co.in/nget/booking/check-train-schedule?trainNo=12951`, `https://paytm.com/`, `https://secure.paytmpayments.com/theia/api/v1/showPaymentPage?mid=IRCTC123&orderId=ORD998877`, `https://accounts.paytm.com/oauth2/authorize?...`, `https://www.google.com/search?q=irctc+pnr+status`, `https://login.microsoftonline.com/common/oauth2/v2.0/authorize?...`, `https://github.com/login?return_to=%2Fsettings%2Fprofile`, `https://www.amazon.in/ap/signin?...`, `https://retail.onlinesbi.sbi/retail/login.htm`, `https://api.razorpay.com/v1/checkout/public?key_id=rzp_live_123456`.
- **Remaining FP (`1/12`)**: `https://netbanking.hdfcbank.com/netbanking/` (`malicious`).
- **Malicious URL Regression (`4/4` detected)**: `xn--pypal-4ve.com/signin`, `paytrn-security.xyz/verify-kyc`, `192.168.1.10/login.php`, `paytm-kyc-update-2026.xyz/`.

### Email Hard-Negative Checks
- **Passed (`3/4`)**: Bank Advisory (`legitimate`, `83.19%`), Amazon Order (`legitimate`, `94.75%`), Phishing KYC (`phishing`, `98.39%`).
- **Remaining FP (`1/4`)**: GitHub Security notification (`phishing`, `73.78%`).

---

## 19. Model Artifact Checksums (v1.0.0 Preserved)
- `url-model-v2.0.0` (`ml/artifacts/url_model_url-model-v2.0.0.joblib`): `163,904` bytes, SHA-256 `1cfdf976ab6e9cd49ecfccdf93fa22433f9c2020b7ca6f9e37a90b8eb94be837`, `production_active: false`.
- `email-model-v2.0.0` (`ml/artifacts/email_model_email-model-v2.0.0.joblib`): `272,033` bytes, SHA-256 `16d716aaec695cbaa487f5d47ad5f8d321e3e3455566bce29c7b9420ba6fb9f1`, `production_active: false`.

---

## 20. Remaining Limitations
1. `https_nested` URLs in `url_v2` test (`n=17`, `70.59%` accuracy) remain underrepresented compared to `https_root` (`n=243`) and `http_nested` (`n=239`); ingesting a larger public crawl of legitimate subpages (e.g., Common Crawl) and HTTPS phishing URLs (e.g., URLhaus/PhishTank) is recommended before production promotion.
2. URL isotonic calibration still overfits when validation accuracy is `99.81%`; temperature scaling is recommended for `url-model-v2.1.0`.
3. Email FPR (`2.60%`) remains above the `1.0%` production gate threshold.
