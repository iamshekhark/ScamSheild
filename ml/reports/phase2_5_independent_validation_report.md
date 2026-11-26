# ScamShield Phase 2.5 — Independent Robustness Validation & Calibration Review

**Review Date:** 2026-11-26  
**Candidate Models Reviewed:** `url-model-v2.0.0`, `email-model-v2.0.0` (`production_active: false`)  
**Scope:** Read-only independent validation; no models activated, retrained, or deployed.

---

## 1. Executive Summary

- **`url-model-v2.0.0` Decision: `NEEDS MORE DATA`**  
  While `url-model-v2.0.0` (`Structured_HistGradientBoosting`) dramatically reduced false positives on realistic legitimate URLs compared to `v1.0.0`, independent auditing revealed four blockers: (1) `9/16` URLs in the Phase 2 regression table overlapped with `train` or `validation` splits (and `3` more shared a `train` domain); (2) the `https_nested` test slice has only `17` samples with `50.0%` recall (`4` false negatives including `paypa1.com` and `bit.ly`); (3) structural-only features lack character-level lexical awareness, missing typosquats (`paypa1.com`, `mfacebocks.com.vn`) and shorteners (`cutt.ly`, `bit.ly`); and (4) isotonic calibration degraded test NLL (`0.0717 -> 0.2494`) by assigning `100.0%` confidence to all `8` test errors.
- **`email-model-v2.0.0` Decision: `SHADOW TEST READY`**  
  `email-model-v2.0.0` (`TFIDF_LogisticRegression_Baseline`) achieved `95.21%` test accuracy, `0.9863` ROC-AUC, `91.51%` phishing recall, and strong isotonic calibration (`ECE = 0.0057`, `Brier = 0.0757`). It is acceptable for **controlled shadow testing** alongside deterministic rules, but not production activation until FPR (`2.60%`) is reduced below `1.0%`.

---

## 2. Files and Artifacts Inspected

- `ml/reports/phase2_dataset_reconstruction_report.md`, `ml/reports/phase2_v2_evaluation.json`
- `ml/datasets/manifests/{url,email}_v2_manifest.json`
- `ml/datasets/splits_v2/{url,email}_{train,validation,test}.json`
- `ml/url_model/feature_extraction.py`, `ml/email_model/preprocessing.py`
- `ml/calibration/calibrate.py`, `ml/artifacts/registry.json`
- `ml/artifacts/url_model_url-model-v2.0.0.joblib`, `ml/artifacts/email_model_email-model-v2.0.0.joblib`
- `extension/rules.js`, `extension/background.js`, `extension/ml_inference.js`

---

## 3. Dataset Provenance and Quality

- **Verified Public Sources**: `tranco_top_1m` (`1,500`), `mitchellkrogza_phishing` (`1,500`), `openphish_feed` (`299`), `huggingface_phishing_email` (`6,000`), `uci_sms_spam` (`3,000`), `verified_samples.json`.
- **Curated Hard-Negatives**: `scamshield_curated_legit_urls` (`67`), `scamshield_curated_malicious_urls` (`26`), `scamshield_curated_legit_emails` (`14`), `scamshield_curated_malicious_emails` (`10`), `cert_in_i4c_curated`.
- **Quality Finding**: Curated samples are representative of real banking/OAuth/checkout structures, but because they are small (`67` legit URLs, `26` malicious URLs) compared to `tranco_top_1m` (`1,500`) and `mitchellkrogza_phishing` (`1,500`), `https_nested` coverage remains sparse (`17` test samples).

---

## 4. Leakage Audit

- **Split Leakage (`VERIFIED`)**: Zero exact content, normalized content, and registrable-domain / template-prefix overlap across `train`, `validation`, and `test` for both `url_v2` and `email_v2`.
- **Phase 2 Regression Contamination (`CONCERN` — Discrepancy Found)**:  
  Auditing the 16 regression URLs in `phase2_v2_evaluation.json` against `splits_v2`:
  - `7` exact URLs were in `train` (`paytm.com/`, `secure.paytmpayments.com/...`, `google.com/search...`, `github.com/login...`, `amazon.in/ap/signin...`, `api.razorpay.com/...`, `xn--pypal-4ve.com/signin`).
  - `3` exact URLs were in `validation` (`irctc.co.in/...` x2, `paytm-kyc-update-2026.xyz/`).
  - `3` additional URLs were unseen exact strings whose registrable domain appeared in `train` (`accounts.paytm.com`, `login.microsoftonline.com`, `paytrn-security.xyz`).
  - Only `3` URLs were in `test` (`retail.onlinesbi.sbi/retail/login.htm`, `netbanking.hdfcbank.com/netbanking/`, `192.168.1.10/login.php`).

---

## 5. URL Robustness Results & HDFC Investigation

### Investigation of `https://netbanking.hdfcbank.com/netbanking/`
- **Independent Verification**: `netbanking.hdfcbank.com` is the official HDFC Bank NetBanking portal.
- **Model Verdict**: `malicious` (`raw_mal_prob = 0.9712`, `calibrated = 100.0%`).
- **Feature Values & Perturbation Analysis** (resetting each feature to the `train` legitimate median):
  - `host_entropy = 3.741` (legit median `3.1219`) -> resetting drops `raw_mal_prob` by **`-0.9476`** (to `0.0236`).
  - `url_length = 43.0` (legit median `20.0`) -> resetting drops `raw_mal_prob` by **`-0.9300`** (to `0.0412`).
  - `dot_count_host = 2.0` (legit median `1.0`) -> resetting drops `raw_mal_prob` by **`-0.7340`** (to `0.2372`).
  - `host_length = 23.0` (legit median `11.0`) -> resetting drops `raw_mal_prob` by **`-0.0524`**.
- **Root Cause**: `Structured_HistGradientBoosting` has no lexical/n-gram features and treats higher host entropy + length + subdomain dot count as malicious when `path_length = 12`.

### Additional Robustness Test Cases (15 Safe Offline URLs)
- **Legitimate (`9/10` passed)**:
  - Passed (`legitimate`, `100.0%`): `www.hdfcbank.com/personal/ways-to-bank/...`, `www.icicibank.com/...`, `checkout.paytm.com/v1/payment?...`, `oauth.reddit.com/api/v1/authorize?...`, `login.live.com/oauth20_authorize.srf?...` (**completely unseen domain**), `docs.github.com/...`, `www.flipkart.com/checkout/init?...`, `api.stripe.com/v1/checkout/sessions?...`, `www.amazon.in/dp/...?utm_source=...`.
  - Failed (`malicious`, `100.0%`): `https://portal.hdfcbank.com/signin` (same host-entropy/subdomain pattern as `netbanking.hdfcbank.com`).
- **Malicious (`4/5` passed, all unseen)**:
  - Caught (`malicious`, `100.0%`): `https://paytm-kyc-reverify-portal.top/auth/login?id=8821`, `https://sbi-netbanking-unblock.icu/`, `https://xn--microsft-0za.com/login`, `http://198.51.100.88/hdfc/netbanking/login.php`.
  - Missed (`legitimate`, `100.0%`): `https://cutt.ly/urgent-hdfc-kyc-update` (shortener abuse missed due to short host/entropy).

---

## 6. HTTPS Nested URL Results (`INCONCLUSIVE`)

Evaluated on all `https_nested` samples in `url_v2` test (`n=17`: `9` legitimate, `8` malicious):
- **Precision**: `80.0%` (4/5) | **Recall**: `50.0%` (4/8) | **FPR**: `11.11%` (1/9) | **FNR**: `50.0%` (4/8)
- **Confidence**: All `17` predictions output `100.0%` calibrated confidence (including all 5 errors).
- **Error Examples**:
  - FP: `https://netbanking.hdfcbank.com/netbanking/`
  - FNs: `https://bit.ly/sbi-kyc-urgent-verify`, `https://mfacebocks.com.vn/elcfvqvdam?q4`, `https://paypa1.com/login-verify`, `https://paypa1.com/account/security-challenge`
- **Status**: Explicitly **INCONCLUSIVE** due to small sample size (`n=17`) and `50.0%` recall on typosquats/shorteners.

---

## 7. URL Calibration Comparison (Val -> Untouched Test, `n=517`)

| Method | Test Brier | Test ECE | Test NLL | Notes |
|---|---:|---:|---:|---|
| **Uncalibrated** | **0.0279** | **0.0138** | **0.0717** | Best across all 3 calibration metrics |
| **Temperature (`T=0.3` on val)** | 0.0293 | 0.0150 | 0.2021 | `T < 1` sharpened probabilities |
| **Isotonic (current `v2.0.0`)** | 0.0309 | 0.0155 | 0.2494 | Overfit on val; assigned `1.0` to all 8 test errors |

All `8` test errors (`2` FPs, `6` FNs) received `1.0` confidence under isotonic calibration (vs. `0.5856`–`0.9991` uncalibrated).

---

## 8–9. Email False-Positive & False-Negative Analysis (`email-model-v2.0.0`, `n=1,337`)

- **Per-Class Metrics**:
  - `legitimate` (`n=923`): Precision `0.9625`, Recall `0.9740`, F1 `0.9682`
  - `phishing` (`n=365`): Precision `0.9382`, Recall `0.9151`, F1 `0.9265`
  - `spam` (`n=49`): Precision `0.8511`, Recall `0.8163`, F1 `0.8333`
- **Confusion Matrix** (`[legitimate, phishing, spam]`):
  - `legitimate`: `[899, 19, 5]` | `phishing`: `[29, 334, 2]` | `spam`: `[6, 3, 40]`
- **FPR**: `2.60%` (`24/923`) | **FNR**: `8.45%` (`35/414`)
- **False Positives by Category (`24`)**: `internal_business_or_other` (`14`), `customer_support` (`4`), `newsletter` (`4`), `legitimate_promotional` (`1`), `transaction_notification` (`1`).
- **False Negatives by Category (`35`)**: `other_phishing_or_spam` (`23`), `short_conversational_phishing` (`8`), `obfuscated_or_embedded_url` (`3`), `urgent_payment_or_impersonation` (`1`).

---

## 10. Independent Evaluation Limitations
- No genuinely independent external crawl/temporal holdout was available offline; the `unseen_urls` check (`n=15`) is a small diagnostic sample, not a statistical benchmark.
- Email category breakdown used deterministic keyword heuristics on sanitized test records.

---

## 11. Production Architecture Safety Review (`VERIFIED`)
Inspected [extension/rules.js](file:///c:/vs%20code/scamshield-extension/extension/rules.js), [extension/background.js](file:///c:/vs%20code/scamshield-extension/extension/background.js), and [extension/ml_inference.js](file:///c:/vs%20code/scamshield-extension/extension/ml_inference.js) without modification:
- Deterministic `HIGH`/`CRITICAL` rules cannot be downgraded by ML (`rules.js` lines 962–968).
- Blocking (`should_block`) requires strong deterministic `HIGH`/`CRITICAL` evidence (`background.js` `hasStrongDeterministicEvidence`), preventing ML-only false positives from blocking pages.
- Missing/invalid/OOD model states return `unavailable` / `uncertain` / `UNABLE_TO_VERIFY`, never `SAFE`.
- Inference latency is `<0.2 ms/sample` (`0.036 ms` URL, `0.165 ms` Email).

---

## 12–14. Recommendations, Blockers & Reproducibility

| Model | Final Decision | Primary Blockers |
|---|---|---|
| **`url-model-v2.0.0`** | **`NEEDS MORE DATA`** | `https_nested` inconclusive (`n=17`, `50%` recall); misses `paypa1.com` & `bit.ly` without char n-grams; isotonic calibration overfits to `1.0` |
| **`email-model-v2.0.0`** | **`SHADOW TEST READY`** | Acceptable for controlled shadow testing; FPR (`2.60%`) must drop below `1.0%` before production |

**Reproducibility**: All measurements were produced from `ml/datasets/splits_v2/*.json` and `ml/artifacts/*-v2.0.0.joblib` (`python ml/experiments/run_phase2_v2_pipeline.py`, `python -m unittest discover -s ml/tests -v`). Both candidates remain `production_active: false`.
