# ScamShield — Independent URL Holdout Benchmark Validation Report

- **Evaluated At:** 2026-11-01T08:20:25.828165+00:00
- **Holdout Dataset:** `ml/datasets/processed/url_holdout_benchmark.json`
- **Total Untouched Samples:** 28
- **Pure ML Alone Threat Detection Accuracy:** 46.43%
- **ScamShield Hybrid Engine Threat Detection Accuracy:** **82.14%**

## 1. Architectural Case Study: Why Pure ML Alone Misses `paypa1.com`

In pure character-level TF-IDF without domain tokenization, `paypa1.com/login-verify` shares high-frequency authentic n-grams (`login`, `verify`, `pay`, `com`). Because `paypa1` was not in the training set, pure statistical logistic regression predicted `legitimate`.

**The ScamShield Hybrid Guarantee:** ScamShield's deterministic rule engine immediately detected the visual homoglyph typosquat (`1` substituting `l` in `paypal.com`) and assigned a CRITICAL severity. Because the **Severity Floor Guarantee** enforces that rule-based CRITICAL/HIGH findings can NEVER be downgraded by ML, the final verdict is safely locked at **CRITICAL (Score: 100)**.

## 2. Sample Evaluation Breakdown

| Domain / Category | Expected | Pure ML Alone | Hybrid Verdict | Correct? |
|---|---|---|---|:---:|
| `paypa1.com` (TYPOSQUATTING) | phishing | legitimate (0.7255) | **CRITICAL** (100) | ✅ |
| `g00gle-security-update.net` (TYPOSQUATTING) | phishing | legitimate (0.6743) | **HIGH** (62) | ✅ |
| `micros0ft-office365-login.com` (TYPOSQUATTING) | phishing | legitimate (0.7378) | **HIGH** (62) | ✅ |
| `netflix-billing-renew.xyz` (BRAND_IMPERSONATION) | phishing | legitimate (0.8391) | **HIGH** (65) | ✅ |
| `evil-bank.top` (SUBDOMAIN_DECEPTION) | phishing | phishing (0.4864) | **MEDIUM** (48) | ❌ |
| `amazon-prime-reward-cash.buzz` (BRAND_IMPERSONATION) | phishing | suspicious (0.439) | **CRITICAL** (90) | ✅ |
| `sbi-yono-kyc-reactivate.top` (BRAND_IMPERSONATION) | phishing | phishing (0.9132) | **CRITICAL** (100) | ✅ |
| `hdfc-bank-rewards-points.click` (BRAND_IMPERSONATION) | phishing | phishing (0.5768) | **HIGH** (68) | ✅ |
| `xn--pple-43d.com` (PUNYCODE_HOMOGRAPH) | phishing | legitimate (0.9708) | **HIGH** (62) | ✅ |
| `xn--e1awd7f.com` (PUNYCODE_HOMOGRAPH) | phishing | legitimate (0.9341) | **HIGH** (65) | ✅ |
| `xn--microsofte-4pb.com` (PUNYCODE_HOMOGRAPH) | phishing | legitimate (0.5848) | **CRITICAL** (100) | ✅ |
| `bit.ly` (SHORTENED_URL) | phishing | legitimate (0.9976) | **SAFE** (8) | ❌ |
| `tinyurl.com` (SHORTENED_URL) | phishing | legitimate (0.8646) | **SAFE** (8) | ❌ |
| `t.co` (SHORTENED_URL) | phishing | legitimate (0.9368) | **SAFE** (8) | ❌ |
| `192.168.1.50` (RAW_IP_HOST) | phishing | phishing (0.9893) | **CRITICAL** (100) | ✅ |
| `203.0.113.15` (RAW_IP_HOST) | phishing | phishing (0.9837) | **CRITICAL** (100) | ✅ |
| `paypal.com` (POPULAR_LEGITIMATE) | legitimate | phishing (0.7514) | **SAFE** (0) | ✅ |
| `google.com` (POPULAR_LEGITIMATE) | legitimate | phishing (0.7708) | **SAFE** (0) | ✅ |
| `microsoftonline.com` (POPULAR_LEGITIMATE) | legitimate | phishing (0.4376) | **SAFE** (0) | ✅ |
| `apple.com` (POPULAR_LEGITIMATE) | legitimate | legitimate (0.7964) | **SAFE** (0) | ✅ |
| `netflix.com` (POPULAR_LEGITIMATE) | legitimate | legitimate (0.6822) | **SAFE** (0) | ✅ |
| `onlinesbi.sbi` (POPULAR_LEGITIMATE) | legitimate | legitimate (0.6652) | **SAFE** (0) | ✅ |
| `hdfcbank.com` (POPULAR_LEGITIMATE) | legitimate | phishing (0.5608) | **SAFE** (0) | ✅ |
| `amazon.in` (POPULAR_LEGITIMATE) | legitimate | phishing (0.6449) | **SAFE** (0) | ✅ |
| `service.gov.uk` (MULTI_PART_CCTLD) | legitimate | legitimate (0.7947) | **SAFE** (0) | ✅ |
| `incometax.gov.in` (MULTI_PART_CCTLD) | legitimate | legitimate (0.764) | **SAFE** (0) | ✅ |
| `mozilla.org` (LEGITIMATE_UNUSUAL) | legitimate | legitimate (0.8458) | **SAFE** (0) | ✅ |
| `githubusercontent.com` (LEGITIMATE_UNUSUAL) | legitimate | legitimate (0.7027) | **HIGH** (65) | ❌ |
