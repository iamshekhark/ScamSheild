# ScamShield Dataset Quality Audit Report

**Audit Generated:** 2026-10-31T17:08:30.542231+00:00

## 1. Executive Summary

| Task | Raw Records | Clean Deduplicated | Duplicates Removed | Conflicts | Max:Min Imbalance |
|---|---:|---:|---:|---:|---:|
| **URL** | 12342 | 12298 | 44 | 27 | 1.05:1 |
| **TEXT_EMAIL** | 13630 | 13026 | 582 | 0 | 588.12:1 |
| **PAYMENT** | 54 | 33 | 21 | 11 | 3.4:1 |

## 2. Per-Task Class Distributions

### URL Classification
```json
{
  "phishing": 6298,
  "legitimate": 6000
}
```
- **Data Sources:** {"benchmark_corpus": 15, "synthetic_seed": 20, "mitchellkrogza_phishing": 6000, "openphish_feed": 300, "tranco_top_1m": 6000, "verified_review": 7}
- **Near-Duplicate Patterns Detected:** 20

### TEXT_EMAIL Classification
```json
{
  "legitimate": 9410,
  "spam": 643,
  "phishing": 2957,
  "scam": 16
}
```
- **Data Sources:** {"benchmark_corpus": 9, "synthetic_seed": 13, "uci_sms_spam": 5574, "huggingface_phishing_email": 8000, "cert_in_i4c_curated": 26, "verified_review": 8}
- **Near-Duplicate Patterns Detected:** 1

### PAYMENT Classification
```json
{
  "fraudulent": 11,
  "legitimate": 17,
  "suspicious": 5
}
```
- **Data Sources:** {"benchmark_corpus": 7, "synthetic_seed": 10, "curated_payments": 32, "verified_review": 5}
- **Near-Duplicate Patterns Detected:** 0

