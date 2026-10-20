# ScamShield Detection Performance & Corpus Benchmark

## 1. Overview

Phase 6 evaluated the ScamShield offline and hybrid detection engine against a curated, safe, non-executing corpus of 31 realistic security threat vectors and legitimate baseline communications across three primary modalities:
1. **Phishing & Lookalike URLs**
2. **Social Engineering & Extortion Messages (English & Hinglish)**
3. **UPI & QR Payment Fraud Vectors**

---

## 2. Benchmark Metrics

| Metric | Target | Benchmark Result | Verdict |
|---|---|---|---|
| **Evaluated Samples** | $\ge 30$ | **31** | PASS |
| **True Positives (TP)** | — | **18** | PASS |
| **True Negatives (TN)** | — | **13** | PASS |
| **False Positives (FP)** | $0$ | **0** | PASS (0.00%) |
| **False Negatives (FN)** | $0$ | **0** | PASS (0.00%) |
| **Precision** | $\ge 95\%$ | **100.00%** | PASS |
| **Recall** | $\ge 95\%$ | **100.00%** | PASS |
| **Accuracy** | $\ge 95\%$ | **100.00%** | PASS |
| **F1-Score** | $\ge 0.95$ | **1.0000** | PASS |

---

## 3. Threat Modality Coverage

### A. Phishing & Malicious URLs
- **Homoglyphs & Typosquats:** Detected `paypa1.com`, `g00gle.com`, `amaz0n.in`, and hyphenated mimicry (`pay-tm.com`, `sbi-kyc.xyz`).
- **Userinfo Credential Spoofing:** Detected and extracted deceptive userinfo patterns (`https://amazon.com@attacker-portal.xyz`).
- **Raw IP Address Hosts:** Flagged raw IP links (`http://192.168.1.100/...`).
- **Punycode Imitation:** Flagged internationalized domain imitation (`xn--...`).
- **Dangerous Schemes:** Flagged executable URI schemes (`javascript:`, `data:`).
- **Legitimate Whitelisting:** Multi-regional authentic domains (`google.co.in`, `amazon.in`, `onlinesbi.sbi`, `hdfcbank.com`, `github.com`, `netflix.com`, `apple.com`) produced 0 false positives.

### B. Scam Messages & Extortion
- **Digital Arrest Extortion:** Detected coercive threats claiming CBI, Police, or Customs Skype/WhatsApp arrest warrants.
- **Hinglish Pretexting:** Detected conversational Hindi/Hinglish OTP harvesting phrases (`bhai otp bhej do`, `pin daalo paise aane ke liye`).
- **KYC & Account Suspension:** Flagged immediate account deactivation and unverified KYC update links.
- **Advance-Fee / Lottery Scams:** Detected unexpected lottery wins demanding processing/registration fees.
- **Courier / Customs Extortion:** Detected detained India Post/Customs parcels demanding release fees.
- **Safety Negation:** Genuine transactional messages advising users *"NEVER share your OTP with anyone"* are correctly recognized as benign.

### C. Payment Verification & UPI/QR Fraud
- **Reverse Collect Fraud:** Detected deceit urging victims to enter their UPI PIN to "receive" or "claim" refunds/cashback.
- **Remote Access Tools:** Detected coercion instructing installation of AnyDesk, TeamViewer, or QuickSupport under electricity disconnection pretexts.
- **Payee Mismatch:** Detected official brand name claims paired with personal individual phone-based VPAs.
- **Bounded Claims & Uncertainty:** All payment scans report `payment_status: "unverified"`, explicitly communicating that screenshots or UTR numbers alone do not guarantee bank settlement.

---

## 4. Offline Resilience & Degradation Guarantees

1. **Zero-Network Engine:** `ScamEngine` operates entirely client-side without network requests.
2. **Graceful Fallback:** When configured for hybrid mode and network/API failures occur (timeouts, DNS failures, or 5xx server errors), `ScamApi` automatically degrades to local rules engine with `is_fallback: true` without interrupting user protection.
3. **Safety Floor Guarantee (H6):** Any scan result exhibiting HIGH or CRITICAL evidence is guaranteed never to return a SAFE verdict.

---

## 5. Known Limitations & Operating Boundaries

1. **Novel Zero-Day Domains:** Purely lexical offline rules cannot detect brand-new throwaway phishing domains that do not reuse brand keywords, typosquats, or known risky TLDs without cloud reputation queries.
2. **Payment Settlement Authoritativeness:** Browser extensions cannot authoritatively confirm bank settlement without direct core banking or UPI switch APIs. ScamShield explicitly marks all payment statuses as `unverified`.
3. **Encrypted or Obfuscated Payloads:** Images or heavily obfuscated OCR text require client-side Tesseract or server-side vision AI; offline fallback relies on lexical and structural regex extraction.
