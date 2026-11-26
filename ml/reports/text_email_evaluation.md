# ScamShield ML Model Evaluation Report — Task: `TEXT_EMAIL`

**Generated:** 2026-11-25T18:57:48.643039+00:00

## 1. Production Activation Gate Status

- **Gate Verdict:** **HELD / DISABLED (PENDING CRITERIA)**
- **Activation Status:** `disabled_insufficient_sample_size`
- **Zero Leakage Verified:** True
- **Review Queue Cleared:** True (0 pending)
- **Security Approved:** False
- **Reasons / Justification:**
  - Insufficient human-reviewed samples: minimum class has 4 reviewed samples in verified_samples.json; production gate strictly requires at least 1000 reviewed samples per class.
  - Macro F1 (0.7878) is below threshold (0.90).
  - Macro Precision (0.7438) is below threshold (0.90).
  - False Positive Rate on legitimate (6.2400%) exceeds max threshold (1.00%).
  - Security sign-off pending: Model requires documented security clearance in security_approvals.json.

## 2. Training vs Test Performance

| Metric | Train Split | Test Split |
|---|---:|---:|
| Samples | 9185 | 1968 |
| Accuracy | 0.9527 | 0.9370 |
| Macro F1 | 0.9250 | 0.7878 |
| Macro Precision | — | 0.7438 |
| Macro Recall | — | 0.8621 |
| Weighted F1 | — | 0.9382 |
| False Positive Rate (Legitimate) | — | 6.2400% |

## 3. Per-Class Test Breakdown

| Class | Precision | Recall | F1-Score | Support |
|---|---:|---:|---:|---:|
| **legitimate** | 0.9749 | 0.9376 | 0.9559 | 1410 |
| **phishing** | 0.8725 | 0.9452 | 0.9074 | 456 |
| **scam** | 0.3333 | 0.6667 | 0.4444 | 3 |
| **spam** | 0.7946 | 0.8990 | 0.8436 | 99 |

## 4. Confusion Matrix

Classes: `legitimate`, `phishing`, `scam`, `spam`

```json
[[1322, 63, 4, 21], [23, 431, 0, 2], [1, 0, 2, 0], [10, 0, 0, 89]]
```
