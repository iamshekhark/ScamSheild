# ScamShield ML Model Evaluation Report — Task: `PAYMENT`

**Generated:** 2026-11-25T18:57:48.744608+00:00

## 1. Production Activation Gate Status

- **Gate Verdict:** **HELD / DISABLED (PENDING CRITERIA)**
- **Activation Status:** `disabled_insufficient_sample_size`
- **Zero Leakage Verified:** True
- **Review Queue Cleared:** True (0 pending)
- **Security Approved:** False
- **Reasons / Justification:**
  - Insufficient human-reviewed samples: minimum class has 1 reviewed samples in verified_samples.json; production gate strictly requires at least 1000 reviewed samples per class.
  - Macro F1 (0.3333) is below threshold (0.90).
  - Macro Precision (0.5000) is below threshold (0.90).
  - False Positive Rate on legitimate (75.0000%) exceeds max threshold (1.00%).
  - Accuracy (0.4444) is below minimum threshold (0.90).
  - Security sign-off pending: Model requires documented security clearance in security_approvals.json.

## 2. Training vs Test Performance

| Metric | Train Split | Test Split |
|---|---:|---:|
| Samples | 35 | 9 |
| Accuracy | 1.0000 | 0.4444 |
| Macro F1 | 1.0000 | 0.3333 |
| Macro Precision | — | 0.5000 |
| Macro Recall | — | 0.3333 |
| Weighted F1 | — | 0.4444 |
| False Positive Rate (Legitimate) | — | 75.0000% |

## 3. Per-Class Test Breakdown

| Class | Precision | Recall | F1-Score | Support |
|---|---:|---:|---:|---:|
| **fraudulent** | 0.5000 | 0.7500 | 0.6000 | 4 |
| **legitimate** | 1.0000 | 0.2500 | 0.4000 | 4 |
| **suspicious** | 0.0000 | 0.0000 | 0.0000 | 1 |

## 4. Confusion Matrix

Classes: `fraudulent`, `legitimate`, `suspicious`

```json
[[3, 0, 1], [2, 1, 1], [1, 0, 0]]
```
