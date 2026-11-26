# ScamShield ML Model Evaluation Report — Task: `URL`

**Generated:** 2026-11-25T18:57:41.460597+00:00

## 1. Production Activation Gate Status

- **Gate Verdict:** **HELD / DISABLED (PENDING CRITERIA)**
- **Activation Status:** `disabled_insufficient_sample_size`
- **Zero Leakage Verified:** True
- **Review Queue Cleared:** True (0 pending)
- **Security Approved:** False
- **Reasons / Justification:**
  - Insufficient human-reviewed samples: minimum class has 1 reviewed samples in verified_samples.json; production gate strictly requires at least 1000 reviewed samples per class.
  - Macro F1 (0.6622) is below threshold (0.90).
  - Macro Precision (0.6620) is below threshold (0.90).
  - Security sign-off pending: Model requires documented security clearance in security_approvals.json.

## 2. Training vs Test Performance

| Metric | Train Split | Test Split |
|---|---:|---:|
| Samples | 8635 | 1850 |
| Accuracy | 0.9953 | 0.9930 |
| Macro F1 | 0.9968 | 0.6622 |
| Macro Precision | — | 0.6620 |
| Macro Recall | — | 0.6623 |
| Weighted F1 | — | 0.9927 |
| False Positive Rate (Legitimate) | — | 0.2100% |

## 3. Per-Class Test Breakdown

| Class | Precision | Recall | F1-Score | Support |
|---|---:|---:|---:|---:|
| **legitimate** | 0.9894 | 0.9979 | 0.9936 | 932 |
| **malicious** | 0.0000 | 0.0000 | 0.0000 | 1 |
| **phishing** | 0.9967 | 0.9891 | 0.9929 | 917 |
| **suspicious** | 0.0000 | 0.0000 | 0.0000 | 0 |

## 4. Confusion Matrix

Classes: `legitimate`, `malicious`, `phishing`, `suspicious`

```json
[[930, 0, 2, 0], [0, 0, 1, 0], [10, 0, 907, 0], [0, 0, 0, 0]]
```
