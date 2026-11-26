# ScamShield Model Card (v2.0.0)

## Model Details
- **Organization:** ScamShield Cybersecurity Research Team
- **Updated:** November 2026
- **Model Type:** Character-level TF-IDF (3–5 n-grams, word boundary padding) + Multiclass Logistic Regression
- **Model Version:** `v2.0.0`
- **Inference Runtime:** Pure JavaScript (`ml_inference.js`) inside Manifest V3 Chrome Extension and Python backend.
- **License:** MIT License

---

## Intended Use
- **Primary Use Case:** Offline secondary signal evaluation for browser extensions to detect phishing links, social engineering messages/emails, and fraudulent UPI payment requests.
- **Safety Invariant:** ML models can never downgrade a deterministic rule-based HIGH or CRITICAL finding.

---

## Training & Evaluation Datasets

| Task | Total Samples | Train Split | Test Split | Grouping Strategy |
|---|---:|---:|---:|---|
| **URL** | 10485 | 8635 | 1850 | public_suffix_list_registrable_domain |
| **TEXT_EMAIL** | 11153 | 9185 | 1968 | template_hash |
| **PAYMENT** | 44 | 35 | 9 | vpa_handle_provider |

---

## Synchronized Test Performance Metrics

| Task | Accuracy | Macro F1 | Weighted F1 | False Positive Rate | Status |
|---|---:|---:|---:|---:|---|
| **URL** | 0.9930 | 0.6622 | 0.9927 | 0.2100% | `disabled_insufficient_sample_size` |
| **TEXT_EMAIL** | 0.9370 | 0.7878 | 0.9382 | 6.2400% | `disabled_insufficient_sample_size` |
| **PAYMENT** | 0.4444 | 0.3333 | 0.4444 | 75.0000% | `disabled_insufficient_sample_size` |

---

## Production Activation Gate Status
> [!NOTE]
> All models undergo rigorous automated auditing against minimum human-reviewed counts, macro F1, and review queue clearance.

### URL Gate: LOCKED (EXPERIMENTAL / SHADOW MODE)
- **Activation Status:** `disabled_insufficient_sample_size`
- **Reviewed Sample Counts:** {'phishing': 19, 'legitimate': 7, 'malicious': 1, 'suspicious': 1}
- **Gate Reasons:**
  - Insufficient human-reviewed samples: minimum class has 1 reviewed samples in verified_samples.json; production gate strictly requires at least 1000 reviewed samples per class.
  - Macro F1 (0.6622) is below threshold (0.90).
  - Macro Precision (0.6620) is below threshold (0.90).
  - Security sign-off pending: Model requires documented security clearance in security_approvals.json.

### TEXT_EMAIL Gate: LOCKED (EXPERIMENTAL / SHADOW MODE)
- **Activation Status:** `disabled_insufficient_sample_size`
- **Reviewed Sample Counts:** {'scam': 4, 'legitimate': 88, 'phishing': 38, 'spam': 15}
- **Gate Reasons:**
  - Insufficient human-reviewed samples: minimum class has 4 reviewed samples in verified_samples.json; production gate strictly requires at least 1000 reviewed samples per class.
  - Macro F1 (0.7878) is below threshold (0.90).
  - Macro Precision (0.7438) is below threshold (0.90).
  - False Positive Rate on legitimate (6.2400%) exceeds max threshold (1.00%).
  - Security sign-off pending: Model requires documented security clearance in security_approvals.json.

### PAYMENT Gate: LOCKED (EXPERIMENTAL / SHADOW MODE)
- **Activation Status:** `disabled_insufficient_sample_size`
- **Reviewed Sample Counts:** {'fraudulent': 5, 'legitimate': 2, 'suspicious': 1}
- **Gate Reasons:**
  - Insufficient human-reviewed samples: minimum class has 1 reviewed samples in verified_samples.json; production gate strictly requires at least 1000 reviewed samples per class.
  - Macro F1 (0.3333) is below threshold (0.90).
  - Macro Precision (0.5000) is below threshold (0.90).
  - False Positive Rate on legitimate (75.0000%) exceeds max threshold (1.00%).
  - Accuracy (0.4444) is below minimum threshold (0.90).
  - Security sign-off pending: Model requires documented security clearance in security_approvals.json.

---

## Mathematical Parity Verification
- Tested across all tasks between scikit-learn and pure JavaScript runtime.
- Maximum probability divergence: **<= 0.00005**.
- Predicted class agreement: **100% exact match**.
