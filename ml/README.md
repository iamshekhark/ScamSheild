# ScamShield Machine Learning Pipeline

> **Modular, reproducible, calibrated ML training, benchmarking, and inference pipeline for Email & URL threat classification.**

---

## 📁 Directory Structure

```text
ml/
├── datasets/
│   ├── raw/                  # Staged public & curated source datasets
│   ├── processed/            # Normalized JSON/CSV datasets
│   ├── splits/               # Leakage-free 70/15/15 train/validation/test splits
│   ├── manifests/            # Dataset manifests, class distributions & provenance
│   └── validate_and_split.py # Validation, deduplication, PII scrubbing & group splitting
├── email_model/
│   ├── preprocessing.py      # Email text normalization, PII scrubbing & structured features
│   ├── train.py              # Baseline & hybrid model training + validation benchmarking
│   ├── evaluate.py           # Held-out test evaluation (F1, AUC, FPR, FNR, latency)
│   └── predict.py            # Unified response contract inference API
├── url_model/
│   ├── feature_extraction.py # URL lexical, domain, host, path & entropy features
│   ├── train.py              # Baseline, RF, HistGB & Hybrid URL model training
│   ├── evaluate.py           # Held-out domain-grouped test evaluation
│   └── predict.py            # Unified response contract inference API
├── calibration/
│   ├── calibrate.py          # Validation-only Temperature, Platt & Isotonic calibration
│   └── evaluate_calibration.py # Brier score, ECE & reliability bin evaluation
├── experiments/              # Validation benchmark logs (email_benchmark.json, url_benchmark.json)
├── artifacts/                # Versioned .joblib bundles + registry.json (SHA-256 & rollback)
├── reports/                  # Validation, calibration & test evaluation reports
├── tests/                    # Automated unit & regression test suite
├── training/                 # Legacy/browser-export parity pipeline (preserved for extension)
├── pipeline/                 # Public dataset connectors & hard-negative review queue
├── common.py                 # Shared artifact registry & unified response contract
└── requirements.txt          # Pinned Python ML dependencies
```

---

## 🛠️ Verified Training & Evaluation Commands

> On Windows, replace `python` with your Python 3.10+ executable (e.g. `C:\Users\shekh\AppData\Local\Python\pythoncore-3.14-64\python.exe`).

### 1. Install Dependencies
```bash
pip install -r ml/requirements.txt
```

### 2. Import Public Datasets (Optional Refresh)
```bash
python ml/pipeline/import_sources.py
```

### 3. Validate Datasets, Deduplicate & Generate 70/15/15 Splits
```bash
python ml/datasets/validate_and_split.py --task all
```

### 4. Train & Benchmark Email Models (Baseline + Hybrid + Random Forest)
```bash
python ml/email_model/train.py
```

### 5. Train & Benchmark URL Models (Baseline + Random Forest + HistGB + Hybrid)
```bash
python ml/url_model/train.py
```

### 6. Evaluate Models on Held-Out Test Splits
```bash
python ml/email_model/evaluate.py
python ml/url_model/evaluate.py
```

### 7. Evaluate Calibration & Generate Reliability Reports
```bash
python ml/calibration/evaluate_calibration.py --task all
```

### 8. Run Local Inference (Unified Response Contract)
```bash
python ml/email_model/predict.py --subject "Urgent KYC" --body "Share your OTP at http://paytrn-security.xyz"
python ml/url_model/predict.py --url "https://secure.paytmpayments.com/"
```

### 9. Run Automated ML Test Suite
```bash
python -m unittest discover -s ml/tests -v
```

### 10. Legacy Browser JSON Export & Parity Verification (Preserved)
```bash
python ml/training/train.py
python ml/training/verify_parity.py
```
