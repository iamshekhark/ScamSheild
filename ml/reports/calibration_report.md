# ScamShield Calibration Evaluation Report
- **Generated At:** 2026-11-26T05:54:47.319536+00:00

## EMAIL (`email-model-v1.0.0` — method: `isotonic`)
- **Test Brier Score:** 0.0844 (uncalibrated) -> **0.0614** (calibrated)
- **Test ECE:** 0.1095 (uncalibrated) -> **0.0118** (calibrated)
- **Test NLL:** 0.2073 (uncalibrated) -> **0.1443** (calibrated)

| Confidence Bin | Count | Avg Confidence | Empirical Accuracy | Gap |
|---|---:|---:|---:|---:|
| 0.4-0.5 | 11 | 0.4940 | 0.6364 | 0.1424 |
| 0.5-0.6 | 26 | 0.5737 | 0.7692 | 0.1955 |
| 0.6-0.7 | 29 | 0.6626 | 0.5862 | 0.0764 |
| 0.7-0.8 | 51 | 0.7597 | 0.6863 | 0.0735 |
| 0.8-0.9 | 27 | 0.8210 | 0.9259 | 0.1049 |
| 0.9-1.0 | 1823 | 0.9867 | 0.9824 | 0.0042 |

## URL (`url-model-v1.0.0` — method: `isotonic`)
- **Test Brier Score:** 0.0042 (uncalibrated) -> **0.0049** (calibrated)
- **Test ECE:** 0.0021 (uncalibrated) -> **0.0024** (calibrated)
- **Test NLL:** 0.008 (uncalibrated) -> **0.0357** (calibrated)

| Confidence Bin | Count | Avg Confidence | Empirical Accuracy | Gap |
|---|---:|---:|---:|---:|
| 0.7-0.8 | 2 | 0.7258 | 0.5000 | 0.2258 |
| 0.9-1.0 | 1848 | 1.0000 | 0.9978 | 0.0022 |
