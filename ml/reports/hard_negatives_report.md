# ScamShield ML Hard-Negative Mining & Error Analysis

**Generated:** 2026-10-31T17:23:31.643084+00:00

## 1. Overview

Hard-negative mining systematically collects samples where candidate models disagreed with ground truth, categorizes failure modes into attack patterns, and enforces human-in-the-loop review before any sample can be promoted into the verified training set. **Unreviewed model predictions are never automatically treated as ground truth.**

## 2. Summary by Task

| Task | False Positives | False Negatives | Total Review Items |
|---|---:|---:|---:|
| **URL** | 3 | 19 | 22 |
| **TEXT_EMAIL** | 90 | 54 | 144 |
| **PAYMENT** | 0 | 3 | 3 |

## 3. Discovered Error Patterns by Attack Category

### URL Error Breakdown

| Attack Pattern Category | Sample Count |
|---|---:|
| `general_lexical_divergence` | 13 |
| `auth_keyword_lure` | 4 |
| `brand_impersonation` | 3 |
| `punycode_homograph` | 1 |
| `suspicious_tld` | 1 |

### TEXT_EMAIL Error Breakdown

| Attack Pattern Category | Sample Count |
|---|---:|
| `general_semantic_divergence` | 117 |
| `credential_and_otp_harvesting` | 12 |
| `utility_disconnection_urgency` | 5 |
| `financial_reward_lure` | 5 |
| `part_time_task_fraud` | 4 |
| `authority_and_arrest_extortion` | 1 |

### PAYMENT Error Breakdown

| Attack Pattern Category | Sample Count |
|---|---:|
| `vpa_pattern_divergence` | 2 |
| `reverse_collect_refund_lure` | 1 |

## 4. Human Verification Protocol

To admit samples into `verified_samples.json`:
1. Open `ml/datasets/raw/review_queue.json`.
2. Inspect each pending item.
3. Set `review_status: 'approved'`, provide `human_verified_label`, and assign `reviewed_by`.
4. Execute `py ml/pipeline/hard_negatives.py --ingest-approved`.
