# ScamShield Dataset Validation & Split Report
- **Dataset Version:** `2.2.0`
- **Generated At:** 2026-11-26T05:52:05.211845+00:00

## Task: EMAIL
- **Raw records:** 13121 | **Trainable:** 13119 | **Unknown excluded:** 0
- **Exact duplicates removed:** 2 | **Near-duplicates (est.):** 42
- **Contradictory labels:** 0 | **Invalid/missing dropped:** 0
- **Class distribution:** `{'phishing': 3022, 'legitimate': 9462, 'spam': 635}`
- **Splits (70/15/15):** train=9185, val=1967, test=1967
- **Zero group leakage:** `True` | **Zero content leakage:** `True`

## Task: URL
- **Raw records:** 12335 | **Trainable:** 12335 | **Unknown excluded:** 0
- **Exact duplicates removed:** 0 | **Near-duplicates (est.):** 70
- **Contradictory labels:** 0 | **Invalid/missing dropped:** 0
- **Class distribution:** `{'malicious': 6321, 'legitimate': 6014}`
- **Splits (70/15/15):** train=8635, val=1850, test=1850
- **Zero group leakage:** `True` | **Zero content leakage:** `True`
