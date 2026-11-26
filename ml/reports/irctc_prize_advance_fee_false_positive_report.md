# ScamShield — IRCTC False Positive Report: `PRIZE_ADVANCE_FEE` (65/100 HIGH)

**Date:** 2026-11-26  
**Target URL:** `https://www.irctc.co.in/`  
**Status:** Root cause verified; awaiting approval before modifying production rules.

---

## 1. Exact Triggering Evidence

On `https://www.irctc.co.in/`, the extension extracts `document.title + "\n" + document.body.innerText` (`content_guard.js`, up to 1,500 chars; `popup.js`, up to 3,500 chars) and passes it to `ScamEngine.scanText(...)` (`rules.js`).

`PRIZE_ADVANCE_FEE` fires whenever **any** word from Group A and **any** word from Group B appear **anywhere** in the extracted page text, regardless of distance, sentence boundary, or negation:

- **Group A (Prize/Award/Congratulatory words)**: `won`, `winner`, `lottery`, `lucky draw`, `jackpot`, `prize`, `congratulations` (e.g., IRCTC awards/achievements, tourism contests, or congratulatory banners).
- **Group B (Booking/Payment words)**: `fee`, `charge`, `charges`, `tax`, `processing`, `deposit`, `claim`, `pay` (e.g., *"Convenience Fee"*, *"Booking Charges"*, *"GST/Tax"*, *"Pay"*, *"Claim Refund"*).

Because `https://www.irctc.co.in/` is a railway ticketing portal, words like `fee`, `charges`, `tax`, and `pay` are always present; any single mention of `won`, `prize`, or `congratulations` anywhere on the page triggers `PRIZE_ADVANCE_FEE` (`HIGH`, `65/100`).

---

## 2. Source Files and Functions

| Component | File | Function / Lines |
|---|---|---|
| Webpage DOM text extraction | `extension/content_guard.js` | `extractSanitizedSignals()` (L46–61) |
| Auto-protection text scan | `extension/background.js` | `runAutomaticScan()` (L238–245) |
| Manual popup page scan | `extension/popup.js` | `btnScanCurrent` handler (L579–595) |
| Client-side `PRIZE_ADVANCE_FEE` rule | `extension/rules.js` | `analyzeText()` (L274–288) |
| Risk score & `65/100` floor | `extension/rules.js` | `calculateRisk()` (L391–454) |
| Server-side `PRIZE_ADVANCE_FEE` rule | `supabase/functions/_shared/detectionEngine.ts` | `analyzeTextAndEmailIntelligence()` (L421–430) |

---

## 3. Rule Matching Logic

In `extension/rules.js` (L275–287):
```js
if (/\b(?:won|winner|lottery|lucky\s*draw|jackpot|prize|congratulations)\b/i.test(text) &&
    /\b(?:fee|charges?|tax|processing|deposit|claim|pay)\b/i.test(text)) {
  evidence.push({
    category: "PRIZE_ADVANCE_FEE",
    severity: "HIGH",
    reason: "Advance-fee or lottery scheme asking for fee/charges to release a prize. Genuine lotteries never demand advance processing payments."
  });
} else if (/\byou\s+(?:have\s+)?won\b.{0,40}\b(?:iphone|car|cash|gift|reward|gold|lottery)\b/i.test(text)) { ... }
```
An identical unbounded `&&` co-occurrence check exists in `supabase/functions/_shared/detectionEngine.ts` (L422–430).

**Defects**:
1. **No proximity or semantic link**: Matches two independent global regexes across 1,500–3,500 characters of unrelated webpage sections.
2. **No negation awareness**: Matches `"no fee or deposit required"` and `"never pay advance fees to claim a lottery"`.
3. **Common booking vocabulary**: `"fee"`, `"charges"`, `"tax"`, `"pay"`, and `"claim"` are standard railway/e-commerce terms.

---

## 4. Risk Score Calculation (`65/100`)

In `extension/rules.js` (`calculateRisk`, L406–454):
1. A single `HIGH` indicator adds `42` points (`score = 42`).
2. `risk_score > 40` initially maps to `MEDIUM`.
3. The severity floor (`FLOOR["HIGH"] = "HIGH"`) upgrades `risk_level` from `MEDIUM` to `HIGH`.
4. Line 450–451 enforces: `else if (risk_level === "HIGH" && risk_score <= 60) { risk_score = 65; }`.
5. `mergeLayeredResults` (`background.js`) merges `urlResult` (`0 SAFE`) with `textResult` (`65 HIGH`), yielding **Score: `65/100`**, **Severity: `HIGH`**, **Rule: `PRIZE_ADVANCE_FEE`**.

---

## 5. Root Cause

`PRIZE_ADVANCE_FEE` treats **unbounded global keyword co-occurrence** of a prize/congratulatory word anywhere on a page and a generic payment/fee word anywhere else on the page as high-confidence advance-fee fraud (`HIGH`, `65/100`), without requiring semantic proximity, an explicit payment-to-release-prize demand, or negation filtering.

---

## 6. Regression Tests (Executed Offline, Pre-Fix)

All inputs below are synthetic representative test cases executed via `extension/rules.js` + `extension/background.js`:

| # | Scenario (Synthetic) | Expected | Actual | Score | Triggered Rules |
|---|---|---|---|---:|---|
| 1 | IRCTC homepage (`Convenience Fee` + `Congratulations ... winning`) | SAFE | **HIGH (FP)** | 65 | `PRIZE_ADVANCE_FEE` |
| 2 | IRCTC booking info (`Tatkal booking charges`, `Claim TDR`, `Pay`) | SAFE | SAFE | 0 | `[]` |
| 3 | Railway promo (`won World Travel Award` + `zero convenience fee`) | SAFE | **HIGH (FP)** | 65 | `PRIZE_ADVANCE_FEE` |
| 4 | Anti-scam advisory (`Never pay advance fees to claim a lottery`) | SAFE | **HIGH (FP)** | 65 | `PRIZE_ADVANCE_FEE` |
| 5 | Genuine advance-fee lottery scam (`Pay Rs 2,500 processing fee ... claim your prize`) | HIGH/CRITICAL | HIGH | 62 | `PRIZE_ADVANCE_FEE`, `URGENCY` |
| 6 | IRCTC phishing (`http://irctc-lucky-winner.xyz/claim` + prize fee) | CRITICAL | HIGH | 65 | `URL_SECURITY`, `DOMAIN_STRUCTURE`, `PRIZE_ADVANCE_FEE` |
| 7 | Legitimate promo (`Congratulations! ... No fee or deposit required`) | SAFE | **HIGH (FP)** | 65 | `PRIZE_ADVANCE_FEE` |
| 8 | Unrelated webpage (`First prize is a laptop` ... `tuition fee`) | SAFE | **HIGH (FP)** | 65 | `PRIZE_ADVANCE_FEE` |

**5/6** legitimate/informational cases falsely triggered `PRIZE_ADVANCE_FEE` at `65/100 HIGH`.

---

## 7. Proposed Minimal Correction (Pending Approval)

Replace the unbounded global `&&` check in `extension/rules.js` (L275–281) and `supabase/functions/_shared/detectionEngine.ts` (L422–430) with **contextual, negation-aware, proximity-bounded matching**:

1. **Negation Guard**: Skip if explicitly negated (e.g., `/(?:no|zero|without|never\s+pay)\s+(?:advance\s+)?(?:fee|fees|charges?|deposit)/i`).
2. **Contextual Action-to-Prize Connection**: Require an explicit payment/fee demand **near** a prize/lottery claim (within ~80–120 chars), e.g.:
   - `(pay|deposit|send|transfer|remit)\b.{0,60}\b(fee|charges?|tax|processing|deposit)\b.{0,80}\b(to\s+(?:claim|release|unlock|receive)|prize|lottery|jackpot|winnings|reward)`
   - OR `(won|winner|lottery|lucky\s*draw|jackpot|prize)\b.{0,80}\b(?:pay|deposit|send|transfer|processing\s+fee|registration\s+fee|tax|charges?)\b.{0,50}\b(to\s+(?:claim|release|unlock|receive)|fee|charges?|deposit)`
3. **Webpage Context Guard**: On `context === "webpage"`, require either explicit prize-release payment phrasing (`to claim/release/unlock your prize`) or supporting suspicious signals (e.g., untrusted domain/urgency) rather than generic `fee`/`pay`/`tax` words; weak standalone matches should not auto-escalate to `HIGH (65/100)`.

---

## 8. Side-Effect Analysis

- **False Positives Eliminated**: Travel, railway, e-commerce, news, and educational pages that mention awards/prizes alongside normal booking/tuition fees or `"zero convenience fee"` will no longer trigger `PRIZE_ADVANCE_FEE`.
- **Fraud Protection Preserved**: Genuine advance-fee scams (which explicitly connect paying a processing/tax/registration fee to claiming/releasing lottery/prize winnings, as well as `"you have won [iPhone/cash/lottery]"`) continue to trigger `PRIZE_ADVANCE_FEE` at `HIGH`. Existing unit tests in `tests/rules.test.js` and `tests/corpus/labeled_scam_corpus.json` remain covered.
- **No Unconditional Whitelisting**: IRCTC is not whitelisted; an impersonating site like `http://irctc-lucky-winner.xyz/claim` asking for a fee to release a prize still triggers `PRIZE_ADVANCE_FEE` plus URL/brand-impersonation checks.
