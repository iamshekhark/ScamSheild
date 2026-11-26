# ScamShield — Critical False Positive Root-Cause Report: Amazon Website Flagged by `text_email` Model

**Date:** 2026-11-26  
**Status:** Root-cause confirmed; awaiting approval before modifying production code.

---

## 1. Root Cause

When **Experimental ML** is enabled in extension settings (`prefs.experimental_ml === true`), visiting Amazon (`https://www.amazon.in/` or `amazon.com`) triggers a **model-task mismatch**:

1. **Layer 1 (`scanUrl`)** correctly recognizes Amazon as an official brand domain (`isKnownOfficialHost("www.amazon.in") === true`) with `0` deterministic rule violations, returning `risk_score: 0`, `risk_level: "SAFE"`, `detection_method: "rules (brand whitelist protected)"`, and `model_confidence: undefined`.
2. **Layer 2 (`scanText`)** extracts `document.title + "\n" + document.body.innerText` from the webpage and calls `ScamEngine.scanText(snippet, { allowExperimental: true, context: "webpage" })`.
3. `ScamEngine.scanText` unconditionally routes **all** text—including `context: "webpage"` DOM text—into `combineWithMl("text_email", ...)`, invoking the **`text_email` classifier** (`models/text_email_classifier.json`, trained on emails/SMS, NOT webpages).
4. `text_email` classifies Amazon's e-commerce DOM text as **`phishing`** (`>= 85%` confidence -> `CRITICAL`, `risk_score: 85`), and `mergeLayeredResults` takes `Math.max(urlScore=0, textScore=85) = 85` (`CRITICAL`) while preserving `urlResult.detection_method` (`"rules (brand whitelist protected)"`) and `urlResult.model_confidence` (`undefined` -> UI displays `"Confidence: Unavailable"`).

---

## 2. Exact Source Files and Functions

| Step | File | Function / Line | Role in Bug |
|---|---|---|---|
| DOM extraction | `extension/content_guard.js` | `extractSanitizedSignals()` (L26–61) | Extracts `title` + `bodyText` (`innerText` up to 1,500 chars) and sends `AUTO_INSPECT_DOM` |
| Auto-guard scan | `extension/background.js` | `runAutomaticScan()` (L224–245) | Calls `ScamEngine.scanUrl(...)` then `ScamEngine.scanText(snippet, { ...scanOpts, context: "webpage" })` |
| Manual page scan | `extension/popup.js` | `btnScanCurrent` handler (L589–595) | Calls `ScamApi.scan({ content: domText, type: "text", ..., context: "webpage" })` |
| Task routing | `extension/rules.js` | `scanText` (L1105) | Hardcodes `combineWithMl("text_email", ...)` even when `options.context === "webpage"` |
| ML combination | `extension/rules.js` | `combineWithMl()` (L926–988) | Brand protection only runs for `task === "url"` (L928); `text_email` `phishing` at `>= 0.85` becomes `CRITICAL` (`85/100`) |
| Layer merge | `extension/background.js` | `mergeLayeredResults()` (L100–167) | Sets `combinedScore = Math.max(0, 85)`, `combinedLevel = "CRITICAL"`, keeps `urlResult.detection_method` and `undefined` `model_confidence` |
| Feature fragments | `extension/ml_inference.js` | `extractCharWbNgrams()` (L80–97), `predict()` (L234–248) | Emits raw padded 3–5 char n-grams (`" + "`, `" es "`, `" car"`, `"car "`, `" men"`) as `top_features` |
| Signal formatting | `extension/rules.js` | `combineWithMl()` (L953–957) | Trims `f.ngram` without deduplication, producing `"+"`, `"es"`, `"car"`, `"men"`, `"car"` |

---

## 3. Model Input Trace

1. **URL Model (`url`)**: Receives `"https://www.amazon.in/"`. Suppressed by `isKnownOfficialHost` (`detection_method: "rules (brand whitelist protected)"`).
2. **Email Model (`text_email`)**: Receives **raw webpage `title + "\n" + body.innerText`** (NOT email subject/body/sender). Never receives URL or domain reputation.

---

## 4. Score Aggregation Trace

1. `urlResult`: `risk_score = 0`, `risk_level = "SAFE"`, `evidence = []`, `model_confidence = undefined`.
2. `textResult`: `ScamML.predict("text_email", snippet)` returns `predicted_class: "phishing"`, `confidence >= 0.85` -> `combineWithMl` creates `ML_CLASSIFICATION_ALERT` with `severity: "CRITICAL"` -> `calculateRisk` returns `risk_score = 85`, `risk_level = "CRITICAL"`.
3. `mergeLayeredResults`:
   - `combinedScore = Math.max(0, 85) = 85`
   - `combinedLevel = "CRITICAL"`
   - `should_block = false` (because `ML_CLASSIFICATION_ALERT` starts with `"ML_"`, so `hasStrongDeterministicEvidence` is `false`)
   - Spreads `...(urlResult || {})`, keeping `detection_method: "rules (brand whitelist protected)"` and `model_confidence: undefined` (`"Confidence: Unavailable"` in `popup.js` L772).

---

## 5. Explanation & Tokenization Defects

- **TF-IDF Character N-Gram Fragments**: `text_email_classifier.json` uses `char_wb` (`ngram_range: [3, 5]`), padding each whitespace token with spaces (e.g., `" + "`, `" es "`, `" car"`, `"car "`, `" men"`).
- **Misleading Display**: `rules.js` L955 calls `f.ngram.trim()` and prints them as `"Key Signals: ..."`.
- **Duplicate Signals**: `" car"` (from `"cart"`/`"card"`) and `"car "` (from `"car"`) are distinct entries in `sparseFeats`, so after `.trim()` both render as `"car"`.

---

## 6. Brand Protection Implementation

- **What it actually is**: `isKnownOfficialHost(parsed.hostname)` in `extension/rules.js` (L30–34, L928–941) is **not** an unconditional domain allowlist—it only suppresses **statistical ML false positives on `task === "url"`** when `ruleEvidence.length === 0`.
- **Bypass Defect**: Because `text_email` runs in Layer 2 on the page's DOM text, it **completely bypasses** the `task === "url"` brand-protection guard and overrides the `0/100 SAFE` URL verdict with `85/100 CRITICAL`.
- **Deterministic Protection Preserved**: Lookalike domains (`amaz0n-security-verify.xyz`), punycode (`xn--...`), userinfo spoofing, external credential/payment form exfiltration, and coercive scams still trigger `analyzeUrl` / `analyzeText` deterministic rules even for official brand names.

---

## 7. Reproduction Steps

Verified offline in Node.js (`extension/rules.js`, `extension/ml_inference.js`, `extension/background.js`) with `models/url_classifier.json` and `models/text_email_classifier.json` loaded and `allowExperimental: true`:
- `ScamEngine.scanUrl("https://www.amazon.in/", { allowExperimental: true })` -> `risk_score: 0`, `risk_level: "SAFE"`, `detection_method: "rules (brand whitelist protected)"`, `model_confidence: undefined`.
- `ScamEngine.scanText(amazonDom, { allowExperimental: true, context: "webpage" })` -> `predicted_class: "phishing"`, `model_confidence: 90.7`, `risk_score: 85`, `risk_level: "CRITICAL"`, `top_features` containing raw char n-grams (`"nlin"`, `"nli"`, `"nline"`, `"si"`, `"+"`).
- `bg.mergeLayeredResults(...)` -> `risk_score: 85`, `risk_level: "CRITICAL"`, `detection_method: "rules (brand whitelist protected)"`, `should_block: false`.

---

## 8. Regression Test Results (`tests/text_email_website_isolation.test.js`)

Executed `node --test tests/text_email_website_isolation.test.js` (without modifying production code):
- **Tests 1–4** (Amazon homepage, product, login, checkout URLs): **PASS** (`SAFE`, `0/100`).
- **Tests 5–6** (`amaz0n-security-verify.xyz`, `paytrn-security.xyz`): **PASS** (`CRITICAL`, `should_block: true`).
- **Tests 8–9** (Phishing email & legitimate GitHub email): **PASS** (`CRITICAL` / `SAFE`, `text_email` ML invoked).
- **Test 7** (Amazon website DOM text with `context: "webpage"`): **FAILS isolation invariant as expected pre-fix** (marked `todo` pending fix approval; observed `text_email` invoked on webpage text with `predicted_class: "phishing"`, `model_confidence: 74.3%`).

---

## 9. Proposed Minimal Fix (Pending Approval)

1. **Enforce Model-Task Isolation (`extension/rules.js`)**:
   - In `scanText(text, options = {})` / `combineWithMl(...)`: when `options.context === "webpage"`, **do not invoke `ScamML.predict("text_email", ...)`** (use deterministic webpage rules only until a dedicated webpage-content model exists).
2. **Fix Misleading & Duplicate Key Signals (`extension/rules.js`, `extension/ml_inference.js`)**:
   - Do not expose raw `char_wb` fragments (`"+"`, `"car"`, `"es"`) as user-facing `"Key Signals"` in `ML_CLASSIFICATION_ALERT.reason`—report calibrated class, confidence percentage, and vocabulary coverage only (or deduplicated readable words `>= 4` chars if ever displayed in debug mode).
3. **Preserve `model_confidence` Consistency (`extension/background.js`)**:
   - Only propagate `model_confidence` when a compatible ML model actually contributed to the final verdict, and never let an incompatible model task contribute to `mergeLayeredResults`.

---

## 10. Potential Side Effects

- Turning off `text_email` ML for `context: "webpage"` means Experimental ML mode will rely on deterministic `analyzeText(..., { context: "webpage" })` + `url` ML + DOM form-action checks for websites, which is the intended safe behavior (and eliminates email-model false positives on shopping/news/banking sites without weakening deterministic phishing rules).
- Email scanning (`scanEmail`) and manual SMS/message scanning (`scanText` without `context: "webpage"`) continue using `text_email` ML unchanged.

---

## 11. Files That Would Need Modification (Upon Approval)

1. `extension/rules.js` (enforce `context !== "webpage"` guard before invoking `text_email` ML; remove raw char n-gram fragments from user-facing `ML_CLASSIFICATION_ALERT` reason).
2. `tests/text_email_website_isolation.test.js` (remove `{ todo: ... }` on Test 7 so all 9 regression scenarios enforce strict isolation).
