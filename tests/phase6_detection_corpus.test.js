// ScamShield Phase 6: Scam Detection, Payment Verification & Offline Protection Tests
// Benchmarks labeled test corpus, computes Precision/Recall, and validates offline fallback resilience

const test = require("node:test");
const assert = require("node:assert");
const path = require("node:path");
const fs = require("fs");

const ScamEngine = require("../extension/rules");
const ScamApi = require("../extension/api");

const CORPUS_PATH = path.join(__dirname, "corpus", "labeled_scam_corpus.json");
const corpus = JSON.parse(fs.readFileSync(CORPUS_PATH, "utf-8"));

// ============================================================================
// 1. Benchmarking & Detection Metrics (Precision, Recall, Confusion Matrix)
// ============================================================================

test("P6-01: Labeled Corpus Evaluation — Confusion Matrix, Precision & Recall", () => {
  let tp = 0; // True Positives: Malicious sample correctly flagged (risk_score >= 40)
  let fp = 0; // False Positives: Benign sample incorrectly flagged (risk_score >= 40)
  let tn = 0; // True Negatives: Benign sample correctly labeled SAFE/LOW (risk_score < 40)
  let fn = 0; // False Negatives: Malicious sample incorrectly labeled SAFE/LOW (risk_score < 40)

  // 1. Evaluate URLs
  for (const item of corpus.urls) {
    const res = ScamEngine.scanUrl(item.content);
    const isFlagged = res.risk_score >= 40 || res.risk_level === "HIGH" || res.risk_level === "CRITICAL";

    if (item.expectedLabel === "PHISHING") {
      if (isFlagged) {
        tp++;
      } else {
        fn++;
        console.error(`[CORPUS FN] Failed to flag phishing URL: ${item.content} (score: ${res.risk_score})`);
      }
    } else {
      if (isFlagged) {
        fp++;
        console.error(`[CORPUS FP] Incorrectly flagged legitimate URL: ${item.content} (score: ${res.risk_score})`);
      } else {
        tn++;
      }
    }
  }

  // 2. Evaluate Messages
  for (const item of corpus.messages) {
    const res = ScamEngine.scanText(item.content);
    const isFlagged = res.risk_score >= 40 || res.risk_level === "HIGH" || res.risk_level === "CRITICAL";

    if (item.expectedLabel === "SCAM_MESSAGE") {
      if (isFlagged) {
        tp++;
      } else {
        fn++;
        console.error(`[CORPUS FN] Failed to flag scam message: ${item.content} (score: ${res.risk_score})`);
      }
    } else {
      if (isFlagged) {
        fp++;
        console.error(`[CORPUS FP] Incorrectly flagged benign message: ${item.content} (score: ${res.risk_score})`);
      } else {
        tn++;
      }
    }
  }

  // 3. Evaluate Payments
  for (const item of corpus.payments) {
    const res = ScamEngine.scanPayment(item.content, item.type);
    const isFlagged = res.risk_score >= 40 || res.risk_level === "HIGH" || res.risk_level === "CRITICAL";

    if (item.expectedLabel === "PAYMENT_SCAM") {
      if (isFlagged) {
        tp++;
      } else {
        fn++;
        console.error(`[CORPUS FN] Failed to flag payment scam: ${item.content} (score: ${res.risk_score})`);
      }
    } else {
      if (isFlagged) {
        fp++;
        console.error(`[CORPUS FP] Incorrectly flagged benign payment: ${item.content} (score: ${res.risk_score})`);
      } else {
        tn++;
      }
    }
  }

  const precision = tp / (tp + fp);
  const recall = tp / (tp + fn);
  const accuracy = (tp + tn) / (tp + tn + fp + fn);
  const f1 = (2 * precision * recall) / (precision + recall);

  console.log(`\n📊 [Phase 6 Detection Benchmark Results]`);
  console.log(`   Samples Evaluated: ${tp + tn + fp + fn}`);
  console.log(`   True Positives (TP):  ${tp}`);
  console.log(`   True Negatives (TN):  ${tn}`);
  console.log(`   False Positives (FP): ${fp}`);
  console.log(`   False Negatives (FN): ${fn}`);
  console.log(`   Precision: ${(precision * 100).toFixed(2)}%`);
  console.log(`   Recall:    ${(recall * 100).toFixed(2)}%`);
  console.log(`   Accuracy:  ${(accuracy * 100).toFixed(2)}%`);
  console.log(`   F1-Score:  ${f1.toFixed(4)}\n`);

  // Target: Zero false positives on legitimate services, high precision and recall
  assert.strictEqual(fp, 0, "Must have 0 false positives on legitimate baseline corpus");
  assert.strictEqual(fn, 0, "Must have 0 false negatives on critical scam fixtures");
  assert.ok(precision >= 0.95, "Precision must be >= 95%");
  assert.ok(recall >= 0.95, "Recall must be >= 95%");
  assert.ok(f1 >= 0.95, "F1 score must be >= 0.95");
});

// ============================================================================
// 2. URL Normalization, Lookalike Domains & Userinfo Spoofing
// ============================================================================

test("P6-02: URL Normalization produces consistent detection regardless of formatting", () => {
  const variations = [
    "https://paypa1.com/login",
    "http://paypa1.com/login",
    "paypa1.com/login",
    "   paypa1.com/login   ",
    "https://PaYpA1.CoM/login/",
    "http://PAYPA1.COM/login?session=123"
  ];

  for (const v of variations) {
    const res = ScamEngine.scanUrl(v);
    assert.strictEqual(
      res.risk_level === "HIGH" || res.risk_level === "CRITICAL",
      true,
      `URL variation '${v}' must be detected as HIGH or CRITICAL`
    );
    assert.ok(
      res.evidence.some((e) => e.category === "BRAND_IMPERSONATION"),
      `Variation '${v}' must detect BRAND_IMPERSONATION`
    );
  }
});

test("P6-03: Userinfo credential spoofing is detected before the @ symbol", () => {
  const spoofedUrl = "https://google.com:password@malicious-phishing-host.xyz/auth";
  const res = ScamEngine.scanUrl(spoofedUrl);

  assert.strictEqual(res.risk_level === "HIGH" || res.risk_level === "CRITICAL", true);
  const userinfoEv = res.evidence.find((e) => e.category === "USERINFO_SPOOFING");
  assert.ok(userinfoEv, "Must flag USERINFO_SPOOFING");
  assert.ok(userinfoEv.reason.includes("malicious-phishing-host.xyz"));
});

// ============================================================================
// 3. Payment Verification & Bounded Uncertainty Guarantees
// ============================================================================

test("P6-04: Payment verification never guarantees settlement and communicates uncertainty", () => {
  const sampleCleanUpi = "merchant@okhdfcbank";
  const cleanRes = ScamEngine.scanPayment(sampleCleanUpi, "upi_id");

  // Even clean VPAs must remain unverified without authoritative banking settlement integration
  assert.strictEqual(cleanRes.payment_status, "unverified");
  assert.strictEqual(cleanRes.detection_method, "rules");

  // Screenshot analysis must explicitly inject the status disclaimer
  const fakeReceipt = "Payment Successful to Ravi Sharma. Paid Rs 1500.";
  const screenshotRes = ScamEngine.scanPayment(fakeReceipt, "screenshot");

  assert.strictEqual(screenshotRes.payment_status, "unverified");
  const disclaimer = screenshotRes.evidence.find((e) => e.category === "STATUS_DISCLAIMER");
  assert.ok(disclaimer, "Must contain STATUS_DISCLAIMER");
  assert.ok(disclaimer.reason.includes("not independently verified"));
});

test("P6-05: Reverse collect fraud & AnyDesk extortion trigger immediate CRITICAL verdicts", () => {
  // Scenario 1: Reverse collect
  const qrCollect = "upi://pay?pa=refund@paytm&tn=Enter+UPI+PIN+to+receive+cashback+reward";
  const qrRes = ScamEngine.scanPayment(qrCollect, "qr_code");

  assert.strictEqual(qrRes.risk_level, "CRITICAL");
  assert.ok(qrRes.risk_score >= 85);
  assert.ok(qrRes.evidence.some((e) => e.category === "REVERSE_COLLECT_FRAUD"));

  // Scenario 2: Remote access extortion
  const anydeskMsg = "Electricity bill is overdue. Install AnyDesk on your mobile for immediate resolution.";
  const msgRes = ScamEngine.scanPayment(anydeskMsg, "message");

  assert.strictEqual(msgRes.risk_level, "CRITICAL");
  assert.ok(msgRes.evidence.some((e) => e.category === "REMOTE_ACCESS_TOOL"));
});

// ============================================================================
// 4. Offline Detection & Graceful Fallback on Network / AI Failures
// ============================================================================

test("P6-06: ScamApi falls back seamlessly to local engine when cloud backend is unavailable", async () => {
  // Point to a non-existent port to guarantee network failure
  ScamApi.init("http://127.0.0.1:59999");

  const phishingUrl = "https://paypa1.com/verify";
  const res = await ScamApi.scan({
    content: phishingUrl,
    type: "url",
    allowAi: true,
    engineMode: "hybrid" // Tries network first, then falls back
  });

  // Verify graceful degradation
  assert.strictEqual(res.is_fallback, true, "Must flag is_fallback when server is unreachable");
  assert.strictEqual(res.detection_method, "rules");
  assert.strictEqual(res.risk_level === "HIGH" || res.risk_level === "CRITICAL", true);
  assert.ok(res.evidence.some((e) => e.category === "BRAND_IMPERSONATION"));
});

test("P6-07: Payment verification API falls back gracefully on server outage", async () => {
  ScamApi.init("http://127.0.0.1:59999");

  const reverseCollectMsg = "Please enter your UPI PIN to claim refund of Rs 2000";
  const res = await ScamApi.verifyPayment({
    content: reverseCollectMsg,
    type: "message",
    allowAi: true,
    engineMode: "hybrid"
  });

  assert.strictEqual(res.is_fallback, true);
  assert.strictEqual(res.detection_method, "rules");
  assert.strictEqual(res.risk_level, "CRITICAL");
  assert.strictEqual(res.payment_status, "unverified");
  assert.ok(res.evidence.some((e) => e.category === "REVERSE_COLLECT_FRAUD"));
});
