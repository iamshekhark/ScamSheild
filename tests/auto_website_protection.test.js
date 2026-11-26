const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.join(__dirname, "..");
const bg = require("../extension/background.js");
const ScamEngine = require("../extension/rules.js");

test("isInspectableUrl filters internal browser, extension, store, and dashboard URLs", () => {
  assert.equal(bg.isInspectableUrl("https://www.google.com/search?q=test"), true);
  assert.equal(bg.isInspectableUrl("http://paytrn-security.xyz/login"), true);
  assert.equal(bg.isInspectableUrl("chrome://extensions"), false);
  assert.equal(bg.isInspectableUrl("chrome-extension://abcdef/popup.html"), false);
  assert.equal(bg.isInspectableUrl("about:blank"), false);
  assert.equal(bg.isInspectableUrl("file:///C:/test.html"), false);
  assert.equal(bg.isInspectableUrl("https://chromewebstore.google.com/detail/test"), false);
  assert.equal(bg.isInspectableUrl("https://chrome.google.com/webstore/detail/test"), false);
  assert.equal(bg.isInspectableUrl("http://localhost:5173/"), false);
});

test("mergeLayeredResults handles legitimate, typosquatted, login form, payment form, and ML-only guard", () => {
  // 1. Legitimate HTTPS
  const safeUrl = ScamEngine.scanUrl("https://www.google.com");
  const safeMerged = bg.mergeLayeredResults(safeUrl, null, null, "https://www.google.com");
  assert.equal(safeMerged.risk_level, "SAFE");
  assert.equal(safeMerged.should_block, false);

  // 2. Typosquatted / phishing URL
  const phishUrl = ScamEngine.scanUrl("http://paytrn-security.xyz/login");
  const phishMerged = bg.mergeLayeredResults(phishUrl, null, null, "http://paytrn-security.xyz/login");
  assert.equal(phishMerged.risk_level, "CRITICAL");
  assert.equal(phishMerged.should_block, true);

  // 3. Suspicious login form posting to external host
  const loginMerged = bg.mergeLayeredResults(
    ScamEngine.scanUrl("https://example-login.test/auth"),
    null,
    { hasPasswordInput: true, externalFormAction: "evil-collector.xyz", hasPaymentKeywords: false },
    "https://example-login.test/auth"
  );
  assert.ok(["HIGH", "CRITICAL"].includes(loginMerged.risk_level));
  assert.ok(loginMerged.indicators.some((i) => i.indicator_type === "SUSPICIOUS_LOGIN_FORM"));

  // 4. Fake payment / KYC form posting externally
  const payMerged = bg.mergeLayeredResults(
    ScamEngine.scanUrl("https://example-kyc.test/verify"),
    null,
    { hasPasswordInput: true, externalFormAction: "steal-kyc.top", hasPaymentKeywords: true },
    "https://example-kyc.test/verify"
  );
  assert.equal(payMerged.risk_level, "CRITICAL");
  assert.equal(payMerged.should_block, true);
  assert.ok(payMerged.indicators.some((i) => i.indicator_type === "EXTERNAL_PAYMENT_FORM"));

  // 5. Never block solely on ML-only indicator without deterministic evidence
  const mlOnlyMerged = bg.mergeLayeredResults(
    {
      risk_score: 90,
      risk_level: "CRITICAL",
      indicators: [{ indicator_type: "ML_URL_ANOMALY", description: "ML model score", severity: "high" }]
    },
    null,
    null,
    "https://neutral-site.example"
  );
  assert.equal(mlOnlyMerged.should_block, false);
});

test("badgeForRisk maps SAFE, warnings, CRITICAL, and UNABLE_TO_VERIFY accurately", () => {
  assert.equal(bg.badgeForRisk("SAFE").text, "SAFE");
  assert.equal(bg.badgeForRisk("HIGH").text, "WARN");
  assert.equal(bg.badgeForRisk("CRITICAL").text, "!!!");
  assert.equal(bg.badgeForRisk("UNABLE_TO_VERIFY").text, "?");
});

test("Manifest V3, content_guard.js privacy, and popup auto-protect toggle are properly wired", () => {
  const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, "extension/manifest.json"), "utf8"));
  assert.ok(manifest.permissions.includes("webNavigation"));
  assert.ok(manifest.permissions.includes("tabs"));
  assert.ok(manifest.permissions.includes("notifications"));
  assert.ok(manifest.content_scripts.some((cs) => cs.js.includes("content_guard.js")));

  const guardSrc = fs.readFileSync(path.join(ROOT, "extension/content_guard.js"), "utf8");
  assert.doesNotMatch(guardSrc, /document\.cookie/);
  assert.match(guardSrc, /attachShadow\(\{ mode: "closed" \}\)/);
  assert.match(guardSrc, /RECORD_GUARD_OVERRIDE/);

  const popupHtml = fs.readFileSync(path.join(ROOT, "extension/popup.html"), "utf8");
  assert.match(popupHtml, /id="toggle-auto-protect"/);
  assert.match(popupHtml, /id="auto-protect-status"/);
  assert.match(popupHtml, /id="setting-auto-protect"/);
});

test("Legitimate payment and government portals (Paytm, IRCTC, SBI, HDFC, Razorpay) are not false-positived", () => {
  const legitCases = [
    {
      url: "https://secure.paytmpayments.com/theia/api/v1/showPaymentPage",
      title: "Paytm Payment Gateway",
      bodyText: "Select an option to pay ₹427.25. Debit Card Number, CVV, Netbanking, UPI. Enter OTP sent to your mobile.",
      dom: { hasPasswordInput: false, hasPaymentKeywords: true, externalFormAction: "" }
    },
    {
      url: "https://paytm.com/recharge",
      title: "Paytm Recharge & Bill Payments",
      bodyText: "Login with mobile number. Enter verification code / OTP to proceed with payment.",
      dom: { hasPasswordInput: true, hasPaymentKeywords: true, externalFormAction: "" }
    },
    {
      url: "https://www.irctc.co.in/nget/train-search",
      title: "IRCTC Next Generation eTicketing System",
      bodyText: "Only Aadhaar Verified users can book Tatkal Train Tickets. Please select your preferred language. Enter OTP for booking.",
      dom: { hasPasswordInput: true, hasPaymentKeywords: true, externalFormAction: "" }
    },
    {
      url: "https://www.onlinesbi.sbi/personal/",
      title: "State Bank of India - Personal Banking",
      bodyText: "Login to NetBanking. Enter OTP. Never share your OTP or PIN with anyone.",
      dom: { hasPasswordInput: true, hasPaymentKeywords: true, externalFormAction: "" }
    },
    {
      url: "https://netbanking.hdfcbank.com/netbanking/",
      title: "Welcome to HDFC Bank NetBanking",
      bodyText: "Customer ID / User ID. Password. Enter OTP. Debit Card Number and CVV for verification.",
      dom: { hasPasswordInput: true, hasPaymentKeywords: true, externalFormAction: "" }
    },
    {
      url: "https://api.razorpay.com/v1/checkout/public",
      title: "Razorpay Checkout",
      bodyText: "Pay via UPI, Debit Card Number, CVV, Netbanking. Enter OTP to complete payment.",
      dom: { hasPasswordInput: false, hasPaymentKeywords: true, externalFormAction: "" }
    }
  ];

  for (const c of legitCases) {
    const urlRes = ScamEngine.scanUrl(c.url);
    const textRes = ScamEngine.scanText(`${c.title}\n${c.bodyText}`, { context: "webpage" });
    const merged = bg.mergeLayeredResults(urlRes, textRes, c.dom, c.url);
    assert.equal(merged.risk_level, "SAFE", `Expected SAFE for ${c.url}, got ${merged.risk_level} (${merged.risk_score})`);
    assert.equal(merged.risk_score, 0, `Expected 0 score for ${c.url}, got ${merged.risk_score}`);
    assert.equal(merged.should_block, false, `Expected should_block=false for ${c.url}`);
  }
});

test("Malicious typosquats, fake login/payment forms, and SMS phishing remain detected and blocked", () => {
  // 1. Typosquatted Paytm payment domain
  const typoPaytm = ScamEngine.scanUrl("https://secure.paytmpayment-verify.xyz/login");
  const typoMerged = bg.mergeLayeredResults(typoPaytm, null, null, "https://secure.paytmpayment-verify.xyz/login");
  assert.ok(["HIGH", "CRITICAL"].includes(typoMerged.risk_level));
  assert.ok(typoMerged.risk_score >= 65);
  assert.ok(typoMerged.indicators.every((i) => i.indicator_type && i.description));

  // 2. Phishing lookalike with suspicious path + HTTP
  const phishPaytm = ScamEngine.scanUrl("http://paytrn-security.xyz/verify");
  const phishMerged = bg.mergeLayeredResults(phishPaytm, null, null, "http://paytrn-security.xyz/verify");
  assert.equal(phishMerged.risk_level, "CRITICAL");
  assert.equal(phishMerged.should_block, true);
  assert.ok(phishMerged.indicators.length > 0);
  assert.ok(phishMerged.indicators.every((i) => i.indicator_type && i.description && i.indicator_type !== "SIGNAL"));

  // 3. SMS / message context still flags OTP & card credential bait
  const smsScam = ScamEngine.scanText("Dear user, your KYC is suspended. Enter your debit card number, CVV and share OTP at http://paytrn-security.xyz");
  assert.equal(smsScam.risk_level, "CRITICAL");
  assert.ok(smsScam.risk_score >= 85);

  // 4. Weak-only deterministic signals must not trigger CRITICAL blocking
  const weakOnly = bg.mergeLayeredResults(
    {
      risk_score: 82,
      risk_level: "CRITICAL",
      evidence: [
        { category: "DOMAIN_STRUCTURE", severity: "LOW", reason: "Risky TLD" },
        { category: "URGENCY", severity: "MEDIUM", reason: "Urgent wording" }
      ]
    },
    null,
    null,
    "https://example-weak.xyz"
  );
  assert.equal(weakOnly.should_block, false);
  assert.notEqual(weakOnly.risk_level, "CRITICAL");
});

test("content_guard.js normalizes indicators, filters blank entries, and handles empty indicator fallback", () => {
  const guardSrc = fs.readFileSync(path.join(ROOT, "extension/content_guard.js"), "utf8");
  assert.match(guardSrc, /No actionable threat indicators available\./);
  assert.match(guardSrc, /getRegistrableDomain/);
  assert.match(guardSrc, /ind\.indicator_type \|\| ind\.category/);
  assert.match(guardSrc, /ind\.description \|\| ind\.reason/);
});
