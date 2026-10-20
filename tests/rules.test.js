// Automated Unit Tests: ScamShield Core Rules & Scoring Normalization
const test = require("node:test");
const assert = require("node:assert/strict");
const ScamEngine = require("../extension/rules.js");

test("Clean websites return 0 score and SAFE level", () => {
  const google = ScamEngine.scanUrl("https://www.google.com");
  assert.equal(google.risk_score, 0);
  assert.equal(google.risk_level, "SAFE");
  assert.equal(google.evidence.length, 0);

  const github = ScamEngine.scanUrl("https://github.com");
  assert.equal(github.risk_score, 0);
  assert.equal(github.risk_level, "SAFE");
});

test("Lookalike brand domains trigger critical brand impersonation", () => {
  const paytmPhish = ScamEngine.scanUrl("http://paytrn-security.xyz/login");
  assert.ok(paytmPhish.risk_score >= 75, `Expected score >= 75, got ${paytmPhish.risk_score}`);
  assert.equal(paytmPhish.risk_level, "CRITICAL");
  assert.ok(paytmPhish.evidence.some((e) => e.category === "BRAND_IMPERSONATION"));
  assert.ok(paytmPhish.evidence.some((e) => e.category === "DOMAIN_STRUCTURE"));
});

test("Raw IP address hosts trigger high severity IP warnings", () => {
  const ipScan = ScamEngine.scanUrl("http://192.168.1.50/verify");
  assert.ok(ipScan.risk_score >= 75);
  assert.ok(ipScan.evidence.some((e) => e.category === "SUSPICIOUS_IP_URL"));
});

test("OTP requests are flagged unless explicitly negated", () => {
  const scamOtp = ScamEngine.scanText("URGENT: Your account will be blocked. Share your OTP immediately.");
  assert.ok(scamOtp.evidence.some((e) => e.category === "OTP_REQUEST"));
  assert.ok(scamOtp.evidence.some((e) => e.category === "URGENCY"));
  assert.ok(scamOtp.risk_score >= 60);

  // Negation test
  const legitimateWarning = ScamEngine.scanText("Bank notice: Do not share your OTP with anyone, including bank staff.");
  assert.equal(legitimateWarning.evidence.some((e) => e.category === "OTP_REQUEST"), false);
});

test("Score levels strictly follow specification thresholds", () => {
  // 0-24: Low / Safe
  assert.equal(ScamEngine.calculateRisk([]).risk_level, "SAFE");

  // Single low severity: e.g. TLD (.xyz)
  const lowTld = ScamEngine.calculateRisk([{ category: "DOMAIN_STRUCTURE", severity: "LOW", reason: "TLD" }]);
  assert.ok(lowTld.risk_score <= 24);
  assert.equal(lowTld.risk_level, "SAFE");

  // High severity OTP + Urgency + IP -> Critical
  const critical = ScamEngine.calculateRisk([
    { category: "OTP_REQUEST", severity: "HIGH", reason: "OTP" },
    { category: "URGENCY", severity: "MEDIUM", reason: "Urgent" },
    { category: "SUSPICIOUS_IP_URL", severity: "HIGH", reason: "IP" }
  ]);
  assert.ok(critical.risk_score >= 75);
  assert.equal(critical.risk_level, "CRITICAL");
});

test("Input guards handle null, undefined, and empty inputs gracefully without throwing", () => {
  const nullUrl = ScamEngine.scanUrl(null);
  assert.equal(nullUrl.risk_score, 0);
  assert.equal(nullUrl.risk_level, "SAFE");

  const emptyText = ScamEngine.scanText("");
  assert.equal(emptyText.risk_score, 0);
  assert.equal(emptyText.risk_level, "SAFE");

  const undefinedEmail = ScamEngine.scanEmail(undefined, null, "");
  assert.equal(undefinedEmail.risk_score, 0);
  assert.equal(undefinedEmail.risk_level, "SAFE");

  const nullPayment = ScamEngine.scanPayment(null, "qr_code");
  assert.equal(nullPayment.risk_score, 0);
  assert.equal(nullPayment.risk_level, "SAFE");
});

test("Digital Arrest and law enforcement coercion triggers CRITICAL risk", () => {
  const text = "CBI Digital Arrest Notice: A narcotics parcel was seized in your name. Connect immediately for police interrogation or face non-bailable arrest warrant.";
  const res = ScamEngine.scanText(text);
  assert.ok(res.risk_score >= 80, `Expected score >= 80, got ${res.risk_score}`);
  assert.equal(res.risk_level, "CRITICAL");
  assert.ok(res.evidence.some((e) => e.category === "DIGITAL_ARREST_EXTORTION"));
});

test("Hinglish OTP request and prepaid job task fraud trigger high severity alerts", () => {
  const hinglishOtp = ScamEngine.scanText("Aapka account verify karne ke liye turant OTP batao warna account band hoga");
  assert.ok(hinglishOtp.evidence.some((e) => e.category === "OTP_REQUEST"));

  const taskScam = ScamEngine.scanText("Part-time job offer: YouTube like and subscribe to earn Rs 5000 daily. Join telegram prepaid task now.");
  assert.ok(taskScam.evidence.some((e) => e.category === "JOB_TASK_FRAUD"));
  assert.ok(taskScam.risk_score >= 40);
});

test("H1: Multi-domain brand whitelisting avoids false positives on authentic regional & service domains", () => {
  const amazonIn = ScamEngine.scanUrl("https://www.amazon.in/gp/product/B08N5WRWNW");
  assert.equal(amazonIn.risk_score, 0);
  assert.equal(amazonIn.risk_level, "SAFE");
  assert.equal(amazonIn.evidence.some((e) => e.category === "BRAND_IMPERSONATION"), false);

  const msOnline = ScamEngine.scanUrl("https://login.microsoftonline.com/common/oauth2");
  assert.equal(msOnline.risk_score, 0);
  assert.equal(msOnline.risk_level, "SAFE");

  const sbi = ScamEngine.scanUrl("https://onlinesbi.sbi/portal");
  assert.equal(sbi.risk_score, 0);
  assert.equal(sbi.risk_level, "SAFE");

  const googleAcc = ScamEngine.scanUrl("https://accounts.google.com/signin/v2");
  assert.equal(googleAcc.risk_score, 0);
  assert.equal(googleAcc.risk_level, "SAFE");

  // Email sender domain whitelisting
  const amazonMail = ScamEngine.scanEmail("Amazon India <orders@amazon.in>", "Your order has shipped", "Package arriving tomorrow.");
  assert.equal(amazonMail.evidence.some((e) => e.category === "BRAND_IMPERSONATION"), false);
  assert.equal(amazonMail.risk_level, "SAFE");
});

test("H2: Advanced URL heuristics catch userinfo spoofing, punycode, unsafe schemes, and typosquatting", () => {
  // Userinfo spoofing
  const userinfo = ScamEngine.scanUrl("https://microsoft.com@attacker-site.com/login");
  assert.ok(userinfo.evidence.some((e) => e.category === "USERINFO_SPOOFING"));
  assert.notEqual(userinfo.risk_level, "SAFE");

  // Punycode
  const punycode = ScamEngine.scanUrl("https://xn--e1afmkfd.xn--p1ai/auth");
  assert.ok(punycode.evidence.some((e) => e.category === "PUNYCODE_LOOKALIKE"));
  assert.notEqual(punycode.risk_level, "SAFE");

  // Unsafe schemes
  const jsScheme = ScamEngine.scanUrl("javascript:alert(document.cookie)");
  assert.ok(jsScheme.evidence.some((e) => e.category === "UNSAFE_SCHEME"));
  assert.equal(jsScheme.risk_level, "HIGH");

  // Typosquatting (paypa1 with numeral substitution)
  const typosquat = ScamEngine.scanUrl("https://paypa1.com/verify");
  assert.ok(typosquat.evidence.some((e) => e.category === "BRAND_IMPERSONATION"));
  assert.ok(typosquat.risk_score >= 65);

  // URL shorteners
  const shortener = ScamEngine.scanUrl("https://bit.ly/3XYZ123");
  assert.ok(shortener.evidence.some((e) => e.category === "URL_SHORTENER"));
});

test("H3: Scam text patterns detect advance-fee, customs, fake prizes, and conversational Hinglish OTP phrases", () => {
  // Advance-fee lottery
  const lottery = ScamEngine.scanText("Congratulations! You won Rs 50,00,000 cash prize in lucky draw. Pay 1500 processing fee to claim transfer.");
  assert.ok(lottery.evidence.some((e) => e.category === "PRIZE_ADVANCE_FEE"));
  assert.ok(lottery.risk_score >= 60);

  // Fake prize claim
  const prize = ScamEngine.scanText("You have won an iPhone 16 Pro reward! Click link now to claim your gift.");
  assert.ok(prize.evidence.some((e) => e.category === "PRIZE_ADVANCE_FEE"));

  // Customs / courier parcel extortion
  const customs = ScamEngine.scanText("Customs alert: Your courier parcel was held and seized. Pay fine immediately to release shipment.");
  assert.ok(customs.evidence.some((e) => e.category === "COURIER_CUSTOMS"));
  assert.ok(customs.risk_score >= 60);

  // Hinglish conversational OTP
  const hinglish1 = ScamEngine.scanText("Bhai jaldi otp bhej do order confirm karna hai");
  assert.ok(hinglish1.evidence.some((e) => e.category === "OTP_REQUEST"));

  const hinglish2 = ScamEngine.scanText("paisa aane ke liye apna upi pin daalo");
  assert.ok(hinglish2.evidence.some((e) => e.category === "REVERSE_COLLECT_FRAUD" || e.category === "OTP_REQUEST"));
});

test("H6: Severity floor guarantee ensures HIGH/CRITICAL findings are never labeled SAFE", () => {
  const highEvidence = ScamEngine.calculateRisk([
    { category: "USERINFO_SPOOFING", severity: "HIGH", reason: "Deceptive userinfo" }
  ]);
  assert.equal(highEvidence.risk_level, "HIGH");
  assert.ok(highEvidence.risk_score >= 65);

  const critEvidence = ScamEngine.calculateRisk([
    { category: "REVERSE_COLLECT_FRAUD", severity: "CRITICAL", reason: "PIN to receive" }
  ]);
  assert.equal(critEvidence.risk_level, "CRITICAL");
  assert.ok(critEvidence.risk_score >= 85);
});

test("Payment scanner correctly parses both 'qr' and 'qr_code' input types", () => {
  const qrUri = "upi://pay?pa=scammer@okaxis&pn=Customer%20Support&tn=Enter%20PIN%20to%20receive%20refund";
  const resQr = ScamEngine.scanPayment(qrUri, "qr");
  assert.equal(resQr.risk_level, "CRITICAL");
  assert.ok(resQr.evidence.some((e) => e.category === "REVERSE_COLLECT_FRAUD"));

  const resQrCode = ScamEngine.scanPayment(qrUri, "qr_code");
  assert.equal(resQrCode.risk_level, "CRITICAL");
  assert.equal(resQrCode.risk_score, resQr.risk_score);
});

