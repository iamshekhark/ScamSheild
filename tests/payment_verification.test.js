const test = require("node:test");
const assert = require("node:assert");
const ScamEngine = require("../extension/rules.js");

test("Authentic UPI VPAs return SAFE level with 0 risk score", () => {
  const authenticVpas = [
    "grocery.store@okhdfcbank",
    "john.doe@paytm",
    "bookshop@okaxis",
    "swiggy.order@icici"
  ];

  for (const vpa of authenticVpas) {
    const res = ScamEngine.scanPayment(vpa, "upi_id");
    assert.strictEqual(res.risk_level, "SAFE", `Expected ${vpa} to be SAFE`);
    assert.strictEqual(res.risk_score, 0);
    assert.strictEqual(res.payment_status, "unverified");
  }
});

test("Impersonated / Deceptive UPI handles trigger CRITICAL brand impersonation", () => {
  const deceptiveVpas = [
    "paytm-refund-desk@ybl",
    "sbi-kyc-verify@okhdfcbank",
    "phonepe-cashback-support@ibl",
    "gpay-helpdesk-official@axl"
  ];

  for (const vpa of deceptiveVpas) {
    const res = ScamEngine.scanPayment(vpa, "upi_id");
    assert.ok(
      ["HIGH", "CRITICAL"].includes(res.risk_level),
      `Expected ${vpa} to be HIGH or CRITICAL, got ${res.risk_level}`
    );
    assert.ok(res.risk_score >= 65, `Expected score >= 65, got ${res.risk_score}`);
    assert.ok(
      res.evidence.some((e) => e.category === "BRAND_IMPERSONATION" || e.category === "DECEPTIVE_PAYEE_HANDLE")
    );
  }
});

test("Malformed UPI syntax is detected and flagged", () => {
  const badVpas = ["not-an-email-or-upi", "user@@bank", "@justbank", "missinghandle@"];
  for (const vpa of badVpas) {
    const res = ScamEngine.scanPayment(vpa, "upi_id");
    assert.ok(res.evidence.some((e) => e.category === "UPI_SYNTAX"));
  }
});

test("QR code with 'Enter PIN to receive money' triggers CRITICAL REVERSE_COLLECT_FRAUD", () => {
  const reverseCollectQr = "upi://pay?pa=scammer99@ybl&pn=Refund%20Officer&am=5000&cu=INR&tn=Enter%20your%206-digit%20UPI%20PIN%20to%20receive%20refund";
  const res = ScamEngine.scanPayment(reverseCollectQr, "qr_code");

  assert.strictEqual(res.risk_level, "CRITICAL");
  assert.ok(res.risk_score >= 85);
  const fraudEvidence = res.evidence.find((e) => e.category === "REVERSE_COLLECT_FRAUD");
  assert.ok(fraudEvidence, "Should detect reverse collect fraud");
  assert.match(fraudEvidence.reason, /In UPI architecture, entering your PIN ALWAYS debits funds/);
});

test("Payee name claiming official support with individual personal VPA triggers mismatch warning", () => {
  const mismatchedQr = "upi://pay?pa=rahul9823412@ybl&pn=SBI%20Customer%20Care&am=1200&cu=INR&tn=Bill%20Payment";
  const res = ScamEngine.scanPayment(mismatchedQr, "qr_code");

  assert.ok(res.risk_score >= 40);
  assert.ok(res.evidence.some((e) => e.category === "PAYEE_MISMATCH"));
});

test("Electricity bill disconnection extortion message triggers HIGH risk", () => {
  const scamMsg = "Dear customer, your electricity power will be disconnected tonight at 9:30 PM due to unpaid bill. Immediately pay Rs 1450 to avoid shut off. Call officer at 9876543210 or UPI billdesk-support@ybl";
  const res = ScamEngine.scanPayment(scamMsg, "message");

  assert.ok(["HIGH", "CRITICAL"].includes(res.risk_level));
  assert.ok(res.evidence.some((e) => e.category === "UTILITY_EXTORTION"));
});

test("Remote access software trap (AnyDesk / TeamViewer) triggers CRITICAL risk", () => {
  const remoteAccessMsg = "Your KYC is suspended. Please install AnyDesk app immediately to share screen and verify bank payment.";
  const res = ScamEngine.scanPayment(remoteAccessMsg, "message");

  assert.strictEqual(res.risk_level, "CRITICAL");
  assert.ok(res.evidence.some((e) => e.category === "REMOTE_ACCESS_TOOL"));
});

test("Payment status is always unverified without authoritative bank settlement integration", () => {
  const fakeConfirmation = "Payment Successful! Paid Rs 50,000 to Store Manager. Transaction completed.";
  const res = ScamEngine.scanPayment(fakeConfirmation, "screenshot");

  assert.strictEqual(res.payment_status, "unverified");
  assert.ok(res.evidence.some((e) => e.category === "STATUS_DISCLAIMER"));
  assert.ok(res.evidence.some((e) => e.category === "SUSPICIOUS_PAYMENT_CONFIRMATION"));
});
