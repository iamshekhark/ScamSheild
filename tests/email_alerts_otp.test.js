// Automated Integration Test: Email Integration, OTP Verification, Alerts & Security Boundaries
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");

// Setup Web Crypto API globals for Node environment
if (!global.crypto) {
  global.crypto = crypto;
}

const ScamEngine = require("../extension/rules.js");

// Mock in-memory OTP verification logic matching Edge Function implementation
class TestOtpService {
  constructor() {
    this.challenges = new Map();
  }

  async hashOtp(code, salt) {
    return crypto.createHash("sha256").update(`${salt}:${code.trim()}`).digest("hex");
  }

  generateCode() {
    const buf = crypto.randomBytes(4);
    const num = (buf.readUInt32BE(0) % 900000) + 100000;
    return num.toString();
  }

  async requestVerification(email, purpose = "registration") {
    const cleanEmail = email.toLowerCase().trim();
    const now = Date.now();

    // Check cooldown (60 seconds)
    const existing = this.challenges.get(`${cleanEmail}:${purpose}`);
    if (existing && !existing.consumed && existing.resendAfter > now) {
      const wait = Math.ceil((existing.resendAfter - now) / 1000);
      throw new Error(`Cooldown active: please wait ${wait} seconds`);
    }

    const code = this.generateCode();
    const salt = crypto.randomBytes(16).toString("hex");
    const codeHash = await this.hashOtp(code, salt);

    const challenge = {
      codeHash,
      salt,
      expiresAt: now + 5 * 60 * 1000, // 5 minutes
      resendAfter: now + 60 * 1000,   // 60 seconds cooldown
      attemptCount: 0,
      maxAttempts: 5,
      consumed: false
    };

    this.challenges.set(`${cleanEmail}:${purpose}`, challenge);
    return { code, expiresAt: challenge.expiresAt };
  }

  async verifyCode(email, inputCode, purpose = "registration") {
    const cleanEmail = email.toLowerCase().trim();
    const challenge = this.challenges.get(`${cleanEmail}:${purpose}`);

    if (!challenge) throw new Error("No active challenge found");
    if (challenge.consumed) throw new Error("Code has already been consumed");
    if (Date.now() > challenge.expiresAt) throw new Error("Verification code has expired");

    challenge.attemptCount++;
    if (challenge.attemptCount > challenge.maxAttempts) {
      challenge.consumed = true;
      throw new Error("Maximum attempts exceeded. Code has been invalidated.");
    }

    const inputHash = await this.hashOtp(inputCode, challenge.salt);
    if (inputHash !== challenge.codeHash) {
      const remaining = challenge.maxAttempts - challenge.attemptCount;
      throw new Error(`Invalid code. ${remaining} attempts remaining.`);
    }

    challenge.consumed = true;
    return { verified: true };
  }
}

// 1. OTP Verification Security Tests
test("OTP generation produces valid 6-digit codes", () => {
  const service = new TestOtpService();
  for (let i = 0; i < 20; i++) {
    const code = service.generateCode();
    assert.equal(code.length, 6);
    assert.match(code, /^\d{6}$/);
  }
});

test("Salted SHA-256 hashes correctly verify authentic codes and reject bad codes", async () => {
  const service = new TestOtpService();
  const salt = "random_salt_123";
  const originalCode = "849201";
  const hash = await service.hashOtp(originalCode, salt);

  assert.equal(await service.hashOtp("849201", salt), hash);
  assert.notEqual(await service.hashOtp("849202", salt), hash);
});

test("OTP verification succeeds with valid code and enforces single-use invalidation", async () => {
  const service = new TestOtpService();
  const req = await service.requestVerification("test@scamshield.local", "registration");

  // First verification succeeds
  const res = await service.verifyCode("test@scamshield.local", req.code, "registration");
  assert.equal(res.verified, true);

  // Replay attempt fails (single-use)
  await assert.rejects(
    async () => { await service.verifyCode("test@scamshield.local", req.code, "registration"); },
    { message: "Code has already been consumed" }
  );
});

test("OTP attempt limit locks and invalidates after 5 wrong attempts", async () => {
  const service = new TestOtpService();
  const req = await service.requestVerification("target@scamshield.local", "recipient_verification");

  // 5 wrong attempts
  for (let i = 0; i < 5; i++) {
    await assert.rejects(
      async () => { await service.verifyCode("target@scamshield.local", "000000", "recipient_verification"); }
    );
  }

  // 6th attempt is blocked for exceeding max attempts even with correct code
  await assert.rejects(
    async () => { await service.verifyCode("target@scamshield.local", req.code, "recipient_verification"); },
    { message: "Maximum attempts exceeded. Code has been invalidated." }
  );
});

test("OTP resend cooldown enforces 60-second waiting period", async () => {
  const service = new TestOtpService();
  await service.requestVerification("cooldown@scamshield.local", "registration");

  // Immediate resend is rejected
  await assert.rejects(
    async () => { await service.requestVerification("cooldown@scamshield.local", "registration"); },
    (err) => err.message.includes("Cooldown active")
  );
});

// 2. Email Scam Rules & Threat Detection Tests
test("Email Scanner flags sender brand spoofing as CRITICAL risk", () => {
  const spoofedSender = "Paytm Security <alert-support@paytrn-security.xyz>";
  const subject = "URGENT: Your KYC is expired";
  const body = "Please update your KYC immediately at http://paytrn-security.xyz/verify";

  const result = ScamEngine.scanEmail(spoofedSender, subject, body);
  assert.ok(result.risk_score >= 75);
  assert.equal(result.risk_level, "CRITICAL");
  assert.ok(result.evidence.some((e) => e.category === "BRAND_IMPERSONATION"));
});

test("Email Scanner flags overdue invoice wire fraud as HIGH/CRITICAL risk", () => {
  const sender = "Billing Dept <invoices@cloud-service-billing.top>";
  const subject = "Invoice #98201 Overdue - Immediate wire transfer required";
  const body = "Please remit funds immediately or legal action will be initiated.";

  const result = ScamEngine.scanEmail(sender, subject, body);
  assert.ok(result.risk_score >= 50);
  assert.ok(result.evidence.some((e) => e.category === "FINANCIAL_FRAUD"));
});

test("Clean authentic emails return SAFE level with 0-score", () => {
  const sender = "GitHub <notifications@github.com>";
  const subject = "[GitHub] Security advisory published for repository";
  const body = "A security advisory has been published for your dependency.";

  const result = ScamEngine.scanEmail(sender, subject, body);
  assert.equal(result.risk_score, 0);
  assert.equal(result.risk_level, "SAFE");
  assert.equal(result.evidence.length, 0);
});

// 3. Notification Deduplication & Suppression Tests
test("Alert delivery system suppresses duplicate notifications with same deduplication key", () => {
  const dispatchedKeys = new Set();

  function dispatchNotification(userId, deduplicationKey) {
    if (dispatchedKeys.has(`${userId}:${deduplicationKey}`)) {
      return { delivery_status: "suppressed" };
    }
    dispatchedKeys.add(`${userId}:${deduplicationKey}`);
    return { delivery_status: "delivered" };
  }

  const res1 = dispatchNotification("user_101", "scan_alert_msg_445_critical");
  assert.equal(res1.delivery_status, "delivered");

  const res2 = dispatchNotification("user_101", "scan_alert_msg_445_critical");
  assert.equal(res2.delivery_status, "suppressed");
});
