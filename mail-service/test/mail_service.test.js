const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const fs = require("node:fs");

// Provide test-only self-contained environment configuration BEFORE importing server modules
const originalEnv = { ...process.env };
const TEST_TOKEN_FILE = path.join(__dirname, `test_token_cache_${Date.now()}.json`);

process.env.TOKEN_CACHE_FILE = TEST_TOKEN_FILE;
process.env.TOKEN_ENCRYPTION_KEY = process.env.TOKEN_ENCRYPTION_KEY || "test_token_encryption_key_32bytes_mock_1234!";
process.env.MAIL_SERVICE_API_KEY = process.env.MAIL_SERVICE_API_KEY || "test_mock_mail_api_key_5678";

// Clean up temporary files on process exit or test end
test.after(() => {
  if (fs.existsSync(TEST_TOKEN_FILE)) {
    try { fs.unlinkSync(TEST_TOKEN_FILE); } catch {}
  }
  process.env = originalEnv;
});

const { MailerService } = require("../src/mailer");
const { app, mailTokens, setMailToken, getStorageEncryptionKey } = require("../src/server");
const { verificationCodeEmail, highRiskAlertEmail } = require("../src/templates");

test("Mail Service: verifies SMTP connection or safe configuration fallback", async () => {
  const mailer = new MailerService();
  if (mailer.isConfigured()) {
    const res = await mailer.verifyConnection();
    assert.strictEqual(res.configured, true);
    // When SMTP is configured, result must either be verified or safely failed without crashing
    assert.ok(typeof res.status === "string");
  } else {
    assert.strictEqual(mailer.isConfigured(), false);
  }
});

test("Mail Service: renders branded verification and alert emails", () => {
  const vEmail = verificationCodeEmail({
    email: "test@example.com",
    code: "654321",
    purpose: "registration"
  });
  assert.ok(vEmail.subject.includes("654321"));
  assert.ok(vEmail.html.includes("654321"));

  const aEmail = highRiskAlertEmail({
    sender: "attacker@spoofed.com",
    subject: "Urgent wire needed",
    riskScore: 90,
    riskLevel: "critical",
    explanation: "High risk scam pattern"
  });
  assert.ok(aEmail.subject.includes("CRITICAL"));
});

test("Mail Service: fail-closed token encryption key verification", () => {
  // Test that missing encryption keys fail closed
  const savedKey = process.env.TOKEN_ENCRYPTION_KEY;
  const savedApiKey = process.env.MAIL_SERVICE_API_KEY;
  delete process.env.TOKEN_ENCRYPTION_KEY;
  delete process.env.MAIL_SERVICE_API_KEY;

  assert.throws(
    () => getStorageEncryptionKey(),
    /CRITICAL_SECURITY_ERROR/
  );

  // Restore test keys
  process.env.TOKEN_ENCRYPTION_KEY = savedKey;
  process.env.MAIL_SERVICE_API_KEY = savedApiKey;
  assert.ok(Buffer.isBuffer(getStorageEncryptionKey()));
});

test("Mail Service: Token cache management handles session tokens cleanly with isolated encryption", () => {
  const email = "unit.test@example.com";
  setMailToken(email, {
    accessToken: "unit_token",
    provider: "gmail",
    expiresAt: Date.now() + 3600000
  });

  assert.strictEqual(mailTokens.has(email), true);
  assert.ok(fs.existsSync(TEST_TOKEN_FILE), "Isolated test token cache file should be created");

  mailTokens.delete(email);
  assert.strictEqual(mailTokens.has(email), false);

  // Clean up test file
  if (fs.existsSync(TEST_TOKEN_FILE)) {
    fs.unlinkSync(TEST_TOKEN_FILE);
  }
});
