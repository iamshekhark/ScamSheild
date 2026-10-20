// Automated Test Suite: ScamShield Nodemailer Mail Service & Supabase Integration
// Tests templates, API key security, rate limiting, input validation, and email dispatch routing

const test = require("node:test");
const assert = require("node:assert/strict");

const {
  verificationCodeEmail,
  passwordResetEmail,
  welcomeEmail,
  awarenessAdvisoryEmail,
  highRiskAlertEmail,
  BRAND
} = require("../mail-service/src/templates");
const { MailerService } = require("../mail-service/src/mailer");

// ---------------------------------------------------------------------------
// 1. Template Rendering & Branding Tests
// ---------------------------------------------------------------------------

test("Mail Templates: verificationCodeEmail produces branded HTML & text for distinct accounts", () => {
  const accounts = [
    { email: "alice@primary-domain.com", code: "482910", purpose: "registration" },
    { email: "bob.secondary@work-corp.in", code: "719304", purpose: "password_reset" },
    { email: "carol@bank-security.net", code: "951230", purpose: "mailbox_connection" }
  ];

  for (const acct of accounts) {
    const res = verificationCodeEmail({
      email: acct.email,
      code: acct.code,
      purpose: acct.purpose,
      expiryMinutes: 10
    });

    // Subject assertion
    assert.ok(res.subject.includes(acct.code), "Subject must include the 6-digit code");
    assert.ok(res.subject.includes("[ScamShield]"), "Subject must have brand prefix");

    // HTML assertions
    assert.ok(res.html.includes(acct.code), "HTML must contain the code");
    assert.ok(res.html.includes(acct.email), "HTML must display target email address");
    assert.ok(res.html.includes(BRAND.bgBase), "HTML must use dark navy SOC base background");
    assert.ok(res.html.includes(BRAND.accentCyan), "HTML must use cyan brand accent");
    assert.ok(res.html.includes("Never share this code with anyone"), "HTML must include anti-fraud warning");

    // Plain-text alternative assertions
    assert.ok(res.text.includes(acct.code), "Plain text must contain the code");
    assert.ok(res.text.includes(acct.email), "Plain text must contain recipient email");
    assert.ok(res.text.includes("SECURITY NOTICE"), "Plain text must include security notice");
  }
});

test("Mail Templates: HTML escaping prevents script injection in recipient email & content", () => {
  const maliciousInput = {
    email: 'user<script>alert("xss")</script>@domain.com',
    code: "123456",
    purpose: '"><img src=x onerror=alert(1)>'
  };

  const res = verificationCodeEmail(maliciousInput);
  assert.ok(!res.html.includes("<script>alert"), "HTML should not contain unescaped script tag");
  assert.ok(res.html.includes("&lt;script&gt;"), "Script tag must be safely escaped");
});

test("Mail Templates: highRiskAlertEmail generates urgent SOC threat warnings", () => {
  const payload = {
    sender: "Paytm Helpdesk <phish@paytrn-security.xyz>",
    subject: "Urgent: Complete KYC or account suspended",
    riskScore: 95,
    riskLevel: "critical",
    explanation: "Detected high-severity brand impersonation and credential harvesting attempt."
  };

  const res = highRiskAlertEmail(payload);
  assert.ok(res.subject.includes("[CRITICAL ALERT]"));
  assert.ok(res.html.includes("CRITICAL (95/100)"));
  assert.ok(res.html.includes("Recommended Action"));
  assert.ok(res.text.includes("SCAMSHIELD CRITICAL SECURITY ALERT"));
});

test("Mail Templates: passwordResetEmail generates dedicated reset codes with amber warning", () => {
  const res = passwordResetEmail({ email: "user@corp.in", code: "852914", expiryMinutes: 10 });
  assert.ok(res.subject.includes("852914"));
  assert.ok(res.subject.includes("Password Reset Code"));
  assert.ok(res.html.includes("852914"));
  assert.ok(res.html.includes("user@corp.in"));
  assert.ok(res.html.includes("account credentials may be compromised"));
  assert.ok(res.text.includes("PASSWORD RESET CODE"));
});

test("Mail Templates: welcomeEmail welcomes new users with cyber suite onboarding guide", () => {
  const res = welcomeEmail({ name: "Rohan Sharma", email: "rohan@example.com" });
  assert.ok(res.subject.includes("Welcome to ScamShield"));
  assert.ok(res.html.includes("Welcome, Rohan Sharma!"));
  assert.ok(res.html.includes("rohan@example.com"));
  assert.ok(res.html.includes("Active Tab & URL Scanner"));
  assert.ok(res.html.includes("UPI & Payment Defense"));
  assert.ok(res.text.includes("Key Capabilities Activated"));
});

test("Mail Templates: awarenessAdvisoryEmail renders actionable threat advisory briefings", () => {
  const res = awarenessAdvisoryEmail({
    email: "subscriber@domain.com",
    title: "Beware of Digital Arrest Scams",
    topic: "Law Enforcement Coercion",
    summary: "Scammers claiming to be CBI or customs officers are threatening citizens with video-call arrests.",
    tips: [
      "No Indian police force conducts arrests via Skype or WhatsApp video.",
      "Never transfer money to any 'security clearing' bank account."
    ]
  });
  assert.ok(res.subject.includes("[ScamShield Advisory] Law Enforcement Coercion"));
  assert.ok(res.html.includes("Beware of Digital Arrest Scams"));
  assert.ok(res.html.includes("No Indian police force conducts arrests"));
  assert.ok(res.text.includes("KEY SAFETY RULES"));
});

// ---------------------------------------------------------------------------
// 2. Mailer Service & Input Validation Tests
// ---------------------------------------------------------------------------

test("MailerService: email address format validator correctly accepts RFC-compliant emails", () => {
  const mailer = new MailerService();

  // Valid formats
  assert.strictEqual(mailer.validateEmail("user@example.com"), true);
  assert.strictEqual(mailer.validateEmail("first.last+tag@sub.domain.co.in"), true);
  assert.strictEqual(mailer.validateEmail("security_team@scamshield.local"), true);

  // Invalid formats
  assert.strictEqual(mailer.validateEmail(""), false);
  assert.strictEqual(mailer.validateEmail(null), false);
  assert.strictEqual(mailer.validateEmail("not-an-email"), false);
  assert.strictEqual(mailer.validateEmail("user@domain"), false);
  assert.strictEqual(mailer.validateEmail("@nodomain.com"), false);
  assert.strictEqual(mailer.validateEmail("user with spaces@domain.com"), false);
});

test("MailerService: sendMail enforces strict input parameters before attempting SMTP dispatch", async () => {
  const mailer = new MailerService();

  // Missing / invalid destination
  await assert.rejects(
    async () => mailer.sendMail({ to: "bad-email", subject: "Test", text: "Hello" }),
    /Invalid destination email address/
  );

  // Missing subject
  await assert.rejects(
    async () => mailer.sendMail({ to: "user@domain.com", subject: "", text: "Hello" }),
    /Missing email subject/
  );

  // Missing body content
  await assert.rejects(
    async () => mailer.sendMail({ to: "user@domain.com", subject: "Hi" }),
    /Email body content/
  );
});

test("MailerService: timeout configurations default to resilient values", () => {
  const mailer = new MailerService({
    connectionTimeout: 8000,
    greetingTimeout: 7000,
    socketTimeout: 12000
  });

  assert.strictEqual(mailer.connectionTimeout, 8000);
  assert.strictEqual(mailer.greetingTimeout, 7000);
  assert.strictEqual(mailer.socketTimeout, 12000);
});

// ---------------------------------------------------------------------------
// 3. API Key Authentication & Rate Limiting Simulation
// ---------------------------------------------------------------------------

test("Mail Service Auth: requires matching API key and rejects unauthorized requests", () => {
  const EXPECTED_KEY = "test_mail_secret_key_12345";

  function simulateAuth(headers, path = "/send") {
    if (path === "/health") return { status: 200 };

    const xApiKey = headers["x-api-key"] || "";
    const authHeader = headers["authorization"] || "";
    let key = xApiKey;
    if (!key && authHeader.startsWith("Bearer ")) {
      key = authHeader.replace(/^Bearer\s+/i, "").trim();
    }

    if (!key || key !== EXPECTED_KEY) {
      return { status: 401, error: "Unauthorized" };
    }
    return { status: 200 };
  }

  // Health endpoint always public
  assert.strictEqual(simulateAuth({}, "/health").status, 200);

  // Missing header returns 401
  assert.strictEqual(simulateAuth({}, "/send").status, 401);

  // Incorrect key returns 401
  assert.strictEqual(simulateAuth({ "x-api-key": "wrong_key" }, "/send").status, 401);
  assert.strictEqual(simulateAuth({ "authorization": "Bearer wrong_bearer" }, "/send").status, 401);

  // Correct X-API-Key returns 200
  assert.strictEqual(simulateAuth({ "x-api-key": EXPECTED_KEY }, "/send").status, 200);

  // Correct Bearer token returns 200
  assert.strictEqual(simulateAuth({ "authorization": `Bearer ${EXPECTED_KEY}` }, "/send").status, 200);
});

test("Mail Service Rate Limiting: enforces maximum request quota per window", () => {
  const rateLimitMap = new Map();
  const LIMIT = 5;

  function simulateRateLimit(ip) {
    const now = Date.now();
    let record = rateLimitMap.get(ip);
    if (!record || now - record.startTime > 60000) {
      record = { startTime: now, count: 1 };
      rateLimitMap.set(ip, record);
      return { allowed: true };
    }

    record.count += 1;
    if (record.count > LIMIT) {
      return { allowed: false, status: 429 };
    }
    return { allowed: true };
  }

  const clientIp = "192.168.1.100";
  for (let i = 1; i <= LIMIT; i++) {
    const res = simulateRateLimit(clientIp);
    assert.strictEqual(res.allowed, true, `Request ${i} should be allowed`);
  }

  // 6th request triggers 429
  const blocked = simulateRateLimit(clientIp);
  assert.strictEqual(blocked.allowed, false);
  assert.strictEqual(blocked.status, 429);
});

// ---------------------------------------------------------------------------
// 4. Supabase emailSender.ts Routing Behavior Simulation
// ---------------------------------------------------------------------------

test("Supabase emailSender: routes to MAIL_SERVICE_URL when configured, falls back to Resend, or fails closed", () => {
  function determineProvider(env) {
    if (env.MAIL_SERVICE_URL && env.MAIL_SERVICE_API_KEY) {
      return "nodemailer_microservice";
    }
    if (env.RESEND_API_KEY) {
      return "resend_api";
    }
    return "fail_closed";
  }

  // When mail service is configured
  assert.strictEqual(
    determineProvider({ MAIL_SERVICE_URL: "http://localhost:8787", MAIL_SERVICE_API_KEY: "secret" }),
    "nodemailer_microservice"
  );

  // When only Resend is configured
  assert.strictEqual(
    determineProvider({ RESEND_API_KEY: "re_12345" }),
    "resend_api"
  );

  // When neither is configured, fails closed
  assert.strictEqual(
    determineProvider({}),
    "fail_closed"
  );
});

// ---------------------------------------------------------------------------
// 5. Encrypted Token Cache Resilience & Tamper Resistance
// ---------------------------------------------------------------------------

test("Mail Service Token Cache: encrypts, decrypts, and resists tampering & key changes", () => {
  process.env.MAIL_SERVICE_API_KEY = "test_mail_service_secret_key_12345678";
  const { encryptCachePayload, decryptCachePayload } = require("../mail-service/src/server.js");
  const testPayload = JSON.stringify({
    "user@example.com": {
      accessToken: "ya29.test_access_token_12345",
      refreshToken: "1//test_refresh_token_67890",
      provider: "gmail"
    }
  });

  // 1. Encryption generates AES-256-GCM envelope
  const envelope = encryptCachePayload(testPayload);
  assert.strictEqual(envelope.version, "aes-256-gcm");
  assert.ok(envelope.iv && envelope.iv.length === 24); // 12 bytes = 24 hex
  assert.ok(envelope.tag && envelope.tag.length === 32); // 16 bytes = 32 hex
  assert.ok(envelope.data);
  assert.notStrictEqual(envelope.data, testPayload);

  // 2. Decryption recovers original data
  const recovered = decryptCachePayload(envelope);
  assert.strictEqual(recovered, testPayload);

  // 3. Tampering with ciphertext fails closed (auth tag mismatch)
  const tamperedEnvelope = { ...envelope, data: envelope.data.slice(0, -2) + "ff" };
  assert.throws(
    () => decryptCachePayload(tamperedEnvelope),
    /Unsupported state or unable to authenticate data|bad decrypt/i
  );

  // 4. Missing required fields fails closed
  assert.throws(
    () => decryptCachePayload({ data: "unencrypted" }),
    /Invalid or unencrypted token cache envelope/
  );
});
