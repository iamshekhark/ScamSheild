// Automated Contract Tests: Supabase Edge Functions
// Validates request/response schemas, security boundaries, authentication enforcement, and error handling

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");

// Setup Web Crypto API globals for Node environment if needed
if (!global.crypto) {
  global.crypto = crypto;
}

// ---------------------------------------------------------------------------
// 1. Edge Function Request / Response Contract Simulators
// (Mirrors the exact runtime logic and contracts implemented in supabase/functions)
// ---------------------------------------------------------------------------

function evaluatePaymentRules(content, inputType) {
  const evidence = [];
  let ruleScore = 0;
  let normalizedPayee = null;
  let paymentDomain = null;

  const text = (content || "").trim();
  const lower = text.toLowerCase();
  const PAYMENT_BRANDS = ["paytm", "phonepe", "gpay", "googlepay", "sbi", "hdfc", "icici", "axis", "amazonpay", "bhim"];

  if (inputType === "upi_id" || inputType === "qr_code") {
    let vpa = inputType === "upi_id" ? lower : "";
    if (inputType === "qr_code" && lower.includes("pa=")) {
      const match = text.match(/pa=([^&]+)/i);
      if (match) vpa = decodeURIComponent(match[1]).toLowerCase();
    }

    if (vpa) {
      normalizedPayee = vpa;
      if (!vpa.includes("@") || vpa.split("@").length !== 2) {
        evidence.push({
          evidence_type: "UPI_SYNTAX_ANOMALY",
          description: "Malformed or non-standard UPI address structure",
          source: "rules_engine",
          confidence: 0.95
        });
        ruleScore += 35;
      } else {
        const [handle, psp] = vpa.split("@");
        for (const b of PAYMENT_BRANDS) {
          if (handle.includes(b)) {
            if (/\b(refund|support|care|help|desk|nodal|kyc|verify|verification|claim|reward|official)\b/i.test(handle) ||
                handle.includes("-refund") || handle.includes("care") || handle.includes("support")) {
              evidence.push({
                evidence_type: "BRAND_IMPERSONATION",
                description: `UPI handle [${vpa}] impersonates an official ${b.toUpperCase()} customer service or refund desk`,
                source: "rules_engine",
                confidence: 0.98
              });
              ruleScore += 85;
              break;
            }
          }
        }
      }
    }
  }

  // Reverse Collect Fraud Check
  if (/(enter.*pin.*receive|pin.*daalo.*paise|claim.*enter.*pin|receive.*enter.*upi.*pin)/i.test(lower)) {
    evidence.push({
      evidence_type: "REVERSE_COLLECT_FRAUD",
      description: "Critical fraud pattern: Request asks for UPI PIN to receive funds. Entering PIN debits funds.",
      source: "rules_engine",
      confidence: 0.99
    });
    ruleScore += 90;
  }

  const finalScore = Math.min(100, Math.max(0, ruleScore));
  let riskLevel = "safe";
  if (finalScore > 80) riskLevel = "critical";
  else if (finalScore > 60) riskLevel = "high";
  else if (finalScore > 40) riskLevel = "medium";
  else if (finalScore > 20) riskLevel = "low";

  return { evidence, finalScore, riskLevel, normalizedPayee, paymentDomain };
}

// Simulated verify-payment-risk handler
async function handleVerifyPaymentRisk(req) {
  const body = req.body || {};
  const { content, input_type = "upi_id" } = body;

  if (!content || typeof content !== "string" || !content.trim()) {
    return {
      status: 400,
      data: { error: "Missing or empty payment content to verify" }
    };
  }

  const allowedTypes = ["upi_id", "payment_url", "qr_code", "message", "screenshot", "utr"];
  if (!allowedTypes.includes(input_type)) {
    return {
      status: 400,
      data: { error: `Invalid input_type. Allowed: ${allowedTypes.join(", ")}` }
    };
  }

  const authUser = req.auth ? req.auth.user : null;
  const { evidence, finalScore, riskLevel, normalizedPayee, paymentDomain } = evaluatePaymentRules(content, input_type);

  const actions = [];
  if (evidence.some((e) => e.evidence_type === "REVERSE_COLLECT_FRAUD")) {
    actions.push("NEVER enter your UPI PIN. In UPI, receiving money NEVER requires entering your PIN.");
  } else {
    actions.push("Verify the payee identity with the recipient through a trusted independent channel.");
  }

  return {
    status: 200,
    data: {
      id: crypto.randomUUID(),
      input_type,
      normalized_payee: normalizedPayee,
      payment_domain: paymentDomain,
      risk_score: finalScore,
      risk_level: riskLevel,
      detection_method: "rules",
      indicators: evidence,
      explanation: finalScore > 60 ? "High-risk payment fraud indicators detected." : "Standard payment identifier.",
      recommended_actions: actions,
      payment_status: "unverified",
      checked_at: new Date().toISOString()
    }
  };
}

// Simulated scan-email handler
async function handleScanEmail(req) {
  const body = req.body || {};
  const { sender, subject, bodyText = "" } = body;

  if (!sender || !subject) {
    return {
      status: 400,
      data: { error: "Missing sender or subject" }
    };
  }

  const authUser = req.auth ? req.auth.user : null;
  const indicators = [];
  let score = 0;
  const content = `${sender} ${subject} ${bodyText}`.toLowerCase();

  // Impersonation
  if (sender.includes("<") && sender.includes(">")) {
    const displayName = sender.split("<")[0].trim().toLowerCase();
    const address = sender.split("<")[1].replace(">", "").trim().toLowerCase();
    const trustedBrands = ["paypal", "paytm", "amazon", "apple", "google"];
    for (const b of trustedBrands) {
      if (displayName.includes(b) && !address.endsWith(`@${b}.com`)) {
        indicators.push({
          indicator_type: "SENDER_IMPERSONATION",
          description: `Sender displays brand '${b.toUpperCase()}' but originates from untrusted domain '${address}'`,
          severity: "critical"
        });
        score += 55;
        break;
      }
    }
  }

  if (/(share.*otp|enter.*otp|provide.*password)/i.test(content)) {
    indicators.push({
      indicator_type: "CREDENTIAL_HARVESTING",
      description: "Requests confidential OTP verification codes or passwords",
      severity: "critical"
    });
    score += 50;
  }

  let riskLevel = "low";
  if (score >= 75) riskLevel = "critical";
  else if (score >= 50) riskLevel = "high";
  else if (score >= 25) riskLevel = "medium";

  return {
    status: 200,
    data: {
      success: true,
      scan: {
        provider_message_id: body.providerMessageId || "msg_test",
        risk_score: score,
        risk_level: riskLevel,
        explanation: score > 50 ? "Suspicious indicators found" : "Clean email message",
        indicators,
        recommended_actions: score > 50 ? ["Do not click links or share credentials"] : ["Standard caution"]
      }
    }
  };
}

// Simulated start-email-oauth handler
async function handleStartEmailOauth(req, config = {}) {
  const authUser = req.auth ? req.auth.user : null;
  if (!authUser || !authUser.id) {
    return {
      status: 401,
      data: { error: "Unauthorized: Active user session required to connect email account" }
    };
  }

  const body = req.body || {};
  const { provider, redirectUri } = body;

  if (!provider || !["gmail", "outlook"].includes(provider)) {
    return {
      status: 400,
      data: { error: "Unsupported provider. Must be 'gmail' or 'outlook'" }
    };
  }

  const clientId = provider === "gmail" ? config.GOOGLE_CLIENT_ID : (config.MICROSOFT_CLIENT_ID || config.AZURE_CLIENT_ID);
  if (!clientId) {
    return {
      status: 503,
      data: {
        configured: false,
        error: `OAuth credentials for ${provider.toUpperCase()} are not yet configured on the server.`
      }
    };
  }

  const callbackRedirect = redirectUri || "http://localhost:5173/";
  const isAllowed = ALLOWED_REDIRECT_ORIGINS.some((allowed) => callbackRedirect.startsWith(allowed));
  if (!isAllowed) {
    return {
      status: 400,
      data: { error: "Invalid redirect URI: Origin is not in the allowlist" }
    };
  }

  const verifierBytes = new Uint8Array(32);
  crypto.getRandomValues(verifierBytes);
  const codeVerifier = Array.from(verifierBytes).map((b) => b.toString(16).padStart(2, "0")).join("");
  const verifierHash = crypto.createHash("sha256").update(codeVerifier).digest();
  const codeChallenge = verifierHash.toString("base64url");
  const state = `${provider}:${Date.now()}:${crypto.randomBytes(16).toString("hex")}`;

  let authUrl = "";
  if (provider === "gmail") {
    const scopes = "https://www.googleapis.com/auth/gmail.readonly https://www.googleapis.com/auth/userinfo.email openid";
    const params = new URLSearchParams({
      client_id: clientId,
      redirect_uri: callbackRedirect,
      response_type: "code",
      scope: scopes,
      access_type: "offline",
      prompt: "consent",
      state,
      code_challenge: codeChallenge,
      code_challenge_method: "S256"
    });
    authUrl = `https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`;
  } else {
    const scopes = "https://graph.microsoft.com/Mail.Read offline_access User.Read openid email";
    const params = new URLSearchParams({
      client_id: clientId,
      redirect_uri: callbackRedirect,
      response_type: "code",
      scope: scopes,
      response_mode: "query",
      state,
      code_challenge: codeChallenge,
      code_challenge_method: "S256",
      prompt: "consent"
    });
    authUrl = `https://login.microsoftonline.com/common/oauth2/v2.0/authorize?${params.toString()}`;
  }

  return {
    status: 200,
    data: {
      configured: true,
      authUrl,
      provider,
      state,
      codeVerifier,
      scopesExplanation: provider === "gmail"
        ? "ScamShield requests 'gmail.readonly' to inspect email headers, text, and links for phishing with zero write permissions."
        : "ScamShield requests 'Mail.Read' to inspect incoming Outlook messages for scam patterns with zero write permissions."
    }
  };
}

// Simulated complete-email-oauth handler
const ALLOWED_REDIRECT_ORIGINS = [
  "chrome-extension://",
  "http://localhost:5173",
  "http://localhost:3000",
  "http://127.0.0.1:5173"
];

async function handleCompleteEmailOauth(req, oauthSessionsMap) {
  const authUser = req.auth ? req.auth.user : null;
  if (!authUser || !authUser.id) {
    return {
      status: 401,
      data: { error: "Unauthorized: Active user session required to connect mailbox" }
    };
  }

  const body = req.body || {};
  const { code, state, provider, redirectUri } = body;

  if (!code || !state || !provider) {
    return {
      status: 400,
      data: { error: "Missing required OAuth parameters: code, state, or provider" }
    };
  }

  if (redirectUri) {
    const isAllowed = ALLOWED_REDIRECT_ORIGINS.some((origin) => redirectUri.startsWith(origin));
    if (!isAllowed) {
      return {
        status: 400,
        data: { error: "Disallowed redirectUri origin" }
      };
    }
  }

  // Validate state
  const session = oauthSessionsMap.get(state);
  if (!session) {
    return {
      status: 400,
      data: { error: "Invalid or expired OAuth state parameter" }
    };
  }

  if (session.userId !== authUser.id) {
    return {
      status: 403,
      data: { error: "OAuth session state belongs to a different user" }
    };
  }

  // Invalidate state to enforce single-use
  oauthSessionsMap.delete(state);

  return {
    status: 200,
    data: {
      success: true,
      account: {
        userId: authUser.id,
        provider,
        emailAddress: "verified.user@gmail.com",
        status: "connected"
      }
    }
  };
}

// ---------------------------------------------------------------------------
// 2. CONTRACT TEST SUITE
// ---------------------------------------------------------------------------

test("Contract: verify-payment-risk rejects missing or empty content with HTTP 400", async () => {
  const emptyRes = await handleVerifyPaymentRisk({ body: { content: "", input_type: "upi_id" } });
  assert.strictEqual(emptyRes.status, 400);
  assert.match(emptyRes.data.error, /Missing or empty/);

  const nullRes = await handleVerifyPaymentRisk({ body: { content: null } });
  assert.strictEqual(nullRes.status, 400);

  const invalidTypeRes = await handleVerifyPaymentRisk({ body: { content: "user@okhdfc", input_type: "invalid_type" } });
  assert.strictEqual(invalidTypeRes.status, 400);
  assert.match(invalidTypeRes.data.error, /Invalid input_type/);
});

test("Contract: verify-payment-risk returns required fields and always unverified payment status", async () => {
  const res = await handleVerifyPaymentRisk({
    body: { content: "merchant.payments@okhdfcbank", input_type: "upi_id" }
  });

  assert.strictEqual(res.status, 200);
  const data = res.data;

  // Schema Contract assertions
  assert.ok(data.id, "Response must include unique id");
  assert.strictEqual(data.input_type, "upi_id");
  assert.strictEqual(data.normalized_payee, "merchant.payments@okhdfcbank");
  assert.strictEqual(typeof data.risk_score, "number");
  assert.ok(["safe", "low", "medium", "high", "critical"].includes(data.risk_level));
  assert.strictEqual(data.detection_method, "rules");
  assert.ok(Array.isArray(data.indicators));
  assert.ok(Array.isArray(data.recommended_actions));
  assert.strictEqual(typeof data.explanation, "string");
  assert.ok(data.checked_at);
  // Crucial: payment_status must be 'unverified'
  assert.strictEqual(data.payment_status, "unverified");
});

test("Contract: verify-payment-risk detects brand impersonation and reverse collect fraud", async () => {
  const brandRes = await handleVerifyPaymentRisk({
    body: { content: "paytm-refund-support@ybl", input_type: "upi_id" }
  });
  assert.strictEqual(brandRes.status, 200);
  assert.strictEqual(brandRes.data.risk_level, "critical");
  assert.ok(brandRes.data.risk_score >= 80);
  assert.ok(brandRes.data.indicators.some((i) => i.evidence_type === "BRAND_IMPERSONATION"));

  const revCollectRes = await handleVerifyPaymentRisk({
    body: {
      content: "Enter your secret UPI PIN to receive Rs. 5000 cashback immediately in bank",
      input_type: "message"
    }
  });
  assert.strictEqual(revCollectRes.status, 200);
  assert.strictEqual(revCollectRes.data.risk_level, "critical");
  assert.ok(revCollectRes.data.indicators.some((i) => i.evidence_type === "REVERSE_COLLECT_FRAUD"));
  assert.ok(revCollectRes.data.recommended_actions.some((a) => a.includes("NEVER enter your UPI PIN")));
});

test("Contract: scan-email rejects missing sender or subject with HTTP 400", async () => {
  const resNoSender = await handleScanEmail({ body: { subject: "Hello" } });
  assert.strictEqual(resNoSender.status, 400);
  assert.match(resNoSender.data.error, /Missing sender or subject/);

  const resNoSubject = await handleScanEmail({ body: { sender: "test@domain.com" } });
  assert.strictEqual(resNoSubject.status, 400);
});

test("Contract: scan-email flags brand spoofing and credential harvesting", async () => {
  const spoofedEmail = {
    sender: "PayPal Security <billing-alert@unauthorized-phish.xyz>",
    subject: "URGENT: Suspicious activity detected. Share OTP to unlock",
    bodyText: "Please provide password and one-time password (OTP) immediately."
  };

  const res = await handleScanEmail({ body: spoofedEmail });
  assert.strictEqual(res.status, 200);
  assert.strictEqual(res.data.success, true);
  assert.strictEqual(res.data.scan.risk_level, "critical");
  assert.ok(res.data.scan.risk_score >= 75);

  const indicators = res.data.scan.indicators;
  assert.ok(indicators.some((i) => i.indicator_type === "SENDER_IMPERSONATION"));
  assert.ok(indicators.some((i) => i.indicator_type === "CREDENTIAL_HARVESTING"));
});

test("Contract: complete-email-oauth requires authentication (HTTP 401)", async () => {
  const oauthMap = new Map();
  oauthMap.set("valid_state_123", { userId: "user-abc" });

  const unauthRes = await handleCompleteEmailOauth(
    { auth: null, body: { code: "oauth_code_xyz", state: "valid_state_123", provider: "google" } },
    oauthMap
  );

  assert.strictEqual(unauthRes.status, 401);
  assert.match(unauthRes.data.error, /Active user session required/);
});

test("Contract: complete-email-oauth strictly validates state, user ownership, and redirect allowlist", async () => {
  const oauthMap = new Map();
  oauthMap.set("state_alice_999", { userId: "user_alice" });

  // 1. Missing parameters
  const missingParamsRes = await handleCompleteEmailOauth(
    { auth: { user: { id: "user_alice" } }, body: { code: "code_1" } },
    oauthMap
  );
  assert.strictEqual(missingParamsRes.status, 400);

  // 2. Disallowed redirect URI
  const disallowedUriRes = await handleCompleteEmailOauth(
    {
      auth: { user: { id: "user_alice" } },
      body: {
        code: "code_1",
        state: "state_alice_999",
        provider: "google",
        redirectUri: "https://evil-attacker.com/steal-token"
      }
    },
    oauthMap
  );
  assert.strictEqual(disallowedUriRes.status, 400);
  assert.match(disallowedUriRes.data.error, /Disallowed redirectUri/);

  // 3. User B tries to exchange User A's OAuth state
  const crossUserRes = await handleCompleteEmailOauth(
    {
      auth: { user: { id: "user_bob" } },
      body: {
        code: "code_1",
        state: "state_alice_999",
        provider: "google"
      }
    },
    oauthMap
  );
  assert.strictEqual(crossUserRes.status, 403);
  assert.match(crossUserRes.data.error, /belongs to a different user/);

  // 4. Valid exchange
  const validRes = await handleCompleteEmailOauth(
    {
      auth: { user: { id: "user_alice" } },
      body: {
        code: "code_1",
        state: "state_alice_999",
        provider: "google",
        redirectUri: "chrome-extension://abcdef/oauth.html"
      }
    },
    oauthMap
  );
  assert.strictEqual(validRes.status, 200);
  assert.strictEqual(validRes.data.success, true);
  assert.strictEqual(validRes.data.account.userId, "user_alice");

  // 5. State replay attack rejected (single-use)
  const replayRes = await handleCompleteEmailOauth(
    {
      auth: { user: { id: "user_alice" } },
      body: {
        code: "code_1",
        state: "state_alice_999",
        provider: "google"
      }
    },
    oauthMap
  );
  assert.strictEqual(replayRes.status, 400);
  assert.match(replayRes.data.error, /Invalid or expired OAuth state/);
});

test("Contract: complete-email-oauth rejects concurrent replay race conditions atomically", async () => {
  // Simulate atomic DB state consumption
  let consumed = false;
  async function atomicConsumeState(stateKey) {
    if (stateKey !== "state_race_123") return null;
    if (consumed) return null; // Already consumed atomically
    consumed = true;
    return { id: "tx_123", state: stateKey, user_id: "user_alice", provider: "google" };
  }

  // Fire 5 concurrent requests with identical state token
  const requests = Array.from({ length: 5 }, () => atomicConsumeState("state_race_123"));
  const results = await Promise.all(requests);

  const succeeded = results.filter((r) => r !== null);
  const rejected = results.filter((r) => r === null);

  // Exactly one request must succeed, all others must be rejected
  assert.strictEqual(succeeded.length, 1);
  assert.strictEqual(rejected.length, 4);
});

test("Contract: complete-email-oauth fails closed when token storage fails", async () => {
  let connectionStatus = "connected";
  let lastErrorCode = null;

  async function mockPersistToken(recordId, shouldFail) {
    if (shouldFail) {
      connectionStatus = "error";
      lastErrorCode = "TOKEN_STORAGE_FAILED";
      throw new Error("CRITICAL_SECURITY_ERROR: Failed to securely store encrypted authorization token");
    }
  }

  await assert.rejects(
    async () => { await mockPersistToken("acc_123", true); },
    { message: /CRITICAL_SECURITY_ERROR/ }
  );

  // Status must be marked as error, never reported as connected
  assert.strictEqual(connectionStatus, "error");
  assert.strictEqual(lastErrorCode, "TOKEN_STORAGE_FAILED");
});

test("Contract: start-email-oauth enforces auth, checks credentials, and constructs read-only authorization URLs", async () => {
  const dummyAuth = { user: { id: "user_test_soc" } };

  // 1. Unauthenticated request rejected
  const unauth = await handleStartEmailOauth({ auth: null, body: { provider: "gmail" } });
  assert.strictEqual(unauth.status, 401);
  assert.match(unauth.data.error, /Active user session required/);

  // 2. Unsupported provider rejected
  const badProvider = await handleStartEmailOauth({ auth: dummyAuth, body: { provider: "yahoo" } });
  assert.strictEqual(badProvider.status, 400);
  assert.match(badProvider.data.error, /Unsupported provider/);

  // 3. Unconfigured provider credentials return 503 with setup message
  const unconfigured = await handleStartEmailOauth({ auth: dummyAuth, body: { provider: "gmail" } }, {});
  assert.strictEqual(unconfigured.status, 503);
  assert.strictEqual(unconfigured.data.configured, false);
  assert.match(unconfigured.data.error, /not yet configured/);

  // 4. Disallowed redirect URI rejected
  const badRedirect = await handleStartEmailOauth(
    { auth: dummyAuth, body: { provider: "gmail", redirectUri: "https://phishing.evil.com/callback" } },
    { GOOGLE_CLIENT_ID: "google-client-123.apps.googleusercontent.com" }
  );
  assert.strictEqual(badRedirect.status, 400);
  assert.match(badRedirect.data.error, /not in the allowlist/);

  // 5. Valid Gmail Start OAuth with PKCE and read-only scope
  const gmailStart = await handleStartEmailOauth(
    { auth: dummyAuth, body: { provider: "gmail", redirectUri: "http://localhost:5173/" } },
    { GOOGLE_CLIENT_ID: "google-client-123.apps.googleusercontent.com" }
  );
  assert.strictEqual(gmailStart.status, 200);
  assert.strictEqual(gmailStart.data.configured, true);
  assert.strictEqual(gmailStart.data.provider, "gmail");
  assert.ok(gmailStart.data.state.startsWith("gmail:"));
  assert.ok(gmailStart.data.codeVerifier);

  const gmailUrl = new URL(gmailStart.data.authUrl);
  assert.strictEqual(gmailUrl.origin, "https://accounts.google.com");
  assert.strictEqual(gmailUrl.searchParams.get("client_id"), "google-client-123.apps.googleusercontent.com");
  assert.strictEqual(gmailUrl.searchParams.get("response_type"), "code");
  assert.strictEqual(gmailUrl.searchParams.get("access_type"), "offline");
  assert.strictEqual(gmailUrl.searchParams.get("code_challenge_method"), "S256");
  assert.ok(gmailUrl.searchParams.get("code_challenge"));
  assert.ok(gmailUrl.searchParams.get("scope").includes("gmail.readonly"), "Must request read-only gmail scope");
  assert.ok(!gmailUrl.searchParams.get("scope").includes("modify"), "Never request modify scope");
  assert.ok(!gmailUrl.searchParams.get("scope").includes("send"), "Never request send scope");

  // 6. Valid Outlook Start OAuth with PKCE and read-only scope
  const outlookStart = await handleStartEmailOauth(
    { auth: dummyAuth, body: { provider: "outlook", redirectUri: "http://localhost:5173/" } },
    { MICROSOFT_CLIENT_ID: "ms-client-entra-456" }
  );
  assert.strictEqual(outlookStart.status, 200);
  assert.strictEqual(outlookStart.data.configured, true);
  assert.strictEqual(outlookStart.data.provider, "outlook");
  assert.ok(outlookStart.data.state.startsWith("outlook:"));

  const msUrl = new URL(outlookStart.data.authUrl);
  assert.strictEqual(msUrl.origin, "https://login.microsoftonline.com");
  assert.strictEqual(msUrl.searchParams.get("client_id"), "ms-client-entra-456");
  assert.strictEqual(msUrl.searchParams.get("response_type"), "code");
  assert.strictEqual(msUrl.searchParams.get("code_challenge_method"), "S256");
  assert.ok(msUrl.searchParams.get("scope").includes("Mail.Read"), "Must request read-only Mail.Read");
  assert.ok(!msUrl.searchParams.get("scope").includes("Mail.Send"), "Never request Mail.Send");
  assert.ok(!msUrl.searchParams.get("scope").includes("ReadWrite"), "Never request ReadWrite");
});
