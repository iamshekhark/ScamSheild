// Live Supabase RLS & Cross-User Isolation Test Suite
// Verifies Row Level Security against an active Supabase test project.
// Requires 6 environment variables: TEST_SUPABASE_URL, TEST_SUPABASE_ANON_KEY,
// TEST_USER_A_EMAIL, TEST_USER_A_PASSWORD, TEST_USER_B_EMAIL, TEST_USER_B_PASSWORD.

const test = require("node:test");
const assert = require("node:assert/strict");

let createClient;
try {
  // Use @supabase/supabase-js from dashboard/node_modules if present
  createClient = require("../dashboard/node_modules/@supabase/supabase-js").createClient;
} catch {
  try {
    createClient = require("@supabase/supabase-js").createClient;
  } catch {
    createClient = null;
  }
}

const SUPABASE_URL = process.env.TEST_SUPABASE_URL;
const SUPABASE_ANON_KEY = process.env.TEST_SUPABASE_ANON_KEY;
const USER_A_EMAIL = process.env.TEST_USER_A_EMAIL;
const USER_A_PASSWORD = process.env.TEST_USER_A_PASSWORD;
const USER_B_EMAIL = process.env.TEST_USER_B_EMAIL;
const USER_B_PASSWORD = process.env.TEST_USER_B_PASSWORD;

const isConfigured = Boolean(
  SUPABASE_URL &&
  SUPABASE_ANON_KEY &&
  USER_A_EMAIL &&
  USER_A_PASSWORD &&
  USER_B_EMAIL &&
  USER_B_PASSWORD
);

if (!isConfigured) {
  console.log("\n⚠️  [Phase 2 RLS Test] Environment not configured.");
  console.log("   To run live Supabase RLS tests, set the 6 environment variables documented in:");
  console.log("   docs/PHASE2_SUPABASE_TESTING.md\n");
}

test("Phase 2 RLS: Environment Configuration Check", { skip: !isConfigured }, () => {
  assert.ok(SUPABASE_URL.startsWith("http"), "TEST_SUPABASE_URL must be a valid URL");
  assert.ok(SUPABASE_ANON_KEY.length > 20, "TEST_SUPABASE_ANON_KEY must be provided");
  assert.ok(USER_A_EMAIL && USER_B_EMAIL, "Both test user emails must be provided");
  assert.notEqual(USER_A_EMAIL, USER_B_EMAIL, "User A and User B must be different accounts");
});

test("Phase 2 RLS: Live Cross-User Isolation (User A vs User B)", { skip: !isConfigured }, async () => {
  // 1. Initialize two isolated Supabase clients
  const clientA = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, { auth: { persistSession: false } });
  const clientB = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, { auth: { persistSession: false } });

  // 2. Authenticate User A and User B
  const { data: authA, error: errA } = await clientA.auth.signInWithPassword({
    email: USER_A_EMAIL,
    password: USER_A_PASSWORD
  });
  assert.ifError(errA);
  assert.ok(authA.user?.id, "User A must authenticate successfully");
  const userAId = authA.user.id;

  const { data: authB, error: errB } = await clientB.auth.signInWithPassword({
    email: USER_B_EMAIL,
    password: USER_B_PASSWORD
  });
  assert.ifError(errB);
  assert.ok(authB.user?.id, "User B must authenticate successfully");
  const userBId = authB.user.id;

  assert.notEqual(userAId, userBId, "User IDs must be distinct");

  // -------------------------------------------------------------------------
  // Test A: Scan History Isolation
  // -------------------------------------------------------------------------
  const testScanPayload = {
    user_id: userAId,
    scan_type: "url",
    submitted_content: "https://example-test-isolation.com",
    normalized_domain: "example-test-isolation.com",
    risk_score: 85,
    risk_level: "critical",
    detection_method: "rules"
  };

  const { data: insertedScan, error: insertErr } = await clientA
    .from("scan_history")
    .insert(testScanPayload)
    .select()
    .single();

  assert.ifError(insertErr);
  assert.ok(insertedScan?.id, "User A must be able to insert their own scan");
  const scanId = insertedScan.id;

  try {
    // User B attempts to read User A's scan
    const { data: readByB } = await clientB
      .from("scan_history")
      .select("*")
      .eq("id", scanId);

    assert.equal(readByB.length, 0, "User B MUST NOT be able to read User A's scan");

    // User B attempts to delete User A's scan
    const { error: delErr } = await clientB
      .from("scan_history")
      .delete()
      .eq("id", scanId);

    // Verify User A's scan is still intact
    const { data: verifyA } = await clientA
      .from("scan_history")
      .select("*")
      .eq("id", scanId);

    assert.equal(verifyA.length, 1, "User B MUST NOT be able to delete User A's scan");

    // -------------------------------------------------------------------------
    // Test B: Scan Indicators Ownership Inheritance & Tamper Prevention
    // -------------------------------------------------------------------------
    const { error: indErr } = await clientA
      .from("scam_indicators")
      .insert({
        scan_id: scanId,
        indicator_type: "PHISHING_URL",
        description: "Test isolation indicator",
        severity: "critical"
      });
    assert.ifError(indErr);

    // User B attempts to read User A's indicator
    const { data: indReadByB } = await clientB
      .from("scam_indicators")
      .select("*")
      .eq("scan_id", scanId);

    assert.equal(indReadByB.length, 0, "User B MUST NOT be able to read indicators of User A's scan");

    // Malicious insertion test: User B attempts to attach an indicator to User A's scan_id
    const { data: tamperedInd, error: tamperErr } = await clientB
      .from("scam_indicators")
      .insert({
        scan_id: scanId,
        indicator_type: "TAMPERED_ATTACHMENT",
        description: "Malicious attempt by User B to inject into User A's scan",
        severity: "critical"
      })
      .select();

    // RLS policy checks EXISTS on parent scan with user_id = auth.uid(), so this must fail or return 0 rows
    assert.ok(
      tamperErr || !tamperedInd || tamperedInd.length === 0,
      "User B MUST NOT be able to attach an indicator to User A's scan"
    );

    // -------------------------------------------------------------------------
    // Test C: Payment Scan Isolation
    // -------------------------------------------------------------------------
    const { data: paymentScanA, error: payErr } = await clientA
      .from("payment_scan_results")
      .insert({
        user_id: userAId,
        input_type: "upi_id",
        normalized_payee: "test.isolation@ybl",
        payment_domain: "ybl",
        risk_score: 90,
        risk_level: "critical",
        detection_method: "rules",
        payment_status: "unverified"
      })
      .select()
      .single();

    assert.ifError(payErr);
    assert.ok(paymentScanA?.id);

    // User B attempts to read User A's payment scan
    const { data: payReadByB } = await clientB
      .from("payment_scan_results")
      .select("*")
      .eq("id", paymentScanA.id);

    assert.equal(payReadByB.length, 0, "User B MUST NOT be able to read User A's payment scan");

    // Clean up payment scan
    await clientA.from("payment_scan_results").delete().eq("id", paymentScanA.id);

  } finally {
    // Clean up test scan
    await clientA.from("scan_history").delete().eq("id", scanId);
  }

  // ---------------------------------------------------------------------------
  // Test D: Zero-Access Client Tables (`USING (false)`)
  // ---------------------------------------------------------------------------
  // 1. connected_mailbox_tokens
  const { data: tokensA } = await clientA.from("connected_mailbox_tokens").select("*");
  assert.equal(tokensA.length, 0, "Authenticated clients must be denied from connected_mailbox_tokens");

  // 2. oauth_pending_transactions
  const { data: oauthA } = await clientA.from("oauth_pending_transactions").select("*");
  assert.equal(oauthA.length, 0, "Authenticated clients must be denied from oauth_pending_transactions");

  // 3. email_verification_challenges
  const { data: challengesA } = await clientA.from("email_verification_challenges").select("*");
  assert.equal(challengesA.length, 0, "Authenticated clients must be denied from email_verification_challenges");

  // 4. payment_provider_events
  const { data: eventsA } = await clientA.from("payment_provider_events").select("*");
  assert.equal(eventsA.length, 0, "Authenticated clients must be denied from payment_provider_events");
});
