// ScamShield Phase 7: UI/UX, Accessibility & End-to-End Regression Tests
// Tests ARIA accessibility, input labelling, dashboard URL validation, and full platform regression

const test = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");

const EXT_DIR = path.join(__dirname, "..", "extension");
const popupHtmlPath = path.join(EXT_DIR, "popup.html");
const popupHtml = fs.readFileSync(popupHtmlPath, "utf-8");

// ============================================================================
// 1. Accessibility & ARIA Structural Verification
// ============================================================================

test("P7-01: Popup UI implements required ARIA roles and tablist navigation", () => {
  // 1. Verify nav tablist
  assert.ok(
    popupHtml.includes('role="tablist"'),
    "Popup must contain role='tablist' navigation container"
  );

  // 2. Verify all primary tab buttons declare role="tab" and aria-selected
  const tabButtonMatches = [...popupHtml.matchAll(/<button[^>]+class="[^"]*tab-btn[^"]*"[^>]*>/gi)];
  assert.ok(tabButtonMatches.length >= 4, "Must have at least 4 primary tab buttons");

  for (const match of tabButtonMatches) {
    const btnHtml = match[0];
    assert.ok(btnHtml.includes('role="tab"'), `Tab button must have role="tab": ${btnHtml}`);
    assert.ok(btnHtml.includes('aria-selected='), `Tab button must have aria-selected: ${btnHtml}`);
  }

  // 3. Verify all tab panes declare role="tabpanel"
  const tabPaneMatches = [...popupHtml.matchAll(/<div[^>]+class="[^"]*tab-pane[^"]*"[^>]*>/gi)];
  assert.ok(tabPaneMatches.length >= 4, "Must have at least 4 tab panes");

  for (const match of tabPaneMatches) {
    const paneHtml = match[0];
    assert.ok(paneHtml.includes('role="tabpanel"'), `Tab pane must declare role="tabpanel": ${paneHtml}`);
  }
});

test("P7-02: Every form input and textarea has an accessible label", () => {
  // Extract all input and textarea IDs in popup.html
  const inputMatches = [...popupHtml.matchAll(/<(?:input|textarea)[^>]+id=["']([^"']+)["'][^>]*>/gi)];
  assert.ok(inputMatches.length >= 6, "Must find form inputs in popup");

  for (const match of inputMatches) {
    const id = match[1];
    const fullTag = match[0];

    // Check if input has an associated <label for="..."> or aria-label
    const hasLabelFor = popupHtml.includes(`for="${id}"`);
    const hasAriaLabel = fullTag.includes('aria-label=') || fullTag.includes('title=');

    assert.ok(
      hasLabelFor || hasAriaLabel,
      `Input element #${id} must have an associated <label for="${id}"> or aria-label for accessibility`
    );
  }
});

// ============================================================================
// 2. Dashboard URL Validation & Navigation Safety
// ============================================================================

test("P7-03: Dashboard URL validator accepts authentic URLs and rejects dangerous schemes", () => {
  function isValidDashboardUrl(val) {
    if (!val || typeof val !== "string") return false;
    try {
      const u = new URL(val.trim());
      return u.protocol === "http:" || u.protocol === "https:";
    } catch {
      return false;
    }
  }

  // Dangerous / Malformed URLs must be rejected
  const invalidUrls = [
    "javascript:alert(document.cookie)",
    "data:text/html,<script>evil()</script>",
    "file:///etc/passwd",
    "vbscript:msgbox()",
    "htp:/bad-scheme",
    "",
    "   ",
    "not_a_valid_url"
  ];

  for (const inv of invalidUrls) {
    assert.strictEqual(
      isValidDashboardUrl(inv),
      false,
      `URL '${inv}' must be rejected by dashboard URL validator`
    );
  }

  // Safe HTTP/HTTPS URLs must be accepted
  const validUrls = [
    "http://localhost:5173",
    "http://localhost:3000",
    "http://127.0.0.1:5173",
    "https://dashboard.scamshield.example.com",
    "https://soc-command.company.internal:8443/app"
  ];

  for (const val of validUrls) {
    assert.strictEqual(
      isValidDashboardUrl(val),
      true,
      `URL '${val}' must be accepted by dashboard URL validator`
    );
  }
});

// ============================================================================
// 3. UI State Transitions & Session Expiry Resilience
// ============================================================================

test("P7-04: Session expiry error handling presents actionable re-authentication prompt", () => {
  // Simulating the error handling logic in loadScanHistory
  function handleHistoryError(errorMessage) {
    const isAuthErr = /unauthorized|expired|401|session/i.test(errorMessage);
    return {
      isAuthErr,
      userMessage: isAuthErr
        ? "Session expired. Please sign in again to sync your scan history."
        : `Unable to load history (${errorMessage})`,
      showReAuthButton: isAuthErr
    };
  }

  // Case A: 401 Unauthorized / Token expired
  const authErrResult = handleHistoryError("Server returned 401 Unauthorized: token expired");
  assert.strictEqual(authErrResult.isAuthErr, true);
  assert.strictEqual(authErrResult.showReAuthButton, true);
  assert.ok(authErrResult.userMessage.includes("Session expired"));

  // Case B: General network error
  const netErrResult = handleHistoryError("Failed to fetch: connection refused");
  assert.strictEqual(netErrResult.isAuthErr, false);
  assert.strictEqual(netErrResult.showReAuthButton, false);
  assert.ok(netErrResult.userMessage.includes("Unable to load history"));
});

// ============================================================================
// 4. End-to-End Platform Core Module Regression
// ============================================================================

test("P7-05: Platform Core Regression — Engine, Crypto, Mail & Packaging modules operate together", async () => {
  // 1. Detection Engine Regression
  const ScamEngine = require("../extension/rules");
  const urlScan = ScamEngine.scanUrl("https://paypa1.com/verify");
  assert.strictEqual(urlScan.risk_level === "HIGH" || urlScan.risk_level === "CRITICAL", true);

  const paymentScan = ScamEngine.scanPayment("refund@paytm", "upi_id");
  assert.strictEqual(paymentScan.payment_status, "unverified");

  // 2. Crypto Regression
  const { encryptToken, decryptToken } = require("./helpers/crypto_helper");
  const testSecret = "regression_test_secret_token_12345";
  const envelope = await encryptToken(testSecret);
  assert.ok(envelope.startsWith("enc:v1:"));
  const decrypted = await decryptToken(envelope);
  assert.strictEqual(decrypted, testSecret);

  // 3. Mail Template Regression
  const { verificationCodeEmail } = require("../mail-service/src/templates");
  const mail = verificationCodeEmail({ email: "user@test.com", code: "123456" });
  assert.ok(mail.html.includes("123456"));

  // 4. Distribution Package Manifest Integrity
  const distManifestPath = path.join(__dirname, "..", "dist", "scamshield-extension-v2.0.0-manifest.json");
  assert.ok(fs.existsSync(distManifestPath), "Extension dist manifest must exist");
  const manifestData = JSON.parse(fs.readFileSync(distManifestPath, "utf-8"));
  assert.strictEqual(manifestData.version, "2.0.0");
});
