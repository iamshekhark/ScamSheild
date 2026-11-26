const test = require("node:test");
const assert = require("node:assert/strict");

const bg = require("../extension/background.js");
const ScamEngine = require("../extension/rules.js");
const ScamML = require("../extension/ml_inference.js");

ScamML.registerModel("url", require("../extension/models/url_classifier.json"));
ScamML.registerModel("text_email", require("../extension/models/text_email_classifier.json"));

test("1-4. Legitimate Amazon URLs (homepage, product, login, checkout) pass URL & deterministic checks", () => {
  const urls = [
    "https://www.amazon.in/",
    "https://www.amazon.in/dp/B09G9BL5CP?utm_source=google",
    "https://www.amazon.in/ap/signin?openid.pape.max_auth_age=0",
    "https://www.amazon.in/gp/buy/spc/handlers/display.html"
  ];
  for (const u of urls) {
    const res = ScamEngine.scanUrl(u, { allowExperimental: true });
    assert.equal(res.risk_level, "SAFE", `Expected SAFE URL verdict for ${u}`);
    assert.equal(res.risk_score, 0);
  }
});

test("5-6. Malicious Amazon lookalike and unrelated phishing website remain CRITICAL and blocked", () => {
  const amazonLookalike = ScamEngine.scanUrl("http://amaz0n-security-verify.xyz/login", { allowExperimental: true });
  const mergedLookalike = bg.mergeLayeredResults(amazonLookalike, null, null, "http://amaz0n-security-verify.xyz/login");
  assert.equal(mergedLookalike.risk_level, "CRITICAL");
  assert.equal(mergedLookalike.should_block, true);

  const unrelatedPhish = ScamEngine.scanUrl("http://paytrn-security.xyz/verify", { allowExperimental: true });
  const mergedPhish = bg.mergeLayeredResults(unrelatedPhish, null, null, "http://paytrn-security.xyz/verify");
  assert.equal(mergedPhish.risk_level, "CRITICAL");
  assert.equal(mergedPhish.should_block, true);
});

test("7. Website content with email-like text (with experimental ML) never invokes text_email ML model", () => {
  const amazonDom = "Online Shopping site in India: Shop Online for Mobiles, Books, Watches, Shoes + more. Men's Fashion, Cart, Prime, Sign in, Your Account, Orders.";
  const urlRes = ScamEngine.scanUrl("https://www.amazon.in/", { allowExperimental: true });
  const textRes = ScamEngine.scanText(amazonDom, { allowExperimental: true, context: "webpage" });
  const merged = bg.mergeLayeredResults(urlRes, textRes, { title: "Amazon.in", bodyText: amazonDom }, "https://www.amazon.in/");

  assert.equal(textRes.ml_result, null, "Website context must never invoke text_email ML model");
  assert.notEqual(merged.risk_level, "CRITICAL");
  assert.ok(merged.risk_score < 40);
});

test("8-9. Email requests still invoke text_email ML model and classify phishing vs legitimate emails", () => {
  const phishEmail = ScamEngine.scanEmail(
    "Security <alert@paytrn-security.xyz>",
    "Urgent: Account Suspended",
    "Share your OTP immediately at http://paytrn-security.xyz/verify to avoid suspension.",
    { allowExperimental: true }
  );
  assert.equal(phishEmail.risk_level, "CRITICAL");
  assert.ok(phishEmail.ml_result !== null);

  const legitEmail = ScamEngine.scanEmail(
    "GitHub <notifications@github.com>",
    "[GitHub] Security advisory published",
    "A security advisory has been published for your repository dependency. Review it in your repository settings.",
    { allowExperimental: true }
  );
  assert.equal(legitEmail.risk_level, "SAFE");
  assert.ok(legitEmail.ml_result !== null);
});
