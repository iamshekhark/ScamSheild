// Unit Test: AES-256-GCM Refresh Token Encryption and Decryption
const test = require("node:test");
const assert = require("node:assert/strict");
const { encryptToken, decryptToken } = require("./helpers/crypto_helper");

test("AES-256-GCM encrypts tokens into randomized non-recoverable ciphertexts with distinct IVs", async () => {
  const rawToken = "ya29.a0AfH6SMCL_sample_gmail_refresh_token_123456789";

  const enc1 = await encryptToken(rawToken);
  const enc2 = await encryptToken(rawToken);

  // Must not equal plaintext or base64
  assert.notEqual(enc1, rawToken);
  assert.equal(enc1.startsWith("enc:v1:"), true);

  // Two encryptions of same token must yield different ciphertexts (random IV)
  assert.notEqual(enc1, enc2);

  // Decryption yields original token
  const dec1 = await decryptToken(enc1);
  const dec2 = await decryptToken(enc2);
  assert.equal(dec1, rawToken);
  assert.equal(dec2, rawToken);
});

test("Token decryption strictly rejects unencrypted tokens and malformed envelopes", async () => {
  const legacyToken = "ya29.sample_legacy_refresh_token";
  const legacyStored = "sec_tok_" + Buffer.from(legacyToken).toString("base64");

  // Legacy Base64 and unencrypted strings must be rejected
  await assert.rejects(
    async () => { await decryptToken(legacyStored); },
    { message: /CRITICAL_SECURITY_ERROR/ }
  );

  await assert.rejects(
    async () => { await decryptToken("raw_plaintext_refresh_token_12345"); },
    { message: /CRITICAL_SECURITY_ERROR/ }
  );
});

module.exports = {
  encryptToken,
  decryptToken
};
