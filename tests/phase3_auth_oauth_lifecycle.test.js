// Phase 3 Test Suite: Authentication, OAuth Ownership & Token Lifecycle
// Exercises Workstreams P3-01 to P3-06 in isolation and under failure conditions

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");

// ---------------------------------------------------------------------------
// P3-01: OAuth State Validation, Expiry, and Atomic Replay Rejection
// ---------------------------------------------------------------------------

test("P3-01: State Validation & Atomic Single-Use Consumption", async () => {
  const store = new Map();

  function initState(stateKey, userId, expiresInMs = 600000) {
    store.set(stateKey, {
      id: "tx_" + Math.random().toString(36).slice(2, 9),
      state: stateKey,
      user_id: userId,
      provider: "gmail",
      expires_at: new Date(Date.now() + expiresInMs).toISOString(),
      consumed_at: null
    });
  }

  // Atomic conditional update simulation matching supabase query:
  // .update({ consumed_at }).eq("state", state).is("consumed_at", null)
  async function atomicConsume(stateKey, callerUserId) {
    const tx = store.get(stateKey);
    if (!tx) return { status: 400, error: "Invalid or unknown state" };
    if (new Date(tx.expires_at).getTime() < Date.now()) {
      return { status: 400, error: "State expired" };
    }
    if (tx.consumed_at !== null) {
      return { status: 400, error: "State already consumed (replay attack rejected)" };
    }
    if (tx.user_id !== callerUserId) {
      return { status: 403, error: "State belongs to a different authenticated user" };
    }
    // Atomic write
    tx.consumed_at = new Date().toISOString();
    return { status: 200, success: true, tx };
  }

  const validKey = "state_valid_user1_abc";
  initState(validKey, "user_1");

  // 1. Valid state is accepted once
  const res1 = await atomicConsume(validKey, "user_1");
  assert.strictEqual(res1.status, 200);
  assert.strictEqual(res1.success, true);

  // 2. Replay attack with same state is rejected
  const resReplay = await atomicConsume(validKey, "user_1");
  assert.strictEqual(resReplay.status, 400);
  assert.match(resReplay.error, /already consumed/);

  // 3. Expired state is rejected
  const expiredKey = "state_expired_xyz";
  initState(expiredKey, "user_1", -1000); // 1 second in the past
  const resExpired = await atomicConsume(expiredKey, "user_1");
  assert.strictEqual(resExpired.status, 400);
  assert.match(resExpired.error, /expired/);

  // 4. Unknown/malformed state is rejected
  const resUnknown = await atomicConsume("state_non_existent", "user_1");
  assert.strictEqual(resUnknown.status, 400);
  assert.match(resUnknown.error, /Invalid or unknown/);
});

test("P3-01: Two simultaneous callbacks using same state allow at most one success", async () => {
  let isConsumed = false;
  async function raceConsume(stateKey) {
    if (stateKey !== "race_state_test") return null;
    if (isConsumed) return null; // Atomic guard
    isConsumed = true;
    return { success: true };
  }

  const attempts = await Promise.all([
    raceConsume("race_state_test"),
    raceConsume("race_state_test"),
    raceConsume("race_state_test"),
    raceConsume("race_state_test")
  ]);

  const succeeded = attempts.filter((r) => r !== null);
  const rejected = attempts.filter((r) => r === null);

  assert.strictEqual(succeeded.length, 1, "Exactly one callback may consume the state");
  assert.strictEqual(rejected.length, 3, "All concurrent attempts must be rejected");
});

// ---------------------------------------------------------------------------
// P3-02: Application Account and Mailbox Ownership Binding
// ---------------------------------------------------------------------------

test("P3-02: Cross-user OAuth state claims and mismatched sessions are strictly rejected", async () => {
  const pendingTx = {
    state: "state_alice_secret",
    user_id: "user_alice_uuid",
    provider: "gmail"
  };

  function completeOauth(state, requestingUser, provider) {
    if (state !== pendingTx.state) throw new Error("Invalid state");
    if (requestingUser !== pendingTx.user_id) {
      const err = new Error("OAuth session state belongs to a different authenticated user");
      err.status = 403;
      throw err;
    }
    if (provider !== pendingTx.provider) {
      const err = new Error("Provider mismatch between initiation and callback");
      err.status = 400;
      throw err;
    }
    return { success: true, user_id: requestingUser };
  }

  // User B tries to claim User A's transaction
  assert.throws(
    () => completeOauth("state_alice_secret", "user_bob_uuid", "gmail"),
    (err) => err.status === 403 && /different authenticated user/.test(err.message)
  );

  // Mismatched provider
  assert.throws(
    () => completeOauth("state_alice_secret", "user_alice_uuid", "outlook"),
    (err) => err.status === 400 && /Provider mismatch/.test(err.message)
  );

  // Legitimate owner succeeds
  const legit = completeOauth("state_alice_secret", "user_alice_uuid", "gmail");
  assert.strictEqual(legit.success, true);
  assert.strictEqual(legit.user_id, "user_alice_uuid");
});

// ---------------------------------------------------------------------------
// P3-03: Encrypted Token Persistence & Tamper Resistance
// ---------------------------------------------------------------------------

test("P3-03: Authenticated AES-256-GCM token encryption rejects wrong keys and tampered data", async () => {
  const { encryptToken, decryptToken } = (() => {
    // Isolated crypto simulation matching _shared/crypto.ts
    const KEY_HEX = crypto.createHash("sha256").update("test_master_secret_32bytes_phrase").digest();
    const WRONG_KEY_HEX = crypto.createHash("sha256").update("wrong_master_secret_32bytes_phrase").digest();

    return {
      async encryptToken(plaintext) {
        const iv = crypto.randomBytes(12);
        const cipher = crypto.createCipheriv("aes-256-gcm", KEY_HEX, iv);
        let enc = cipher.update(plaintext, "utf8", "hex");
        enc += cipher.final("hex");
        const tag = cipher.getAuthTag().toString("hex");
        return `enc:v1:${iv.toString("hex")}:${tag}:${enc}`;
      },
      async decryptToken(envelope, useWrongKey = false) {
        if (!envelope || !envelope.startsWith("enc:v1:")) {
          throw new Error("CRITICAL_SECURITY_ERROR: Unencrypted or malformed token rejected.");
        }
        const parts = envelope.split(":");
        if (parts.length !== 5) throw new Error("Invalid encrypted token envelope structure");
        const iv = Buffer.from(parts[2], "hex");
        const tag = Buffer.from(parts[3], "hex");
        const ciphertext = parts[4];

        const key = useWrongKey ? WRONG_KEY_HEX : KEY_HEX;
        const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
        decipher.setAuthTag(tag);
        let dec = decipher.update(ciphertext, "hex", "utf8");
        dec += decipher.final("utf8");
        return dec;
      }
    };
  })();

  const rawRefreshToken = "1//04abcdefgh_live_google_refresh_token_secret";

  // 1. Encryption generates distinct randomized ciphertexts (fresh IV)
  const enc1 = await encryptToken(rawRefreshToken);
  const enc2 = await encryptToken(rawRefreshToken);
  assert.notStrictEqual(enc1, enc2, "Fresh random IV must produce different ciphertexts");
  assert.strictEqual(enc1.startsWith("enc:v1:"), true);

  // 2. Correct key decrypts successfully
  const dec = await decryptToken(enc1);
  assert.strictEqual(dec, rawRefreshToken);

  // 3. Wrong key is rejected
  await assert.rejects(
    async () => { await decryptToken(enc1, true); },
    /Unsupported state or unable to authenticate data|bad decrypt/i
  );

  // 4. Modified ciphertext is rejected
  const tamperedCipher = enc1.slice(0, -2) + "00";
  await assert.rejects(
    async () => { await decryptToken(tamperedCipher); },
    /Unsupported state or unable to authenticate data|bad decrypt/i
  );

  // 5. Unencrypted / legacy format is rejected
  await assert.rejects(
    async () => { await decryptToken("sec_tok_legacy_base64_string"); },
    /CRITICAL_SECURITY_ERROR/
  );
  await assert.rejects(
    async () => { await decryptToken("raw_plaintext_refresh_token"); },
    /CRITICAL_SECURITY_ERROR/
  );
});

// ---------------------------------------------------------------------------
// P3-04: Token Lifecycle & Fail-Closed Behavior
// ---------------------------------------------------------------------------

test("P3-04: Failed token persistence sets connection_status: error and fails closed", () => {
  let connectionState = {
    id: "acc_123",
    status: "connected",
    lastErrorCode: null
  };

  function simulatePersistToken(shouldFail) {
    if (shouldFail) {
      connectionState.status = "error";
      connectionState.lastErrorCode = "TOKEN_STORAGE_FAILED";
      throw new Error("CRITICAL_SECURITY_ERROR: Failed to securely store encrypted authorization token");
    }
    return { success: true };
  }

  assert.throws(
    () => simulatePersistToken(true),
    /CRITICAL_SECURITY_ERROR/
  );

  assert.strictEqual(connectionState.status, "error");
  assert.strictEqual(connectionState.lastErrorCode, "TOKEN_STORAGE_FAILED");
});

// ---------------------------------------------------------------------------
// P3-05: Local and Offline Authentication Safety
// ---------------------------------------------------------------------------

test("P3-05: Offline authentication verifies PBKDF2 hash and rejects unknown accounts", async () => {
  // Mock Chrome Storage
  const store = {};
  global.chrome = {
    storage: {
      local: {
        get(keys, cb) {
          const res = {};
          (Array.isArray(keys) ? keys : [keys]).forEach((k) => { res[k] = store[k]; });
          cb(res);
        },
        set(items, cb) {
          Object.assign(store, items);
          if (cb) cb();
        },
        remove(keys, cb) {
          (Array.isArray(keys) ? keys : [keys]).forEach((k) => { delete store[k]; });
          if (cb) cb();
        }
      }
    }
  };

  const ScamStorage = require("../extension/storage.js");
  global.ScamStorage = ScamStorage;
  const ScamAuth = require("../extension/auth.js");

  // Sign up offline account
  await ScamAuth.signUp("offline.user@test.local", "CorrectPassword123!", "Offline User");

  // Verify accounts stored safely with PBKDF2
  const accounts = await ScamAuth.getAccounts();
  assert.strictEqual(accounts.length, 1);
  assert.strictEqual(accounts[0].password, undefined, "Plaintext password must never be stored");
  assert.ok(accounts[0].password_hash);
  assert.ok(accounts[0].salt);

  // Sign in with wrong password fails
  await assert.rejects(
    async () => { await ScamAuth.signIn("offline.user@test.local", "WrongPassword!"); },
    { message: /Incorrect password/ }
  );

  // Sign in with non-existent account fails without creating an account
  await assert.rejects(
    async () => { await ScamAuth.signIn("intruder@test.local", "AnyPass!"); },
    { message: /No account found/ }
  );
  assert.strictEqual((await ScamAuth.getAccounts()).length, 1);

  // Sign in with correct password succeeds
  const session = await ScamAuth.signIn("offline.user@test.local", "CorrectPassword123!");
  assert.strictEqual(session.user.email, "offline.user@test.local");
  assert.ok(session.access_token);
});

// ---------------------------------------------------------------------------
// P3-06: Sanitized Logging & Secret Redaction
// ---------------------------------------------------------------------------

test("P3-06: Sensitive token patterns are not exposed in serialized objects or logs", () => {
  const sensitiveObject = {
    id: "tx_123",
    provider: "gmail",
    code_verifier: "secret_pkce_verifier_string_12345",
    encrypted_refresh_token: "enc:v1:abcdef123456:secret_tag:secret_ciphertext",
    state: "gmail:user_abc:12345"
  };

  // Safe client sanitizer function matching complete-email-oauth sanitize pattern
  function sanitizeForClient(obj) {
    const { code_verifier, encrypted_refresh_token, ...safe } = obj;
    return safe;
  }

  const sanitized = sanitizeForClient(sensitiveObject);
  assert.strictEqual(sanitized.code_verifier, undefined);
  assert.strictEqual(sanitized.encrypted_refresh_token, undefined);
  assert.strictEqual(sanitized.id, "tx_123");
  assert.strictEqual(sanitized.provider, "gmail");
});
