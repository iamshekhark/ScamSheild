// Automated Integration Test: Auth, Storage & Privacy Boundaries
const test = require("node:test");
const assert = require("node:assert/strict");

// Mock Chrome Storage for Node testing
global.chrome = {
  storage: {
    local: {
      store: {},
      get(keys, cb) {
        if (typeof keys === "string") keys = [keys];
        const res = {};
        keys.forEach((k) => { res[k] = this.store[k]; });
        cb(res);
      },
      set(items, cb) {
        Object.assign(this.store, items);
        if (cb) cb();
      },
      remove(keys, cb) {
        if (typeof keys === "string") keys = [keys];
        keys.forEach((k) => { delete this.store[k]; });
        if (cb) cb();
      }
    }
  }
};

const ScamStorage = require("../extension/storage.js");
global.ScamStorage = ScamStorage;
const ScamAuth = require("../extension/auth.js");

test("Storage wrapper safely sets and retrieves sessions", async () => {
  await ScamStorage.setSession({ access_token: "mock-jwt-token", user: { id: "u-123", email: "test@scamshield.local" } });
  const s = await ScamStorage.getSession();
  assert.equal(s.access_token, "mock-jwt-token");
  assert.equal(s.user.email, "test@scamshield.local");
});

test("Signout clears session and prevents leakage to next user", async () => {
  await ScamStorage.setSession({ access_token: "secret-token", user: { id: "u-999" } });
  await ScamStorage.set({ lastScan: { scan_id: "scan-secret-data" } });

  await ScamStorage.clearSession();

  assert.equal(await ScamStorage.getSession(), null);
  const remaining = await ScamStorage.get("lastScan");
  assert.equal(remaining.lastScan, undefined);
});

test("User preferences default safely to privacy-first standards", async () => {
  chrome.storage.local.store = {};
  const prefs = await ScamStorage.getPreferences();
  assert.equal(prefs.save_history, true);
  assert.equal(prefs.allow_ai, true);
  assert.equal(prefs.engine_mode, "offline");
});

test("Password reset workflow allows password recovery and login", async () => {
  chrome.storage.local.store = {};
  await ScamAuth.signUp("shekhar@example.com", "oldPassword123", "Shekhar");

  // Test password verification on login rejects wrong password
  await assert.rejects(
    async () => { await ScamAuth.signIn("shekhar@example.com", "wrongPassword"); },
    { message: "Incorrect password. Please verify and try again." }
  );

  // Request password reset
  const req = await ScamAuth.requestPasswordReset("shekhar@example.com");
  assert.ok(req.code);

  // Reset password
  await ScamAuth.resetPassword("shekhar@example.com", "newSecurePassword456");

  // Verify new password logs in successfully
  const session = await ScamAuth.signIn("shekhar@example.com", "newSecurePassword456");
  assert.equal(session.user.email, "shekhar@example.com");
});

test("Local fallback stores PBKDF2 hash, salt, and iterations instead of plaintext password", async () => {
  chrome.storage.local.store = {};
  await ScamAuth.signUp("pbkdf2_user@scamshield.local", "superSecretPass999", "Security Tester");

  const accounts = await ScamAuth.getAccounts();
  assert.equal(accounts.length, 1);
  const acc = accounts[0];

  // Plaintext password field must NOT exist
  assert.equal(acc.password, undefined);
  // PBKDF2 fields must exist
  assert.ok(acc.password_hash, "password_hash must be present");
  assert.ok(acc.salt, "salt must be present");
  assert.equal(acc.iterations, 100000);
  assert.equal(acc.salt.length, 32); // 16 bytes hex = 32 chars
  assert.equal(acc.password_hash.length, 64); // 256 bits = 64 hex chars
});

test("Local sign-in strictly rejects unknown emails without auto-creating accounts", async () => {
  chrome.storage.local.store = {};

  // Sign-in when no accounts exist must reject, never auto-create
  await assert.rejects(
    async () => { await ScamAuth.signIn("nonexistent@scamshield.local", "anyPassword123"); },
    { message: /No account found for this email/ }
  );

  const accounts = await ScamAuth.getAccounts();
  assert.equal(accounts.length, 0, "No account should have been created");

  // Sign-in with wrong password on existing account must reject
  await ScamAuth.signUp("realuser@scamshield.local", "correctPass123", "Real User");
  await assert.rejects(
    async () => { await ScamAuth.signIn("realuser@scamshield.local", "wrongPass456"); },
    { message: /Incorrect password/ }
  );
});
