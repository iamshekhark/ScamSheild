// Automated Security Test: Row Level Security (RLS) Isolation & Cross-Tenant Boundary Verification
// Validates that multi-tenant RLS rules strictly prevent User A and User B from accessing each other's data

const test = require("node:test");
const assert = require("node:assert/strict");

// Simulated PostgreSQL RLS Query Engine
class MockRlsDatabase {
  constructor() {
    this.tables = {
      payment_scan_results: [],
      payment_evidence: [],
      payment_provider_events: [],
      connected_email_accounts: [],
      email_scan_results: [],
      email_verification_challenges: [],
      notification_preferences: [],
      notification_delivery_log: [],
      oauth_pending_transactions: [],
      connected_mailbox_tokens: []
    };
  }

  // Executes a query on behalf of an authenticated context (auth.uid()) or service_role
  forUser(userId) {
    const authUid = userId; // simulates auth.uid()

    return {
      // payment_scan_results: USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id)
      payment_scan_results: {
        select: (filter = {}) => {
          return this.tables.payment_scan_results.filter((row) => {
            // RLS filter: auth.uid() = user_id
            if (row.user_id !== authUid) return false;
            for (const [k, v] of Object.entries(filter)) {
              if (row[k] !== v) return false;
            }
            return true;
          });
        },
        insert: (row) => {
          // WITH CHECK (auth.uid() = user_id)
          if (row.user_id !== authUid) {
            throw new Error("RLS check violation: new row violates row-level security policy for table 'payment_scan_results'");
          }
          this.tables.payment_scan_results.push({ ...row });
          return row;
        },
        delete: (filter = {}) => {
          const initialLen = this.tables.payment_scan_results.length;
          this.tables.payment_scan_results = this.tables.payment_scan_results.filter((row) => {
            // USING (auth.uid() = user_id)
            if (row.user_id !== authUid) return true; // untouched
            for (const [k, v] of Object.entries(filter)) {
              if (row[k] !== v) return true;
            }
            return false; // deleted
          });
          return initialLen - this.tables.payment_scan_results.length;
        }
      },

      // payment_evidence: USING (EXISTS (SELECT 1 FROM payment_scan_results psr WHERE psr.id = payment_evidence.scan_id AND psr.user_id = auth.uid()))
      payment_evidence: {
        select: (filter = {}) => {
          return this.tables.payment_evidence.filter((row) => {
            const parentScan = this.tables.payment_scan_results.find((psr) => psr.id === row.scan_id);
            if (!parentScan || parentScan.user_id !== authUid) return false;
            for (const [k, v] of Object.entries(filter)) {
              if (row[k] !== v) return false;
            }
            return true;
          });
        }
      },

      // payment_provider_events: USING (false)
      payment_provider_events: {
        select: () => {
          // RLS: USING (false)
          return [];
        },
        insert: () => {
          throw new Error("RLS check violation: client insert forbidden on 'payment_provider_events'");
        }
      },

      // connected_email_accounts: USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id)
      connected_email_accounts: {
        select: (filter = {}) => {
          return this.tables.connected_email_accounts.filter((row) => {
            if (row.user_id !== authUid) return false;
            for (const [k, v] of Object.entries(filter)) {
              if (row[k] !== v) return false;
            }
            return true;
          });
        },
        update: (filter = {}, updates = {}) => {
          let updatedCount = 0;
          for (const row of this.tables.connected_email_accounts) {
            if (row.user_id === authUid) {
              let match = true;
              for (const [k, v] of Object.entries(filter)) {
                if (row[k] !== v) { match = false; break; }
              }
              if (match) {
                Object.assign(row, updates);
                updatedCount++;
              }
            }
          }
          return updatedCount;
        }
      },

      // email_scan_results: USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id)
      email_scan_results: {
        select: (filter = {}) => {
          return this.tables.email_scan_results.filter((row) => {
            if (row.user_id !== authUid) return false;
            for (const [k, v] of Object.entries(filter)) {
              if (row[k] !== v) return false;
            }
            return true;
          });
        }
      },

      // email_verification_challenges: USING (false)
      email_verification_challenges: {
        select: () => {
          return [];
        }
      },

      // notification_preferences: USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id)
      notification_preferences: {
        select: (filter = {}) => {
          return this.tables.notification_preferences.filter((row) => {
            if (row.user_id !== authUid) return false;
            for (const [k, v] of Object.entries(filter)) {
              if (row[k] !== v) return false;
            }
            return true;
          });
        },
        update: (filter = {}, updates = {}) => {
          let updatedCount = 0;
          for (const row of this.tables.notification_preferences) {
            if (row.user_id === authUid) {
              let match = true;
              for (const [k, v] of Object.entries(filter)) {
                if (row[k] !== v) { match = false; break; }
              }
              if (match) {
                Object.assign(row, updates);
                updatedCount++;
              }
            }
          }
          return updatedCount;
        }
      },

      // notification_delivery_log: USING (auth.uid() = user_id)
      notification_delivery_log: {
        select: (filter = {}) => {
          return this.tables.notification_delivery_log.filter((row) => {
            if (row.user_id !== authUid) return false;
            for (const [k, v] of Object.entries(filter)) {
              if (row[k] !== v) return false;
            }
            return true;
          });
        }
      },

      // oauth_pending_transactions: USING (false) - Deny direct public/client queries
      oauth_pending_transactions: {
        select: () => []
      },

      // connected_mailbox_tokens: USING (false) - Deny direct public/client queries
      connected_mailbox_tokens: {
        select: () => []
      }
    };
  }

  // Admin / Service Role bypass for backend seed
  asServiceRole() {
    return {
      insert: (table, row) => {
        this.tables[table].push({ ...row });
        return row;
      }
    };
  }
}

// ---------------------------------------------------------------------------
// RLS Isolation Test Cases
// ---------------------------------------------------------------------------

test("RLS Isolation: payment_scan_results isolates User A and User B completely", () => {
  const db = new MockRlsDatabase();
  const service = db.asServiceRole();

  const userA = "11111111-1111-1111-1111-111111111111";
  const userB = "22222222-2222-2222-2222-222222222222";

  // Seed scans for User A and User B
  service.insert("payment_scan_results", {
    id: "scan-a-1",
    user_id: userA,
    input_type: "upi_id",
    normalized_payee: "alice@okaxis",
    risk_score: 0,
    risk_level: "safe"
  });

  service.insert("payment_scan_results", {
    id: "scan-b-1",
    user_id: userB,
    input_type: "upi_id",
    normalized_payee: "bob@paytm",
    risk_score: 90,
    risk_level: "critical"
  });

  // User A can only see User A's scan
  const clientA = db.forUser(userA);
  const userAScans = clientA.payment_scan_results.select();
  assert.strictEqual(userAScans.length, 1);
  assert.strictEqual(userAScans[0].id, "scan-a-1");

  // User B can only see User B's scan
  const clientB = db.forUser(userB);
  const userBScans = clientB.payment_scan_results.select();
  assert.strictEqual(userBScans.length, 1);
  assert.strictEqual(userBScans[0].id, "scan-b-1");

  // User B cannot select User A's scan even by explicit ID
  const crossSelect = clientB.payment_scan_results.select({ id: "scan-a-1" });
  assert.strictEqual(crossSelect.length, 0, "User B must not see User A's scan");

  // User B cannot delete User A's scan
  const deletedCount = clientB.payment_scan_results.delete({ id: "scan-a-1" });
  assert.strictEqual(deletedCount, 0, "User B cannot delete User A's scan");
  assert.strictEqual(clientA.payment_scan_results.select().length, 1, "User A's scan must remain intact");

  // User B cannot insert a scan impersonating User A
  assert.throws(
    () => {
      clientB.payment_scan_results.insert({
        id: "scan-spoofed",
        user_id: userA,
        input_type: "upi_id",
        risk_score: 0,
        risk_level: "safe"
      });
    },
    /violates row-level security policy/,
    "Client cannot insert row for a different user_id"
  );
});

test("RLS Isolation: payment_evidence inherits parent scan ownership", () => {
  const db = new MockRlsDatabase();
  const service = db.asServiceRole();

  const userA = "user-alice-uuid";
  const userB = "user-bob-uuid";

  service.insert("payment_scan_results", { id: "scan-1", user_id: userA });
  service.insert("payment_evidence", {
    id: "ev-1",
    scan_id: "scan-1",
    evidence_type: "BRAND_IMPERSONATION",
    description: "Fake Paytm Support"
  });

  // User A can view evidence for their own scan
  const clientA = db.forUser(userA);
  const evAlice = clientA.payment_evidence.select({ scan_id: "scan-1" });
  assert.strictEqual(evAlice.length, 1);
  assert.strictEqual(evAlice[0].id, "ev-1");

  // User B cannot view evidence for User A's scan
  const clientB = db.forUser(userB);
  const evBob = clientB.payment_evidence.select({ scan_id: "scan-1" });
  assert.strictEqual(evBob.length, 0, "User B must not be able to read User A's evidence");
});

test("RLS Policy: payment_provider_events and email_verification_challenges deny direct client access", () => {
  const db = new MockRlsDatabase();
  const service = db.asServiceRole();

  // Populate sensitive webhook events and OTP challenge hashes via service role
  service.insert("payment_provider_events", {
    id: "event-1",
    provider: "razorpay",
    provider_event_id: "evt_123",
    verified_event_status: "paid"
  });

  service.insert("email_verification_challenges", {
    id: "challenge-1",
    email: "user@example.com",
    code_hash: "hash_secret_value"
  });

  const client = db.forUser("any-user-uuid");

  // Clients receive zero rows on SELECT (USING false)
  assert.strictEqual(client.payment_provider_events.select().length, 0);
  assert.strictEqual(client.email_verification_challenges.select().length, 0);

  // Clients cannot write to payment_provider_events
  assert.throws(
    () => {
      client.payment_provider_events.insert({ id: "evt-fake" });
    },
    /client insert forbidden/
  );
});

test("RLS Isolation: connected_email_accounts and email_scan_results are user-bound", () => {
  const db = new MockRlsDatabase();
  const service = db.asServiceRole();

  const userA = "user-a";
  const userB = "user-b";

  service.insert("connected_email_accounts", {
    id: "acct-a",
    user_id: userA,
    provider: "google",
    email_address: "alice@gmail.com",
    sync_status: "active"
  });

  service.insert("email_scan_results", {
    id: "scan-a",
    user_id: userA,
    sender_address: "attacker@fake.xyz",
    subject_redacted: "Urgent invoice",
    risk_level: "critical"
  });

  const clientB = db.forUser(userB);

  // User B cannot see User A's connected mailbox or scans
  assert.strictEqual(clientB.connected_email_accounts.select().length, 0);
  assert.strictEqual(clientB.email_scan_results.select().length, 0);

  // User B cannot modify User A's mailbox sync status
  const updatedCount = clientB.connected_email_accounts.update({ id: "acct-a" }, { sync_status: "disconnected" });
  assert.strictEqual(updatedCount, 0);

  // User A retains access
  const clientA = db.forUser(userA);
  assert.strictEqual(clientA.connected_email_accounts.select()[0].sync_status, "active");
});

test("RLS Isolation: notification_preferences and delivery_log are isolated per user", () => {
  const db = new MockRlsDatabase();
  const service = db.asServiceRole();

  const userA = "user-alice";
  const userB = "user-bob";

  service.insert("notification_preferences", {
    user_id: userA,
    recipient_email: "alice@corp.com",
    critical_risk_alerts: true
  });

  service.insert("notification_delivery_log", {
    id: "log-1",
    user_id: userA,
    notification_type: "high_risk_alert",
    delivery_status: "delivered"
  });

  const clientB = db.forUser(userB);

  // User B cannot read User A's recipient email or delivery logs
  assert.strictEqual(clientB.notification_preferences.select().length, 0);
  assert.strictEqual(clientB.notification_delivery_log.select().length, 0);

  // User B cannot redirect User A's alerts
  const updated = clientB.notification_preferences.update(
    { user_id: userA },
    { recipient_email: "hacker@evil.com" }
  );
  assert.strictEqual(updated, 0);

  const clientA = db.forUser(userA);
  assert.strictEqual(clientA.notification_preferences.select()[0].recipient_email, "alice@corp.com");
});

test("RLS Isolation: connected_mailbox_tokens and oauth_pending_transactions deny direct client access", () => {
  const db = new MockRlsDatabase();
  const service = db.asServiceRole();
  const userA = "user-alice-security";

  // Service role creates token and pending oauth transaction
  service.insert("connected_mailbox_tokens", {
    id: "token-1",
    account_id: "acct-1",
    user_id: userA,
    encrypted_refresh_token: "enc:v1:a1b2c3d4e5f6:9876543210abcdef",
    token_encryption_version: "v1"
  });

  service.insert("oauth_pending_transactions", {
    id: "tx-1",
    user_id: userA,
    provider: "gmail",
    state: "gmail:1234567890:randomhex",
    code_verifier: "secret_pkce_verifier",
    redirect_uri: "http://localhost:5173/"
  });

  // Client query (even from userA herself) MUST be denied (empty) to prevent frontend token leakage
  const clientA = db.forUser(userA);
  assert.strictEqual(clientA.connected_mailbox_tokens.select().length, 0, "Direct client queries to mailbox tokens must be rejected");
  assert.strictEqual(clientA.oauth_pending_transactions.select().length, 0, "Direct client queries to pending oauth transactions must be rejected");

  // Service role retains access for server-side token refresh and exchange
  assert.strictEqual(db.tables.connected_mailbox_tokens.length, 1);
  assert.strictEqual(db.tables.oauth_pending_transactions.length, 1);
});
