# Phase 2 — Supabase Row Level Security & Account Isolation Testing Guide

This guide details the procedure for executing live RLS security validation against a dedicated test Supabase project.

---

## 1. Prerequisites

1. A dedicated Supabase test project (do NOT use production).
2. The database migrations applied in order:
   - `supabase/migrations/20261018000000_init_scamshield_schema.sql`
   - `supabase/migrations/20261018010000_email_integration_alerts.sql`
   - `supabase/migrations/20261019000000_payment_scam_verification.sql`
   - `supabase/migrations/20261019010000_secure_oauth_flow.sql`
3. Two confirmed test users created in the Supabase project:
   - **User A** (e.g., `user_a@scamshield-test.local`)
   - **User B** (e.g., `user_b@scamshield-test.local`)

---

## 2. Environment Configuration

Set the following six environment variables before running the test suite:

```bash
# Supabase Project Endpoints
export TEST_SUPABASE_URL="https://<your-project-ref>.supabase.co"
export TEST_SUPABASE_ANON_KEY="<your-anon-key>"

# User A Test Credentials
export TEST_USER_A_EMAIL="user_a@scamshield-test.local"
export TEST_USER_A_PASSWORD="<user-a-password>"

# User B Test Credentials
export TEST_USER_B_EMAIL="user_b@scamshield-test.local"
export TEST_USER_B_PASSWORD="<user-b-password>"
```

*(On Windows PowerShell, use `$env:TEST_SUPABASE_URL="..."`)*

---

## 3. Running the Test Suite

Execute the live test runner:

```bash
npm run test:phase2:supabase
```

---

## 4. Test Scenarios Executed

The runner signs in both test users and executes the following assertions:

1. **Scan History Isolation:**
   - User A inserts a private scan record.
   - User B attempts `SELECT`, `UPDATE`, and `DELETE` on User A's scan record.
   - Assert: User B receives empty result (`data: []`) or 0 rows modified. User B cannot delete User A's scan.

2. **Indicators Ownership Inheritance:**
   - User A attaches scan indicators to their scan.
   - User B attempts `SELECT` on User A's indicators.
   - Assert: User B cannot see User A's indicator details.

3. **Payment Scam & Evidence Isolation:**
   - User A inserts a `payment_scan_results` row.
   - User B attempts to read or modify User A's payment scan.
   - Assert: User B is isolated; cross-tenant access is blocked.

4. **Zero-Access Tables (`USING (false)`):**
   - Both authenticated users attempt direct queries against:
     - `connected_mailbox_tokens`
     - `oauth_pending_transactions`
     - `email_verification_challenges`
     - `payment_provider_events`
   - Assert: Direct client `SELECT` / `INSERT` / `UPDATE` queries are denied (`403` or empty set).

5. **Guest Scans vs User Scans:**
   - Evaluates whether unauthenticated / guest scans (`user_id IS NULL`) are isolated or intentionally public.
