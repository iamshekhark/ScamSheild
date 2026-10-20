# ScamShield Known Issues Tracking Log

This file tracks all identified defects, architectural concerns, and security findings across the ScamShield platform.

---

## Active & Under-Remediation Issues

*(None currently active. All Phase 1 through Phase 8 items resolved and verified.)*

---

## Resolved Issues & Audit Remediations

### [UI-01] UI/UX Polish, Accessibility, Responsive Tables & Truthful Empty States
* **Severity:** Medium / User Experience & Accessibility
* **Status:** Resolved & Merged
* **Trigger:** Integration of `scamshield-ui-ux-fixed-source`.
* **Resolution:** 
  1. Updated `extension/popup.css`: Added compact-width handling, enhanced typography, focus rings, larger touch targets, reduced motion support (`prefers-reduced-motion`), and adaptive light-theme support while preserving the default dark command center styling.
  2. Updated `dashboard/src/styles.css`: Added light-theme CSS variable support, responsive horizontally scrollable data tables, responsive header/cards, and reduced motion queries.
  3. Updated `dashboard/src/components/Overview.tsx`: Removed fabricated `+12.4%` trends and placeholder flags. Replaced with truthful evidence-based metrics and clear empty states ("An empty history does not indicate that traffic is safe").
  4. Verified dashboard production build (`vite build` in 1.59s) and full test suite (103 passed, 0 failures, 0 cancellations).

### [AUDIT-C1] Sanitization of Distributable Release Packages & Workspace Hygiene
* **Severity:** High / Security Hygiene
* **Status:** Resolved & Verified
* **Trigger:** Audit of user-uploaded outer zip `scamshield-extension(7).zip` identified uncommitted `.env`, `.token_cache.json`, and `node_modules`.
* **Resolution:** 
  1. Updated root `.gitignore`, `mail-service/.gitignore`, and `dashboard/.gitignore` to strictly ignore all `.env*` (except `.env.example`), `node_modules`, and `**/.token_cache.json`.
  2. Deleted temporary runtime `.token_cache.json` from workspace.
  3. Hardened `scripts/package-source-release.js` with regex/substring exclusion for all token cache variants.
  4. Executed `npm run package:source` and binary-scanned `dist/scamshield-source-release-v2.0.0.zip` (106 files, 0 secrets, 0 `.env`, 0 `token_cache`, 0 `node_modules`).
  5. Advised human operator to rotate any test credentials present in `scamshield-extension(7).zip`.

### [AUDIT-C2] Dashboard Production Build & Platform-Agnostic Dependency Management
* **Severity:** High / Build Reproducibility
* **Status:** Resolved & Verified
* **Trigger:** Audit environment failed to build dashboard from pre-bundled `node_modules` due to missing `@rollup/rollup-linux-x64-gnu`.
* **Resolution:** 
  1. Verified `dashboard/package.json` optionalDependencies has `"@rollup/rollup-linux-x64-gnu": "^4.64.9"` matching Rollup version in `dashboard/package-lock.json`.
  2. Confirmed clean CI installation (`.github/workflows/ci.yml`) runs `npm --prefix dashboard ci` prior to `npm run build:dashboard` on clean multi-OS runners.
  3. Confirmed source release zip completely omits `node_modules/`, preventing cross-OS binary contamination.
  4. Verified local `npm run build:dashboard` passes cleanly (`vite v5.4.21 building for production... ✓ built in 1.57s`).

### [AUDIT-C3] Phase 4 SMTP Verification Test Determinism
* **Severity:** Medium / Test Reliability
* **Status:** Resolved & Verified
* **Trigger:** `tests/phase4_email_integrations.test.js` failed when running in an audit environment where live SMTP credentials or egress were absent.
* **Resolution:** 
  1. Separated SMTP tests into two distinct contracts:
     - `P4-04a`: Deterministic unit/contract test verifying configuration parsing, safe status reporting, and fail-closed error handling without requiring live SMTP egress.
     - `P4-04b`: Dedicated live SMTP network test that runs when `process.env.LIVE_SMTP_TEST === "true"` and cleanly skips otherwise via `{ skip: !isLiveSmtpConfigured }`.
  2. Enforced fail-closed invariant: failure never marks email as verified or reports a successful delivery.

### [AUDIT-C4] Phase 7 Regression Test Nested Import Bug
* **Severity:** Medium / Test Runner Failure
* **Status:** Resolved & Verified
* **Trigger:** `tests/phase7_ui_regression.test.js` imported `tests/token_encryption.test.js` for `encryptToken`/`decryptToken`, causing `node:test` to register nested subtests under `P7-05` which were cancelled.
* **Resolution:** 
  1. Extracted `encryptToken` and `decryptToken` into dedicated standalone helper `tests/helpers/crypto_helper.js` containing no `test(...)` blocks.
  2. Updated `tests/token_encryption.test.js` and `tests/phase7_ui_regression.test.js` to import from `./helpers/crypto_helper`.
  3. Running `npm test` now yields 0 cancelled tests and 100% clean passes.

### [AUDIT-C5] Mail-Service Package Test Self-Containment
* **Severity:** Medium / Test Isolation
* **Status:** Resolved & Verified
* **Trigger:** `mail-service/test/mail_service.test.js` failed in clean checkouts lacking a `.env` file because `TOKEN_ENCRYPTION_KEY` was missing for token cache encryption.
* **Resolution:** 
  1. Updated `mail-service/test/mail_service.test.js` to provide test-only mock configuration (`TOKEN_ENCRYPTION_KEY`, `MAIL_SERVICE_API_KEY`) and use an isolated temp file for `TOKEN_CACHE_FILE`.
  2. Added test explicitly asserting that missing encryption keys throw `CRITICAL_SECURITY_ERROR`, verifying fail-closed security.
  3. Added teardown cleaning up temporary files and restoring original environment.
  4. All 4 tests in `npm --prefix mail-service test` pass cleanly.

---

### [P8-01] Phase 8 Final Independent Release Audit
* **Severity:** Phase Gate / Release Milestone
* **Status:** Resolved & Verified
* **Resolution:** Completed remediations for all findings C1–C5 identified in Phase 8 static audit. All 106 automated tests pass (103 pass, 0 fail, 3 cleanly skipped live integration checks). Live Supabase RLS isolation verified against `https://twrdubnndhgbqlaeeabl.supabase.co`. Clean release artifacts produced in `dist/`.

### [P5-01] Rollup Native Module Platform Dependency & Reproducible Builds
* **Severity:** Medium
* **Status:** Resolved & Verified
* **Resolution:** Preserved lockfile integrity (`dashboard/package-lock.json`) with version alignment (`4.64.9`) between `rollup` and the Linux native binary declared under `optionalDependencies`. Added multi-OS GitHub Actions workflow (`.github/workflows/ci.yml`).

### [SEC-08] Atomic Verification Challenge Consumption
* **Severity:** High
* **Status:** Resolved & Verified
* **Resolution:** In `supabase/functions/verify-email-code/index.ts`, challenge consumption was made atomic using `.update({ consumed_at }).eq("id", challenge.id).is("consumed_at", null)`. Concurrent reuse of the same code is strictly rejected. Verified via `tests/phase4_email_integrations.test.js`.

### [SEC-09] Safe Handling of Email Dispatch Failures
* **Severity:** Medium
* **Status:** Resolved & Verified
* **Resolution:** In `supabase/functions/request-email-verification/index.ts`, if `sendTransactionalEmail` fails, the newly inserted challenge is invalidated immediately, and an explicit HTTP 502 error is returned.

### [P4-01] Phase 4 Mail Service & Token Lifecycle Hardening
* **Severity:** Medium
* **Status:** Resolved & Verified
* **Resolution:** Implemented `/oauth/refresh-token`, `/oauth/disconnect`, rotated refresh token persistence, bounded retry on token expiration in `/oauth/sync-mailbox`, and live SMTP connection verification.

### [P2-01] Phase 2 Live Supabase Verification Gate
* **Severity:** High (Phase Gate)
* **Status:** Resolved & Verified against Live Database
* **Resolution:** Executed `tests/supabase_phase2_live.test.js` against live project `https://twrdubnndhgbqlaeeabl.supabase.co` with two confirmed test accounts (`user.alpha.test@gmail.com` and `user.beta.test@gmail.com`). 
* **Verified Evidence:**
  - `scan_history`: User B cannot read or delete User A's scan (0 rows returned).
  - `scam_indicators`: User B cannot read User A's scan indicators, and User B cannot insert an indicator referencing User A's `scan_id` (denied by parent scan ownership check).
  - `payment_scan_results`: User B cannot read User A's payment scans.
  - Zero-Access Tables: Authenticated clients receive 0 rows from `connected_mailbox_tokens`, `oauth_pending_transactions`, `email_verification_challenges`, and `payment_provider_events` (`USING (false)` policy enforced).
