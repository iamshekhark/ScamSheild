# ScamShield Email Integration, OTP Verification & Email Alerts

## 1. Architectural Overview

ScamShield extends beyond URL and message analysis by introducing full **Mailbox Phishing Protection**, **Server-Side OTP Verification**, and **Transactional Cybersecurity Alerts**.

```
Browser Extension & Web Dashboard
         │
         ├── OAuth 2.0 PKCE ──> Google Gmail (gmail.readonly) & Outlook (Mail.Read)
         │
         ├── 6-Digit OTP Flow ──> request-email-verification (Salted SHA-256 Hashing)
         │
         ├── Mailbox Audits ──> scan-email (Impersonation, Extortion, Risky TLDs)
         │
         └── Alerts & Reports ──> Transactional Dispatcher (Resend / Exponential Backoff / Deduplication)
```

---

## 2. Database Schema (`supabase/migrations/20261018010000_email_integration_alerts.sql`)

### Tables Implemented:
1. `connected_email_accounts`:
   - Stores Gmail & Microsoft Outlook OAuth connections.
   - Stores encrypted refresh token references (`encrypted_refresh_token`).
   - Tracks `monitoring_enabled` (requires explicit user consent), `last_successful_sync_at`, and `connection_status`.
   - Strict Row Level Security: Users can query and manage only their own accounts.
2. `email_scan_results`:
   - Stores detection results: sender, subject (redacted), risk score (0-100), indicators, and recommended actions.
   - Unique constraint on `(user_id, provider_message_id)` to avoid duplicate entries.
3. `email_verification_challenges`:
   - Stores salted SHA-256 OTP hashes (never plaintext codes).
   - Enforces 5-minute expiry, max 5 attempts, single-use consumption, and 60-second cooldown.
   - Denies all direct client queries; accessible only by trusted server functions.
4. `notification_preferences`:
   - Manages alerts for critical phishing, suspicious emails, account sign-ins, connection status, and weekly summaries.
   - Tracks `recipient_verified` flag.
5. `notification_delivery_log`:
   - Tracks delivery status (`delivered`, `failed`, `suppressed`).
   - Deduplication key prevents duplicate alerts for the same scan.

---

## 3. Server-Side Edge Functions (`supabase/functions/`)

| Function Name | Purpose |
|---|---|
| `request-email-verification` | Generates 6-digit OTP, computes salted SHA-256 digest, enforces 60s cooldown, dispatches transactional email. |
| `verify-email-code` | Validates 6-digit code against hash using timing-safe comparison, checks 5-attempt limit, marks consumed. |
| `resend-email-verification` | Enforces 60-second cooldown, invalidates older challenges, dispatches a fresh code. |
| `start-email-oauth` | Generates PKCE code challenge and CSRF state token with minimum scopes (`gmail.readonly`, `Mail.Read`). |
| `complete-email-oauth` | Server-side code exchange, encrypts refresh token, stores account without exposing secrets to frontend. |
| `disconnect-email-account` | Revokes OAuth tokens with Google/Microsoft, removes account, triggers status alert. |
| `scan-email` | Analyzes email headers, sender brand spoofing, urgent extortion, and embedded links. Saves result. |
| `sync-email-account` | Polls mailbox messages with explicit user consent and updates sync timestamp. |
| `process-email-notification` | Queue worker verifying user consent, applying deduplication, and sending transactional alerts. |
| `update-notification-preferences` | Updates alert toggles and resets recipient verification if address is changed. |
| `send-weekly-security-summary` | Scheduled worker aggregating 7-day threat metrics and sending weekly digests. |

---

## 4. Email Templates (`_shared/emailTemplates.ts`)

Responsive, branded HTML templates with strict HTML escaping and zero clickable dangerous links:
1. `verificationCode`: 6-digit OTP code with 5-minute countdown.
2. `welcome`: Activation notice for newly protected accounts.
3. `highRiskAlert`: Critical phishing alert with detected risk indicators and safety recommendations.
4. `suspiciousEmailSummary`: Digest of flagged emails from mailbox scans.
5. `newLoginAlert`: Real-time login notification with IP and device info.
6. `mailboxRevoked`: Notification when OAuth session expires or is revoked.
7. `weeklyReport`: 7-day cybersecurity summary of blocked threats.

---

## 5. Security & Privacy Guarantees

1. **Least-Privilege Scopes**: Only `gmail.readonly` and `Mail.Read` are requested. Zero write, send, or delete permissions.
2. **Never Plaintext Codes**: OTPs are salted and hashed using SHA-256 before insertion into the database.
3. **No Credential Exposure**: Provider OAuth refresh tokens and client secrets are strictly handled on the backend; never exposed to extension storage or client JS.
4. **Untrusted Input Protection**: Email bodies and user inputs are strictly escaped; dangerous links from phishing emails are suppressed in alert digests.
5. **Deduplication & Rate Limiting**: Alerts for the same email message are deduplicated per user with bounded exponential backoff retries.

---

## 6. Automated Integration Tests (`tests/email_alerts_otp.test.js`)

Run with:
```bash
node --test tests/*.test.js
```
All 18 tests passing:
- OTP generation and validation
- Salted SHA-256 hashing and verification
- 5-attempt locking and single-use invalidation
- 60-second resend cooldown enforcement
- Email brand spoofing and invoice fraud detection
- Notification deduplication and duplicate alert suppression
