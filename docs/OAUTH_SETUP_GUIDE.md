# ScamShield OAuth 2.0 Mailbox Integration Setup Guide

This guide details how to configure production OAuth 2.0 authorization code credentials for **Google Gmail** and **Microsoft Outlook** with strict, read-only permissions for ScamShield's automated phishing and fraud defense.

---

## 1. Google Gmail OAuth 2.0 Setup

ScamShield uses official Google OAuth 2.0 to inspect incoming emails and headers for brand impersonation and malicious phishing links.

### Permissions Requested
- `https://www.googleapis.com/auth/gmail.readonly` — View your email messages and settings (read-only)
- `https://www.googleapis.com/auth/userinfo.email` — View your email address
- `openid` — Associate you with your Google account

> **Security Note:** ScamShield **never** requests send, write, or delete permissions (`https://mail.google.com/` or `gmail.modify` are explicitly omitted).

### Step-by-Step Instructions
1. Navigate to the **[Google Cloud Console](https://console.cloud.google.com/)**.
2. Create or select a project (e.g., `ScamShield Security`).
3. Navigate to **APIs & Services > Library** and enable **Gmail API**.
4. Go to **APIs & Services > OAuth consent screen**:
   - User Type: **External** (or **Internal** for Google Workspace orgs).
   - App Name: `ScamShield`.
   - User Support Email: your support email (e.g., `support.scamsheild@gmail.com`).
   - Developer Contact Email: your technical contact.
   - Scopes: Add `.../auth/gmail.readonly` and `.../auth/userinfo.email`.
5. Go to **APIs & Services > Credentials > Create Credentials > OAuth client ID**:
   - Application type: **Web application**.
   - Name: `ScamShield Web Dashboard`.
   - **Authorized JavaScript origins**:
     - `http://localhost:5173`
     - `https://scamshield.local` (or your production domain)
   - **Authorized redirect URIs**:
     - `http://localhost:5173/`
     - `https://scamshield.local/` (or your production dashboard URL)
6. Copy the **Client ID** and **Client Secret**.

---

## 2. Microsoft Outlook / Microsoft Graph Setup

ScamShield connects to personal Microsoft accounts (Outlook.com, Hotmail, Live) and Microsoft 365 / Entra ID work accounts via Microsoft Graph.

### Permissions Requested
- `https://graph.microsoft.com/Mail.Read` — Read user mail (delegated read-only)
- `offline_access` — Maintain access to data you have given it access to (enables refresh tokens)
- `User.Read` — Sign in and read user profile
- `openid`, `email` — Authenticate and view email identity

> **Security Note:** ScamShield **never** requests `Mail.ReadWrite`, `Mail.Send`, or `MailboxSettings.ReadWrite`.

### Step-by-Step Instructions
1. Navigate to the **[Microsoft Entra Admin Center](https://entra.microsoft.com/)** or **[Azure Portal](https://portal.azure.com/)**.
2. Navigate to **Identity > Applications > App registrations**.
3. Click **New registration**:
   - Name: `ScamShield Mailbox Security`.
   - Supported account types: **Accounts in any organizational directory (Any Microsoft Entra ID / multitenant) and personal Microsoft accounts (e.g. Skype, Xbox, Outlook.com)**.
   - Redirect URI (optional now, configured in next step): Web -> `http://localhost:5173/`.
4. Click **Register**. Note your **Application (client) ID**.
5. Under **Authentication**:
   - Ensure the Web redirect URI matches your dashboard: `http://localhost:5173/` or your production domain.
6. Under **Certificates & secrets**:
   - Click **New client secret**.
   - Add a description (e.g., `ScamShield Edge Token Exchange`) and choose an expiration period.
   - Copy the secret **Value** (not the Secret ID).
7. Under **API permissions**:
   - Click **Add a permission > Microsoft Graph > Delegated permissions**.
   - Search for and check: `Mail.Read` and `User.Read`.
   - (Optional for single-tenant enterprise deployments): Click **Grant admin consent**.

---

## 3. Configuring Supabase Edge Function Secrets

In Supabase, store the OAuth credentials as secure backend environment variables:

```bash
# Using Supabase CLI:
supabase secrets set \
  GOOGLE_CLIENT_ID="your-client-id.apps.googleusercontent.com" \
  GOOGLE_CLIENT_SECRET="GOCSPX-your-secret" \
  MICROSOFT_CLIENT_ID="your-entra-app-id" \
  MICROSOFT_CLIENT_SECRET="your-entra-secret-value" \
  MICROSOFT_TENANT_ID="common" \
  TOKEN_ENCRYPTION_KEY="your-random-32-byte-master-encryption-key" \
  DASHBOARD_ORIGIN="http://localhost:5173"
```

Or configure them in **Supabase Dashboard > Project Settings > Edge Functions > Secrets**.

---

## 4. Security Architecture Highlights

1. **User-Bound State & Single-Use:**
   - Every OAuth flow starts with an authenticated request to `start-email-oauth`.
   - A cryptographic state and PKCE verifier are stored on the server in `oauth_pending_transactions` bound to `authUser.id`.
   - The transaction expires in 10 minutes and is marked `consumed_at = now()` immediately upon callback exchange, rejecting any replay attempts.

2. **Isolated Token Storage:**
   - Refresh tokens are encrypted using **AES-256-GCM** with a distinct random 96-bit IV per encryption.
   - Tokens are stored exclusively in `connected_mailbox_tokens` with Row Level Security denying all client access (`USING (false)`).
   - Frontend queries to `connected_email_accounts` never expose tokens.

3. **Authentic Identity Validation:**
   - Account email addresses and provider user IDs are fetched directly from Google's `userinfo` and Microsoft's Graph `/v1.0/me` endpoints over authenticated server-to-server TLS connections, never trusting user-supplied parameters.
