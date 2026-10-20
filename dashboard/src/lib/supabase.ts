import { createClient } from "@supabase/supabase-js";

const envUrl = import.meta.env.VITE_SUPABASE_URL;
const envKey = import.meta.env.VITE_SUPABASE_ANON_KEY;

export const isLiveSupabaseConfigured = Boolean(
  envUrl &&
  !envUrl.includes("your-project") &&
  envKey &&
  envKey !== "your-anon-key"
);
const MAIL_SERVICE_URL = import.meta.env.VITE_MAIL_SERVICE_URL || "http://localhost:8787";

export interface ScanRecord {
  id: string;
  user_id: string;
  scan_type: "url" | "text" | "email" | "message" | "screenshot";
  submitted_content: string;
  normalized_domain?: string | null;
  risk_score: number;
  risk_level: "low" | "medium" | "high" | "critical";
  detection_method: "rules" | "ai" | "hybrid";
  explanation?: string | null;
  indicators: Array<{
    indicator_type: string;
    description: string;
    severity: "low" | "medium" | "high" | "critical";
  }>;
  recommended_actions: string[];
  created_at: string;
}

export interface UserPreferences {
  save_scan_history: boolean;
  allow_ai_analysis: boolean;
  allow_anonymous_telemetry: boolean;
}

export interface ConnectedEmailAccount {
  id: string;
  user_id: string;
  provider: "gmail" | "outlook";
  provider_account_id: string;
  email_address: string;
  connection_status: "connected" | "expired" | "revoked" | "error";
  granted_scopes: string[];
  monitoring_enabled: boolean;
  last_successful_sync_at?: string | null;
  last_error_code?: string | null;
  created_at: string;
  updated_at: string;
}

export interface EmailScanResult {
  id: string;
  user_id: string;
  connected_account_id?: string | null;
  provider_message_id: string;
  normalized_message_fingerprint: string;
  sender_address: string;
  subject_redacted: string;
  risk_score: number;
  risk_level: "low" | "medium" | "high" | "critical";
  detection_method: "rules" | "ai" | "hybrid";
  indicators: Array<{
    indicator_type: string;
    description: string;
    severity: "low" | "medium" | "high" | "critical";
  }>;
  explanation?: string | null;
  recommended_actions: string[];
  scanned_at: string;
  created_at: string;
}

export interface NotificationPreferences {
  id?: string;
  user_id: string;
  recipient_email?: string;
  recipient_verified: boolean;
  suspicious_email_alerts: boolean;
  critical_risk_alerts: boolean;
  account_security_alerts: boolean;
  connection_status_alerts: boolean;
  weekly_summary: boolean;
  updated_at: string;
}

export interface NotificationDeliveryLog {
  id: string;
  user_id: string;
  notification_type: string;
  deduplication_key: string;
  provider_message_id?: string;
  delivery_status: "pending" | "delivered" | "failed" | "suppressed";
  attempt_count: number;
  last_error_code?: string | null;
  created_at: string;
  sent_at?: string | null;
}

export interface PaymentScanRecord {
  id: string;
  user_id: string;
  input_type: "upi_id" | "payment_url" | "qr_code" | "message" | "screenshot" | "utr";
  normalized_payee?: string | null;
  payment_domain?: string | null;
  risk_score: number;
  risk_level: "safe" | "low" | "medium" | "high" | "critical";
  detection_method: "rules" | "ai" | "hybrid";
  indicators: Array<{
    evidence_type: string;
    description: string;
    source?: string;
    confidence?: number;
  }>;
  explanation: string;
  recommended_actions: string[];
  reputation_source?: string | null;
  checked_at?: string;
  payment_status: "unverified" | "pending" | "successful" | "failed" | "cancelled" | "refunded" | "unknown";
  created_at: string;
}

// Default pre-seeded scans for instant demonstration
const INITIAL_MOCK_SCANS: ScanRecord[] = [
  {
    id: "scan-001",
    user_id: "demo-user",
    scan_type: "url",
    submitted_content: "http://paytrn-security.xyz/login",
    normalized_domain: "paytrn-security.xyz",
    risk_score: 92,
    risk_level: "critical",
    detection_method: "hybrid",
    explanation: "High-probability phishing site mimicking Paytm with an unverified throwaway TLD.",
    indicators: [
      { indicator_type: "BRAND_IMPERSONATION", description: "Typo-squatting mimics Paytm (paytm.com)", severity: "critical" },
      { indicator_type: "DOMAIN_STRUCTURE", description: "Uses risky .xyz top-level domain", severity: "medium" },
      { indicator_type: "URL_SECURITY", description: "Insecure connection (plain HTTP)", severity: "medium" }
    ],
    recommended_actions: [
      "Do not enter passwords or banking details.",
      "Navigate to official paytm.com directly."
    ],
    created_at: new Date(Date.now() - 3600000 * 2).toISOString()
  },
  {
    id: "scan-002",
    user_id: "demo-user",
    scan_type: "text",
    submitted_content: "URGENT: Your bank account will be suspended today. Share your OTP immediately at http://192.168.1.50/verify to restore access.",
    normalized_domain: "192.168.1.50",
    risk_score: 100,
    risk_level: "critical",
    detection_method: "hybrid",
    explanation: "Aggressive credential and OTP extortion combining time pressure with raw IP phishing.",
    indicators: [
      { indicator_type: "OTP_REQUEST", description: "Asks user to divulge one-time verification password", severity: "critical" },
      { indicator_type: "URGENCY", description: "High-pressure urgency wording ('immediately')", severity: "medium" },
      { indicator_type: "THREAT", description: "Threat of immediate account suspension", severity: "medium" },
      { indicator_type: "SUSPICIOUS_IP_URL", description: "Contains raw numerical IP link", severity: "high" }
    ],
    recommended_actions: [
      "Never share OTPs with anyone.",
      "Block the sender and report to official cyber crime helpline."
    ],
    created_at: new Date(Date.now() - 3600000 * 18).toISOString()
  },
  {
    id: "scan-003",
    user_id: "demo-user",
    scan_type: "url",
    submitted_content: "http://192.168.1.50/verify",
    normalized_domain: "192.168.1.50",
    risk_score: 82,
    risk_level: "critical",
    detection_method: "rules",
    explanation: "Destination points to a raw IP address instead of a registered domain.",
    indicators: [
      { indicator_type: "SUSPICIOUS_IP_URL", description: "Raw IP host detected", severity: "high" },
      { indicator_type: "URL_SECURITY", description: "Non-HTTPS protocol", severity: "medium" }
    ],
    recommended_actions: [
      "Do not open raw IP URLs."
    ],
    created_at: new Date(Date.now() - 3600000 * 36).toISOString()
  },
  {
    id: "scan-004",
    user_id: "demo-user",
    scan_type: "url",
    submitted_content: "https://www.google.com",
    normalized_domain: "google.com",
    risk_score: 0,
    risk_level: "low",
    detection_method: "rules",
    explanation: "Legitimate domain with standard security and valid HTTPS.",
    indicators: [],
    recommended_actions: [
      "Standard safe website."
    ],
    created_at: new Date(Date.now() - 3600000 * 48).toISOString()
  }
];

// In-browser mock engine that activates when Supabase cloud is not configured
class LocalMockClient {
  private authListeners: Array<(event: string, session: any) => void> = [];

  private getStoredSession() {
    const raw = localStorage.getItem("scamshield_session");
    return raw ? JSON.parse(raw) : null;
  }

  private setStoredSession(session: any) {
    if (session) {
      localStorage.setItem("scamshield_session", JSON.stringify(session));
    } else {
      localStorage.removeItem("scamshield_session");
    }
    this.authListeners.forEach((fn) => fn(session ? "SIGNED_IN" : "SIGNED_OUT", session));
  }

  private getStoredScans(): ScanRecord[] {
    const raw = localStorage.getItem("scamshield_scans");
    if (!raw) {
      localStorage.setItem("scamshield_scans", JSON.stringify(INITIAL_MOCK_SCANS));
      return INITIAL_MOCK_SCANS;
    }
    return JSON.parse(raw);
  }

  private setStoredScans(scans: ScanRecord[]) {
    localStorage.setItem("scamshield_scans", JSON.stringify(scans));
  }

  private getStoredAccounts(): Array<{ id: string; email: string; password?: string; full_name?: string }> {
    const raw = localStorage.getItem("scamshield_accounts");
    return raw ? JSON.parse(raw) : [];
  }

  private setStoredAccounts(accounts: Array<{ id: string; email: string; password?: string; full_name?: string }>) {
    localStorage.setItem("scamshield_accounts", JSON.stringify(accounts));
  }

  public auth = {
    getSession: async () => {
      const session = this.getStoredSession();
      return { data: { session }, error: null };
    },

    signInWithPassword: async ({ email, password }: { email: string; password?: string }) => {
      const cleanEmail = (email || "").toLowerCase().trim();
      const accounts = this.getStoredAccounts();
      let account = accounts.find((a) => a.email === cleanEmail);

      // If no account exists yet, register the first account with this password
      if (!account) {
        if (accounts.length === 0) {
          account = {
            id: "usr_" + Math.random().toString(36).slice(2, 9),
            email: cleanEmail,
            password: password || "",
            full_name: cleanEmail.split("@")[0]
          };
          accounts.push(account);
          this.setStoredAccounts(accounts);
        } else {
          return {
            data: { user: null, session: null },
            error: new Error("No account found for this email. Click 'Need an account? Register' below.")
          };
        }
      }

      // Verify password
      if (account.password && password && account.password !== password) {
        return {
          data: { user: null, session: null },
          error: new Error("Incorrect password. Please verify and try again.")
        };
      }

      const user = {
        id: account.id,
        email: account.email,
        user_metadata: { full_name: account.full_name || account.email.split("@")[0] }
      };
      const session = {
        access_token: "mock_jwt_" + Date.now(),
        user,
        expires_at: Date.now() + 86400000
      };
      this.setStoredSession(session);
      return { data: { user, session }, error: null };
    },

    signUp: async ({ email, password }: { email: string; password?: string }) => {
      const cleanEmail = (email || "").toLowerCase().trim();
      if (!cleanEmail) {
        return { data: { user: null, session: null }, error: new Error("Please enter a valid email address.") };
      }
      if (!password || password.length < 6) {
        return { data: { user: null, session: null }, error: new Error("Password must be at least 6 characters.") };
      }

      const accounts = this.getStoredAccounts();
      const existing = accounts.find((a) => a.email === cleanEmail);

      if (existing) {
        if (existing.password && existing.password !== password) {
          return {
            data: { user: null, session: null },
            error: new Error("An account already exists with this email. Please enter the correct password to sign in.")
          };
        }
        return this.auth.signInWithPassword({ email, password });
      }

      const newAccount = {
        id: "usr_" + Math.random().toString(36).slice(2, 9),
        email: cleanEmail,
        password: password,
        full_name: cleanEmail.split("@")[0]
      };
      accounts.push(newAccount);
      this.setStoredAccounts(accounts);

      const user = {
        id: newAccount.id,
        email: newAccount.email,
        user_metadata: { full_name: newAccount.full_name }
      };
      const session = {
        access_token: "mock_jwt_" + Date.now(),
        user,
        expires_at: Date.now() + 86400000
      };
      this.setStoredSession(session);

      // In local mode, welcome notification is logged; in live mode, Supabase Auth handles welcome
      console.info(`[Auth] Welcome email queued for ${cleanEmail}`);

      return { data: { user, session }, error: null };
    },

    resetPasswordForEmail: async (email: string) => {
      const cleanEmail = (email || "").toLowerCase().trim();
      if (!cleanEmail) {
        return { data: null, error: new Error("Please enter your email address.") };
      }
      const accounts = this.getStoredAccounts();
      let account = accounts.find((a) => a.email === cleanEmail);
      if (!account) {
        // Auto-provision so user can test password reset with any email address
        account = {
          id: "usr_" + Math.random().toString(36).slice(2, 9),
          email: cleanEmail,
          password: "InitialPassword123!",
          full_name: cleanEmail.split("@")[0]
        };
        accounts.push(account);
        this.setStoredAccounts(accounts);
      }
      // Generate real 6-digit verification code
      const code = Math.floor(100000 + Math.random() * 900000).toString();
      localStorage.setItem("scamshield_reset_" + cleanEmail, JSON.stringify({ code, expires: Date.now() + 15 * 60000 }));

      console.info(`[Auth] Password reset code for ${cleanEmail}: ${code}`);

      let emailDispatched = false;
      try {
        const mailRes = await fetch(`${MAIL_SERVICE_URL}/send-password-reset`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            email: cleanEmail,
            code,
            expiryMinutes: 15
          })
        });
        const mailData = await mailRes.json();
        if (mailData && mailData.success) {
          emailDispatched = true;
        }
      } catch (e) {
        console.warn("[MailService] Local dispatch skipped or offline:", e);
      }

      return {
        data: {
          code,
          emailDispatched,
          message: emailDispatched
            ? "A password reset verification code has been dispatched to your email."
            : `A password reset code has been generated. (Verification code: ${code})`
        },
        error: null
      };
    },

    updatePasswordWithCode: async ({ email, code, newPassword }: { email: string; code?: string; newPassword: string }) => {
      const cleanEmail = (email || "").toLowerCase().trim();
      if (!cleanEmail) {
        return { data: null, error: new Error("Please enter your email address.") };
      }
      if (!newPassword || newPassword.length < 6) {
        return { data: null, error: new Error("New password must be at least 6 characters.") };
      }

      const accounts = this.getStoredAccounts();
      const accountIndex = accounts.findIndex((a) => a.email === cleanEmail);
      if (accountIndex === -1) {
        return { data: null, error: new Error("Account not found.") };
      }

      // Verify reset code if present in storage
      const resetRaw = localStorage.getItem("scamshield_reset_" + cleanEmail);
      if (resetRaw) {
        const stored = JSON.parse(resetRaw);
        if (stored.expires < Date.now()) {
          return { data: null, error: new Error("Verification code expired. Please request a new code.") };
        }
        if (code && code.trim() !== stored.code) {
          return { data: null, error: new Error("Invalid verification code. Please check and try again.") };
        }
      }

      // Update password
      accounts[accountIndex].password = newPassword;
      this.setStoredAccounts(accounts);
      localStorage.removeItem("scamshield_reset_" + cleanEmail);

      // Auto sign-in the user
      const user = {
        id: accounts[accountIndex].id,
        email: accounts[accountIndex].email,
        user_metadata: { full_name: accounts[accountIndex].full_name || accounts[accountIndex].email.split("@")[0] }
      };
      const session = {
        access_token: "mock_jwt_" + Date.now(),
        user,
        expires_at: Date.now() + 86400000
      };
      this.setStoredSession(session);

      return { data: { user, session }, error: null };
    },

    updateUser: async ({ password }: { password?: string }) => {
      const current = this.getStoredSession();
      if (!current?.user?.email) {
        return { data: null, error: new Error("No active session.") };
      }
      if (!password || password.length < 6) {
        return { data: null, error: new Error("Password must be at least 6 characters.") };
      }
      const accounts = this.getStoredAccounts();
      const account = accounts.find((a) => a.email === current.user.email);
      if (account) {
        account.password = password;
        this.setStoredAccounts(accounts);
      }
      return { data: { user: current.user }, error: null };
    },

    signOut: async () => {
      this.setStoredSession(null);
      return { error: null };
    },

    onAuthStateChange: (callback: (event: string, session: any) => void) => {
      this.authListeners.push(callback);
      return {
        data: {
          subscription: {
            unsubscribe: () => {
              this.authListeners = this.authListeners.filter((fn) => fn !== callback);
            }
          }
        }
      };
    }
  };

  private getStoredEmailAccounts(): ConnectedEmailAccount[] {
    const raw = localStorage.getItem("scamshield_email_accounts");
    if (!raw) {
      const initial: ConnectedEmailAccount[] = [];
      localStorage.setItem("scamshield_email_accounts", JSON.stringify(initial));
      return initial;
    }
    const parsed = JSON.parse(raw);
    const session = this.getStoredSession();
    const currentUserId = session?.user?.id;
    let modified = false;
    parsed.forEach((a: any) => {
      if (a.id !== "acc-gmail-01") {
        if ((!a.user_id || a.user_id === "demo-user") && currentUserId) {
          a.user_id = currentUserId;
          modified = true;
        }
      }
    });
    if (modified) {
      localStorage.setItem("scamshield_email_accounts", JSON.stringify(parsed));
    }
    return parsed.filter((a: any) => a.id !== "acc-gmail-01");
  }

  private setStoredEmailAccounts(accs: ConnectedEmailAccount[]) {
    localStorage.setItem("scamshield_email_accounts", JSON.stringify(accs));
  }

  private getStoredEmailScans(): EmailScanResult[] {
    const raw = localStorage.getItem("scamshield_email_scans");
    if (!raw) {
      const initial: EmailScanResult[] = [
        {
          id: "escan-001",
          user_id: "demo-user",
          connected_account_id: "acc-gmail-01",
          provider_message_id: "msg_paytm_spoof_981",
          normalized_message_fingerprint: "fp_paytm_phish",
          sender_address: "Paytm Security <alert-support@paytrn-security.xyz>",
          subject_redacted: "URGENT: Your KYC is expired. Re-verify OTP to prevent blocking",
          risk_score: 95,
          risk_level: "critical",
          detection_method: "hybrid",
          indicators: [
            { indicator_type: "SENDER_IMPERSONATION", description: "Display name mimics Paytm but sender domain is untrusted .xyz host", severity: "critical" },
            { indicator_type: "CREDENTIAL_HARVESTING", description: "Requests immediate OTP and KYC identity verification", severity: "critical" },
            { indicator_type: "URGENT_EXTORTION", description: "Threatens immediate service termination within 24 hours", severity: "high" }
          ],
          explanation: "Aggressive phishing campaign combining brand impersonation with credential extortion.",
          recommended_actions: [
            "Do not click links or reply to this email.",
            "Mark as Phishing in your email provider."
          ],
          scanned_at: new Date(Date.now() - 3600000 * 3).toISOString(),
          created_at: new Date(Date.now() - 3600000 * 3).toISOString()
        },
        {
          id: "escan-002",
          user_id: "demo-user",
          connected_account_id: "acc-gmail-01",
          provider_message_id: "msg_invoice_fraud_44",
          normalized_message_fingerprint: "fp_invoice_scam",
          sender_address: "Billing Dept <invoices@cloud-service-billing.top>",
          subject_redacted: "Invoice #98201 Overdue - Immediate wire transfer required",
          risk_score: 80,
          risk_level: "critical",
          detection_method: "rules",
          indicators: [
            { indicator_type: "FINANCIAL_FRAUD", description: "Unsolicited overdue invoice demanding immediate wire transfer", severity: "high" },
            { indicator_type: "SUSPICIOUS_LINK", description: "Points to high-risk top-level domain (.top)", severity: "high" }
          ],
          explanation: "Fake invoice scam targeting corporate accounting with deceptive urgent payment instructions.",
          recommended_actions: [
            "Verify invoice directly with your vendor via telephone.",
            "Never wire funds based on unsolicited email instructions."
          ],
          scanned_at: new Date(Date.now() - 3600000 * 12).toISOString(),
          created_at: new Date(Date.now() - 3600000 * 12).toISOString()
        },
        {
          id: "escan-003",
          user_id: "demo-user",
          connected_account_id: "acc-gmail-01",
          provider_message_id: "msg_safe_github_12",
          normalized_message_fingerprint: "fp_safe_github",
          sender_address: "GitHub <notifications@github.com>",
          subject_redacted: "[GitHub] Security advisory published for repository dependency",
          risk_score: 5,
          risk_level: "low",
          detection_method: "rules",
          indicators: [],
          explanation: "Authentic notifications from legitimate github.com domain.",
          recommended_actions: ["Standard safe email."],
          scanned_at: new Date(Date.now() - 3600000 * 24).toISOString(),
          created_at: new Date(Date.now() - 3600000 * 24).toISOString()
        }
      ];
      localStorage.setItem("scamshield_email_scans", JSON.stringify(initial));
      return initial;
    }
    return JSON.parse(raw);
  }

  private setStoredEmailScans(scans: EmailScanResult[]) {
    localStorage.setItem("scamshield_email_scans", JSON.stringify(scans));
  }

  private getStoredNotifLogs(): NotificationDeliveryLog[] {
    const raw = localStorage.getItem("scamshield_notif_logs");
    if (!raw) {
      const initial: NotificationDeliveryLog[] = [
        {
          id: "nlog-001",
          user_id: "demo-user",
          notification_type: "high_risk_alert",
          deduplication_key: "scan_alert_paytm_critical",
          provider_message_id: "resend_msg_84920",
          delivery_status: "delivered",
          attempt_count: 1,
          last_error_code: null,
          created_at: new Date(Date.now() - 3600000 * 3).toISOString(),
          sent_at: new Date(Date.now() - 3600000 * 3).toISOString()
        }
      ];
      localStorage.setItem("scamshield_notif_logs", JSON.stringify(initial));
      return initial;
    }
    return JSON.parse(raw);
  }

  public functions = {
    invoke: async (name: string, { body }: { body?: any } = {}) => {
      // Local implementation of server functions for immediate in-browser execution
      if (name === "request-email-verification" || name === "resend-email-verification") {
        const email = (body?.email || "").toLowerCase().trim();
        const code = Math.floor(100000 + Math.random() * 900000).toString();
        localStorage.setItem("scamshield_otp_" + email, JSON.stringify({
          code,
          expires: Date.now() + 5 * 60 * 1000,
          attempts: 0
        }));

        // Verification code stored in localStorage for immediate verification
        console.info(`[Verification] OTP generated for ${email}: ${code}`);

        let emailDispatched = false;
        try {
          const mailRes = await fetch(`${MAIL_SERVICE_URL}/send-verification-code`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              email,
              code,
              purpose: body?.purpose || "recipient_verification",
              expiryMinutes: 5
            })
          });
          const mailData = await mailRes.json();
          if (mailData && mailData.success) {
            emailDispatched = true;
          }
        } catch (e) {
          console.warn("[MailService] Local dispatch skipped or offline:", e);
        }

        return {
          data: {
            success: true,
            resendAfterSeconds: 60,
            expiresInMinutes: 5,
            code,
            emailDispatched,
            message: emailDispatched
              ? `Verification code dispatched to ${email}.`
              : `Verification code generated for ${email}. (Code: ${code})`
          },
          error: null
        };
      }

      if (name === "verify-email-code") {
        const email = (body?.email || "").toLowerCase().trim();
        const code = (body?.code || "").trim();
        const raw = localStorage.getItem("scamshield_otp_" + email);
        if (!raw) {
          return { data: null, error: new Error("Verification code expired or not found. Please request a new code.") };
        }
        const chal = JSON.parse(raw);
        if (chal.expires < Date.now()) {
          localStorage.removeItem("scamshield_otp_" + email);
          return { data: null, error: new Error("Verification code expired. Please request a new code.") };
        }
        chal.attempts = (chal.attempts || 0) + 1;
        if (chal.attempts > 5) {
          localStorage.removeItem("scamshield_otp_" + email);
          return { data: null, error: new Error("Maximum attempts exceeded. Code has been invalidated.") };
        }
        if (chal.code !== code) {
          localStorage.setItem("scamshield_otp_" + email, JSON.stringify(chal));
          return { data: null, error: new Error(`Incorrect code. ${5 - chal.attempts} attempts remaining.`) };
        }
        // Success
        localStorage.removeItem("scamshield_otp_" + email);
        return { data: { success: true, verified: true, message: "Email verified successfully." }, error: null };
      }

      if (name === "start-email-oauth") {
        const provider = body?.provider || "gmail";
        const redirectUri = body?.redirectUri || (window.location.origin + window.location.pathname);
        const googleClientId = import.meta.env.VITE_GOOGLE_CLIENT_ID || "";
        const msClientId = import.meta.env.VITE_MICROSOFT_CLIENT_ID || import.meta.env.VITE_AZURE_CLIENT_ID || "";
        const clientId = provider === "gmail" ? googleClientId : msClientId;

        if (!clientId) {
          return {
            data: {
              configured: false,
              provider,
              error: `OAuth credentials for ${provider.toUpperCase()} are not yet configured on the server. Please configure ${provider === "gmail" ? "GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET" : "MICROSOFT_CLIENT_ID and MICROSOFT_CLIENT_SECRET"} in Supabase project secrets or environment variables.`
            },
            error: null
          };
        }

        // Generate PKCE code verifier and challenge
        const verifierBytes = new Uint8Array(32);
        crypto.getRandomValues(verifierBytes);
        const codeVerifier = Array.from(verifierBytes).map((b) => b.toString(16).padStart(2, "0")).join("");
        const verifierHash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(codeVerifier));
        const codeChallenge = btoa(String.fromCharCode(...new Uint8Array(verifierHash)))
          .replace(/\+/g, "-")
          .replace(/\//g, "_")
          .replace(/=+$/, "");

        const stateRandom = Array.from(crypto.getRandomValues(new Uint8Array(16))).map((b) => b.toString(16).padStart(2, "0")).join("");
        const state = `${provider}:${Date.now()}:${stateRandom}`;

        // Store transaction in localStorage to validate on callback
        localStorage.setItem(`scamshield_oauth_tx_${state}`, JSON.stringify({
          provider,
          state,
          codeVerifier,
          redirectUri,
          expiresAt: Date.now() + 10 * 60 * 1000
        }));

        let authUrl = "";
        if (provider === "gmail") {
          const scopes = [
            "https://www.googleapis.com/auth/gmail.readonly",
            "https://www.googleapis.com/auth/userinfo.email",
            "openid"
          ].join(" ");
          const params = new URLSearchParams({
            client_id: clientId,
            redirect_uri: redirectUri,
            response_type: "code",
            scope: scopes,
            access_type: "offline",
            prompt: "consent",
            state,
            code_challenge: codeChallenge,
            code_challenge_method: "S256",
            include_granted_scopes: "true"
          });
          authUrl = `https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`;
        } else {
          const scopes = [
            "https://graph.microsoft.com/Mail.Read",
            "offline_access",
            "User.Read",
            "openid",
            "email"
          ].join(" ");
          const params = new URLSearchParams({
            client_id: clientId,
            redirect_uri: redirectUri,
            response_type: "code",
            scope: scopes,
            response_mode: "query",
            state,
            code_challenge: codeChallenge,
            code_challenge_method: "S256",
            prompt: "consent"
          });
          const tenantId = import.meta.env.VITE_MICROSOFT_TENANT_ID || "common";
          authUrl = `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/authorize?${params.toString()}`;
        }

        return {
          data: {
            configured: true,
            authUrl,
            provider,
            state,
            codeVerifier,
            scopesExplanation: provider === "gmail"
              ? "ScamShield requests 'gmail.readonly' to inspect email headers, text, and links for phishing with zero write or delete permissions."
              : "ScamShield requests 'Mail.Read' to inspect incoming Outlook messages for scam patterns with zero write permissions."
          },
          error: null
        };
      }

      if (name === "complete-email-oauth") {
        const provider = body?.provider || "gmail";
        const code = body?.code;
        const state = body?.state;
        const codeVerifier = body?.codeVerifier || "";
        const redirectUri = body?.redirectUri || (window.location.origin + window.location.pathname);

        if (!code || !state) {
          return { data: null, error: new Error("Missing required OAuth parameters: code or state") };
        }

        // Validate state across localStorage or sessionStorage or timestamp format
        const txKey = `scamshield_oauth_tx_${state}`;
        const rawTx = localStorage.getItem(txKey);
        let storedVerifier = codeVerifier;

        if (rawTx) {
          try {
            const tx = JSON.parse(rawTx);
            localStorage.removeItem(txKey);
            if (Date.now() > tx.expiresAt) {
              return { data: null, error: new Error("OAuth session has expired. Please initiate connection again.") };
            }
            if (tx.provider !== provider) {
              return { data: null, error: new Error("Provider mismatch in OAuth transaction callback") };
            }
            storedVerifier = tx.codeVerifier || storedVerifier;
          } catch {
            // fallback
          }
        } else {
          // Fallback check on state timestamp (valid within 15 minutes)
          const parts = state.split(":");
          if (parts.length >= 2) {
            const timestamp = parseInt(parts[1], 10);
            if (!isNaN(timestamp) && (Date.now() - timestamp > 15 * 60 * 1000)) {
              return { data: null, error: new Error("OAuth session has expired. Please initiate connection again.") };
            }
          }
        }

        // Exchange code with mail-service bridge
        try {
          const exchangeRes = await fetch(`${MAIL_SERVICE_URL}/oauth/exchange-token`, {
            method: "POST",
            headers: {
              "Content-Type": "application/json"
            },
            body: JSON.stringify({
              provider,
              code,
              codeVerifier: storedVerifier,
              redirectUri
            })
          });

          const exchangeData = await exchangeRes.json();
          if (!exchangeRes.ok || !exchangeData.success) {
            return {
              data: null,
              error: new Error(exchangeData.error || "Failed to exchange authorization code for credentials")
            };
          }

          const session = this.getStoredSession();
          const targetUserId = body?.userId || session?.user?.id || "usr_active";

          const newAcc: ConnectedEmailAccount = {
            id: `acc-${provider}-${Date.now().toString(36)}`,
            user_id: targetUserId,
            provider,
            provider_account_id: exchangeData.providerAccountId || exchangeData.email,
            email_address: exchangeData.email,
            connection_status: "connected",
            granted_scopes: exchangeData.scopes || (provider === "gmail" ? ["https://www.googleapis.com/auth/gmail.readonly"] : ["https://graph.microsoft.com/Mail.Read"]),
            monitoring_enabled: true,
            last_successful_sync_at: new Date().toISOString(),
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString()
          };

          const current = this.getStoredEmailAccounts();
          const updated = current.filter((a) => a.email_address !== newAcc.email_address);
          this.setStoredEmailAccounts([newAcc, ...updated]);

          // Save audited incoming messages into email_scan_results
          let scannedCount = 0;
          if (Array.isArray(exchangeData.scannedMessages) && exchangeData.scannedMessages.length > 0) {
            const currentScans = this.getStoredEmailScans();
            const formattedScans: EmailScanResult[] = exchangeData.scannedMessages.map((m: any) => ({
              id: "escan-" + Math.random().toString(36).slice(2, 9),
              user_id: targetUserId,
              connected_account_id: newAcc.id,
              provider_message_id: m.provider_message_id || ("msg_" + Math.random().toString(36).slice(2, 8)),
              normalized_message_fingerprint: "fp_" + Math.random().toString(36).slice(2, 8),
              sender_address: m.sender_address,
              subject_redacted: m.subject_redacted,
              risk_score: m.risk_score,
              risk_level: m.risk_level,
              detection_method: m.detection_method || "rules",
              indicators: m.indicators || [],
              explanation: m.explanation || "Audited by ScamShield read-only mailbox monitor.",
              recommended_actions: m.recommended_actions || ["Standard safe email."],
              scanned_at: m.scanned_at || new Date().toISOString(),
              created_at: m.created_at || new Date().toISOString()
            }));
            this.setStoredEmailScans([...formattedScans, ...currentScans]);
            scannedCount = formattedScans.length;
          }

          return { data: { success: true, account: newAcc, scannedCount }, error: null };
        } catch (fetchErr: any) {
          return {
            data: null,
            error: new Error(`Could not reach authentication service at ${MAIL_SERVICE_URL}: ${fetchErr.message}`)
          };
        }
      }

      if (name === "disconnect-email-account") {
        const id = body?.accountId;
        const current = this.getStoredEmailAccounts();
        this.setStoredEmailAccounts(current.filter((a) => a.id !== id));
        return { data: { success: true }, error: null };
      }

      if (name === "sync-email-account") {
        const id = body?.accountId;
        const current = this.getStoredEmailAccounts();
        const acc = current.find((a) => a.id === id);
        let syncedCount = 0;
        if (acc) {
          acc.last_successful_sync_at = new Date().toISOString();
          this.setStoredEmailAccounts([...current]);

          try {
            const syncRes = await fetch(`${MAIL_SERVICE_URL}/oauth/sync-mailbox`, {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ email: acc.email_address, provider: acc.provider })
            });
            const syncData = await syncRes.json();
            if (syncData.success && Array.isArray(syncData.scannedMessages) && syncData.scannedMessages.length > 0) {
              const currentScans = this.getStoredEmailScans();
              const formattedScans: EmailScanResult[] = syncData.scannedMessages.map((m: any) => ({
                id: "escan-" + Math.random().toString(36).slice(2, 9),
                user_id: acc.user_id,
                connected_account_id: acc.id,
                provider_message_id: m.provider_message_id || ("msg_" + Math.random().toString(36).slice(2, 8)),
                normalized_message_fingerprint: "fp_" + Math.random().toString(36).slice(2, 8),
                sender_address: m.sender_address,
                subject_redacted: m.subject_redacted,
                risk_score: m.risk_score,
                risk_level: m.risk_level,
                detection_method: m.detection_method || "rules",
                indicators: m.indicators || [],
                explanation: m.explanation || "Audited by ScamShield read-only mailbox monitor.",
                recommended_actions: m.recommended_actions || ["Standard safe email."],
                scanned_at: m.scanned_at || new Date().toISOString(),
                created_at: m.created_at || new Date().toISOString()
              }));
              this.setStoredEmailScans([...formattedScans, ...currentScans]);
              syncedCount = formattedScans.length;
            }
          } catch (syncErr) {
            console.warn("[Mailbox Sync] Failed to query sync-mailbox:", syncErr);
          }
        }
        return { data: { success: true, syncedAt: new Date().toISOString(), totalScanned: syncedCount }, error: null };
      }

      if (name === "send-weekly-security-summary") {
        const logs = this.getStoredNotifLogs();
        const newLog: NotificationDeliveryLog = {
          id: "nlog-" + Math.random().toString(36).slice(2, 8),
          user_id: body?.userId || "demo-user",
          notification_type: "weekly_summary",
          deduplication_key: `weekly_summary_${Date.now()}`,
          delivery_status: "delivered",
          attempt_count: 1,
          created_at: new Date().toISOString(),
          sent_at: new Date().toISOString()
        };
        this.setStoredNotifLogs([newLog, ...logs]);
        return { data: { success: true, dispatched: 1 }, error: null };
      }

      if (name === "verify-payment-risk") {
        const content = body?.content || "";
        const inputType = body?.input_type || "upi_id";
        const lower = content.toLowerCase();

        let riskScore = 0;
        let riskLevel: "safe" | "low" | "medium" | "high" | "critical" = "safe";
        const evidence: any[] = [];
        const actions: string[] = [];

        if (/(?:enter|type|share|input|put|provide)\s+(?:your\s+)?(?:(?:\d+[- ]?digit|secret|4|6)\s+)?(?:upi\s+)?(?:pin|code|password)\s+to\s+(?:receive|claim|accept|credit|get|refund)/i.test(lower) ||
            /(?:enter|type|input|put).*(?:pin|secret\s*code).*(?:receive|claim|get\s*refund|credit|accept)/i.test(lower)) {
          riskScore = 95;
          riskLevel = "critical";
          evidence.push({
            evidence_type: "REVERSE_COLLECT_FRAUD",
            description: "CRITICAL ALERT: Note instructs entering a UPI PIN to receive money. In UPI architecture, entering your PIN ALWAYS debits funds from your bank account!",
            source: "rules_engine",
            confidence: 0.99
          });
          actions.push("DO NOT enter your UPI PIN. In UPI, receiving money NEVER requires entering your PIN.");
        } else if (/\b(anydesk|teamviewer|rustdesk|quicksupport|airdroid|screenshare|screen\s*share)\b/i.test(lower)) {
          riskScore = 88;
          riskLevel = "critical";
          evidence.push({
            evidence_type: "REMOTE_ACCESS_TOOL",
            description: "Coerces victim to install remote desktop software (e.g., AnyDesk/TeamViewer) to hijack banking credentials",
            source: "rules_engine",
            confidence: 0.98
          });
          actions.push("NEVER install remote desktop tools or share your screen on caller request.");
        } else if (/(?:electricity|power|bijli)\s+(?:bill\s+)?(?:will\s+be\s+)?(?:disconnected|cut|shut\s*off|disconnected\s+tonight)/i.test(lower)) {
          riskScore = 75;
          riskLevel = "high";
          evidence.push({
            evidence_type: "UTILITY_EXTORTION",
            description: "Uses immediate electricity disconnection threat to pressure urgent payment",
            source: "rules_engine",
            confidence: 0.92
          });
          actions.push("Verify bill status directly on your official electricity board website.");
        } else if (lower.includes("-refund") || lower.includes("support-desk") || lower.includes("cashback-desk")) {
          riskScore = 82;
          riskLevel = "critical";
          evidence.push({
            evidence_type: "BRAND_IMPERSONATION",
            description: `Payment identifier [${content}] mimics official customer support or refund desk`,
            source: "rules_engine",
            confidence: 0.95
          });
          actions.push("Verify payee credentials directly through your official banking application.");
        } else {
          actions.push("Verify payee identity before confirming the transfer.");
        }

        const newPaymentScan: PaymentScanRecord = {
          id: "pscan-" + Math.random().toString(36).slice(2, 8),
          user_id: body?.userId || "demo-user",
          input_type: inputType,
          normalized_payee: inputType === "upi_id" || inputType === "qr_code" ? content.split("?")[0].replace("upi://pay", "") : null,
          payment_domain: inputType === "payment_url" ? (content.split("/")[2] || content) : null,
          risk_score: riskScore,
          risk_level: riskLevel,
          detection_method: "hybrid",
          indicators: evidence,
          explanation: riskScore > 60
            ? "High-risk payment fraud patterns identified. Critical financial indicators detected."
            : "No known scam patterns detected for this payment identifier.",
          recommended_actions: actions,
          reputation_source: null,
          checked_at: new Date().toISOString(),
          payment_status: "unverified",
          created_at: new Date().toISOString()
        };

        const existing = this.getStoredPaymentScans();
        this.setStoredPaymentScans([newPaymentScan, ...existing]);

        return { data: newPaymentScan, error: null };
      }

      if (name === "get-payment-scan-history") {
        const scans = this.getStoredPaymentScans();
        return { data: { scans, total: scans.length }, error: null };
      }

      if (name === "check-payment-reputation") {
        return {
          data: {
            found: false,
            identifier: body?.identifier,
            reputation: "unknown",
            message: "No known threat intelligence alerts on record."
          },
          error: null
        };
      }

      return { data: { success: true }, error: null };
    }
  };

  private getStoredPaymentScans(): PaymentScanRecord[] {
    const raw = localStorage.getItem("scamshield_payment_scans");
    if (!raw) {
      const initial: PaymentScanRecord[] = [
        {
          id: "pscan-001",
          user_id: "demo-user",
          input_type: "qr_code",
          normalized_payee: "scammer99@ybl",
          risk_score: 95,
          risk_level: "critical",
          detection_method: "hybrid",
          indicators: [
            {
              evidence_type: "REVERSE_COLLECT_FRAUD",
              description: "QR note instructs entering UPI PIN to receive refund. In UPI, PIN entry only debits funds.",
              confidence: 0.99
            }
          ],
          explanation: "Critical reverse collect scam detected. Never enter your PIN to receive money or refunds.",
          recommended_actions: [
            "DO NOT enter your UPI PIN.",
            "Decline this payment request immediately."
          ],
          checked_at: new Date(Date.now() - 3600000 * 2).toISOString(),
          payment_status: "unverified",
          created_at: new Date(Date.now() - 3600000 * 2).toISOString()
        },
        {
          id: "pscan-002",
          user_id: "demo-user",
          input_type: "message",
          normalized_payee: "billdesk-support@ybl",
          risk_score: 75,
          risk_level: "high",
          detection_method: "rules",
          indicators: [
            {
              evidence_type: "UTILITY_EXTORTION",
              description: "Uses immediate electricity disconnection threat to pressure urgent payment",
              confidence: 0.92
            }
          ],
          explanation: "Utility bill extortion message using false urgency to pressure rapid fund transfer.",
          recommended_actions: [
            "Verify bill status directly on your official electricity board website.",
            "Do not call phone numbers sent via SMS."
          ],
          checked_at: new Date(Date.now() - 3600000 * 8).toISOString(),
          payment_status: "unverified",
          created_at: new Date(Date.now() - 3600000 * 8).toISOString()
        },
        {
          id: "pscan-003",
          user_id: "demo-user",
          input_type: "upi_id",
          normalized_payee: "grocery.store@okhdfcbank",
          risk_score: 0,
          risk_level: "safe",
          detection_method: "rules",
          indicators: [],
          explanation: "Standard merchant UPI ID syntax with legitimate HDFC PSP handle.",
          recommended_actions: [
            "Verify payee merchant name in your payment app before entering PIN."
          ],
          checked_at: new Date(Date.now() - 3600000 * 20).toISOString(),
          payment_status: "unverified",
          created_at: new Date(Date.now() - 3600000 * 20).toISOString()
        }
      ];
      localStorage.setItem("scamshield_payment_scans", JSON.stringify(initial));
      return initial;
    }
    return JSON.parse(raw);
  }

  private setStoredPaymentScans(scans: PaymentScanRecord[]) {
    localStorage.setItem("scamshield_payment_scans", JSON.stringify(scans));
  }

  private setStoredNotifLogs(logs: NotificationDeliveryLog[]) {
    localStorage.setItem("scamshield_notif_logs", JSON.stringify(logs));
  }

  public from = (table: string) => {
    return {
      select: (_cols?: string, _opts?: any) => ({
        eq: (_field: string, _val: any) => ({
          order: (_orderField: string, _opts2?: any) => {
            let data: any = [];
            if (table === "scan_history") data = this.getStoredScans();
            else if (table === "connected_email_accounts") data = this.getStoredEmailAccounts();
            else if (table === "email_scan_results") data = this.getStoredEmailScans();
            else if (table === "payment_scan_results") data = this.getStoredPaymentScans();
            else if (table === "notification_delivery_log") data = this.getStoredNotifLogs();
            return Promise.resolve({ data, error: null, count: data.length });
          },
          maybeSingle: () => {
            if (table === "user_preferences") {
              const raw = localStorage.getItem("scamshield_prefs");
              const prefs = raw ? JSON.parse(raw) : { save_scan_history: true, allow_ai_analysis: true, allow_anonymous_telemetry: false };
              return Promise.resolve({ data: prefs, error: null });
            }
            if (table === "notification_preferences") {
              const raw = localStorage.getItem("scamshield_notif_prefs");
              const prefs = raw ? JSON.parse(raw) : {
                user_id: _val,
                recipient_email: "user.security@gmail.com",
                recipient_verified: true,
                suspicious_email_alerts: true,
                critical_risk_alerts: true,
                account_security_alerts: true,
                connection_status_alerts: true,
                weekly_summary: true,
                updated_at: new Date().toISOString()
              };
              return Promise.resolve({ data: prefs, error: null });
            }
            return Promise.resolve({ data: null, error: null });
          }
        }),
        order: (_orderField: string, _opts2?: any) => {
          let data: any = [];
          if (table === "connected_email_accounts") data = this.getStoredEmailAccounts();
          else if (table === "email_scan_results") data = this.getStoredEmailScans();
          else if (table === "payment_scan_results") data = this.getStoredPaymentScans();
          else if (table === "notification_delivery_log") data = this.getStoredNotifLogs();
          return Promise.resolve({ data, error: null, count: data.length });
        }
      }),

      delete: () => ({
        eq: (field: string, val: any) => {
          if (table === "scan_history") {
            const current = this.getStoredScans();
            if (field === "id") this.setStoredScans(current.filter((s) => s.id !== val));
            else if (field === "user_id") this.setStoredScans([]);
          } else if (table === "connected_email_accounts") {
            const current = this.getStoredEmailAccounts();
            if (field === "id") this.setStoredEmailAccounts(current.filter((a) => a.id !== val));
          } else if (table === "email_scan_results") {
            const current = this.getStoredEmailScans();
            if (field === "id") this.setStoredEmailScans(current.filter((s) => s.id !== val));
          } else if (table === "payment_scan_results") {
            const current = this.getStoredPaymentScans();
            if (field === "id") this.setStoredPaymentScans(current.filter((s) => s.id !== val));
            else if (field === "user_id") this.setStoredPaymentScans([]);
          }
          return Promise.resolve({ error: null });
        }
      }),

      upsert: (payload: any) => {
        if (table === "user_preferences") {
          localStorage.setItem("scamshield_prefs", JSON.stringify(payload));
        } else if (table === "notification_preferences") {
          localStorage.setItem("scamshield_notif_prefs", JSON.stringify(payload));
        } else if (table === "connected_email_accounts") {
          const current = this.getStoredEmailAccounts();
          const idx = current.findIndex((a) => a.id === payload.id);
          if (idx >= 0) current[idx] = { ...current[idx], ...payload };
          else current.push(payload);
          this.setStoredEmailAccounts(current);
        } else if (table === "email_scan_results") {
          const current = this.getStoredEmailScans();
          const newScan: EmailScanResult = {
            id: payload.id || "escan-" + Math.random().toString(36).slice(2, 8),
            created_at: new Date().toISOString(),
            scanned_at: new Date().toISOString(),
            ...payload
          };
          this.setStoredEmailScans([newScan, ...current]);
          return Promise.resolve({ data: newScan, error: null });
        }
        return Promise.resolve({ data: payload, error: null });
      },

      insert: (payload: any) => {
        if (table === "scan_history") {
          const current = this.getStoredScans();
          const newScan: ScanRecord = {
            id: "scan-" + Math.random().toString(36).slice(2, 8),
            created_at: new Date().toISOString(),
            ...payload
          };
          this.setStoredScans([newScan, ...current]);
          return Promise.resolve({ data: newScan, error: null });
        }
        if (table === "email_scan_results") {
          const current = this.getStoredEmailScans();
          const newScan: EmailScanResult = {
            id: "escan-" + Math.random().toString(36).slice(2, 8),
            created_at: new Date().toISOString(),
            scanned_at: new Date().toISOString(),
            ...payload
          };
          this.setStoredEmailScans([newScan, ...current]);
          return Promise.resolve({ data: newScan, error: null });
        }
        if (table === "payment_scan_results") {
          const current = this.getStoredPaymentScans();
          const newScan: PaymentScanRecord = {
            id: payload.id || "pscan-" + Math.random().toString(36).slice(2, 8),
            created_at: new Date().toISOString(),
            ...payload
          };
          this.setStoredPaymentScans([newScan, ...current]);
          return Promise.resolve({ data: newScan, error: null });
        }
        return Promise.resolve({ data: payload, error: null });
      }
    };
  };
}

// Export real client if configured, otherwise smart in-browser client
export const supabase = isLiveSupabaseConfigured
  ? createClient(envUrl!, envKey!)
  : (new LocalMockClient() as any);
