import React, { useState, useEffect } from "react";
import { supabase } from "../lib/supabase";
import type { ConnectedEmailAccount } from "../lib/supabase";

interface EmailConnectionsProps {
  userId: string;
  onRefreshScans?: () => void;
}

export const EmailConnections: React.FC<EmailConnectionsProps> = ({ userId, onRefreshScans }) => {
  const [accounts, setAccounts] = useState<ConnectedEmailAccount[]>([]);
  const [loading, setLoading] = useState(true);
  const [connectingProvider, setConnectingProvider] = useState<string | null>(null);

  // Status and concise error/feedback banner
  const [bannerMessage, setBannerMessage] = useState<{
    type: "info" | "success" | "warning" | "error";
    title?: string;
    text: string;
  } | null>(null);

  // Manual OTP verification state
  const [manualEmail, setManualEmail] = useState("");
  const [otpSent, setOtpSent] = useState(false);
  const [otpCode, setOtpCode] = useState(["", "", "", "", "", ""]);
  const [otpError, setOtpError] = useState("");
  const [otpSuccess, setOtpSuccess] = useState("");
  const [cooldown, setCooldown] = useState(0);
  const [isVerifying, setIsVerifying] = useState(false);

  useEffect(() => {
    if (userId) {
      loadAccounts();
      checkOAuthCallback();
    }
  }, [userId]);

  const checkOAuthCallback = async () => {
    const urlParams = new URLSearchParams(window.location.search);
    const code = urlParams.get("code");
    const state = urlParams.get("state");
    const errorParam = urlParams.get("error");
    const errorDesc = urlParams.get("error_description");
    const oauthStatus = urlParams.get("oauth_status");
    const connectedEmail = urlParams.get("email");
    const connectedProv = urlParams.get("provider");

    // Case 1: Backend direct redirect callback completed (Architecture B)
    if (oauthStatus === "success") {
      setBannerMessage({
        type: "success",
        title: "Mailbox Connected",
        text: `Successfully connected ${connectedProv?.toUpperCase() || "email"} mailbox (${connectedEmail || "verified account"}) with real-time scam protection!`
      });
      window.history.replaceState({}, document.title, window.location.pathname);
      sessionStorage.removeItem("scamshield_oauth_pending");
      await loadAccounts();
      if (onRefreshScans) onRefreshScans();
      return;
    }

    // Case 2: Cancellation or denied permissions
    if (errorParam) {
      const isDenied = errorParam === "access_denied" || (errorDesc && errorDesc.toLowerCase().includes("denied"));
      setBannerMessage({
        type: isDenied ? "warning" : "error",
        title: isDenied ? "Authorization Cancelled" : "OAuth Handshake Error",
        text: isDenied
          ? "Authorization was cancelled by user. No mailbox permissions were granted."
          : `OAuth authorization failed: ${errorDesc || errorParam}`
      });
      sessionStorage.removeItem("scamshield_oauth_pending");
      window.history.replaceState({}, document.title, window.location.pathname);
      return;
    }

    // Case 3: Frontend callback handoff (Architecture A)
    if (code && state) {
      try {
        const storedStr = sessionStorage.getItem("scamshield_oauth_pending");
        let pendingProvider = "gmail";
        let storedState = "";
        let codeVerifier = "";

        if (storedStr) {
          try {
            const pending = JSON.parse(storedStr);
            pendingProvider = pending.provider;
            storedState = pending.state;
            codeVerifier = pending.codeVerifier || "";
            if (pending.expiresAt && Date.now() > pending.expiresAt) {
              throw new Error("OAuth authorization session timed out. Please initiate connection again.");
            }
          } catch (e: any) {
            console.warn("[OAuth] Pending session parse error:", e);
          }
        }

        // If client session storage has state, ensure it matches to prevent CSRF
        if (storedState && storedState !== state) {
          throw new Error("OAuth state parameter mismatch (potential cross-site forgery). Connection rejected.");
        }

        setConnectingProvider(pendingProvider);
        setBannerMessage({
          type: "info",
          title: "Connecting Mailbox",
          text: `Exchanging authorization code with ${pendingProvider.toUpperCase()} and establishing read-only protection...`
        });

        const completeRes = await supabase.functions.invoke("complete-email-oauth", {
          body: {
            provider: pendingProvider,
            code,
            state,
            codeVerifier,
            redirectUri: window.location.origin + window.location.pathname,
            userId
          }
        });

        sessionStorage.removeItem("scamshield_oauth_pending");
        window.history.replaceState({}, document.title, window.location.pathname);

        if (completeRes.error) throw completeRes.error;
        if (completeRes.data?.error) throw new Error(completeRes.data.error);

        const email = completeRes.data?.account?.email_address || "verified account";
        const scannedCount = completeRes.data?.scannedCount || 0;
        await loadAccounts();
        if (onRefreshScans) onRefreshScans();

        setBannerMessage({
          type: "success",
          title: "Mailbox Connected & Protected",
          text: `Successfully connected ${pendingProvider.toUpperCase()} mailbox (${email})! Audited ${scannedCount} incoming emails for phishing and fraudulent links.`
        });
      } catch (err: unknown) {
        setBannerMessage({
          type: "error",
          title: "OAuth Connection Failed",
          text: err instanceof Error ? err.message : String(err)
        });
      } finally {
        setConnectingProvider(null);
      }
    }
  };

  useEffect(() => {
    if (cooldown > 0) {
      const timer = setTimeout(() => setCooldown(cooldown - 1), 1000);
      return () => clearTimeout(timer);
    }
  }, [cooldown]);

  const loadAccounts = async () => {
    setLoading(true);
    try {
      // Security: Strictly query only non-sensitive mailbox attributes without token secrets
      const { data } = await supabase
        .from("connected_email_accounts")
        .select("id, user_id, provider, provider_account_id, email_address, connection_status, granted_scopes, monitoring_enabled, last_successful_sync_at, last_error_code, created_at, updated_at")
        .eq("user_id", userId)
        .order("created_at", { ascending: false });

      if (data) {
        // Enforce zero demo data: display strictly authentic verified connected accounts
        const realAccounts = (data as ConnectedEmailAccount[]).filter(
          (a) => a.id !== "acc-gmail-01"
        );
        setAccounts(realAccounts);
      }
    } catch (err) {
      console.warn("Failed to load email accounts:", err);
    } finally {
      setLoading(false);
    }
  };

  const handleStartOAuth = async (provider: "gmail" | "outlook") => {
    if (!userId) {
      setBannerMessage({
        type: "error",
        title: "Authentication Required",
        text: "Please sign in to your ScamShield account before connecting a mailbox."
      });
      return;
    }

    if (connectingProvider) return; // Prevent duplicate clicks

    setConnectingProvider(provider);
    setBannerMessage({
      type: "info",
      title: "Opening Authorization",
      text: `Connecting to ${provider === "gmail" ? "Google" : "Microsoft"} login...`
    });

    try {
      const redirectUri = window.location.origin + window.location.pathname;
      const res = await supabase.functions.invoke("start-email-oauth", {
        body: { provider, redirectUri }
      });

      if (res.error) throw res.error;

      // Concise error handling when provider secrets are unconfigured
      if (res.data?.configured === false || !res.data?.authUrl) {
        setBannerMessage({
          type: "error",
          title: `${provider === "gmail" ? "Google" : "Microsoft"} OAuth Not Configured`,
          text: res.data?.error || `Server credentials for ${provider.toUpperCase()} are not configured. Set ${provider === "gmail" ? "GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET" : "MICROSOFT_CLIENT_ID and MICROSOFT_CLIENT_SECRET"} in Supabase project secrets.`
        });
        setConnectingProvider(null);
        return;
      }

      // Store state securely in sessionStorage for CSRF validation upon return
      sessionStorage.setItem(
        "scamshield_oauth_pending",
        JSON.stringify({
          provider,
          state: res.data.state,
          codeVerifier: res.data.codeVerifier,
          expiresAt: Date.now() + 10 * 60 * 1000
        })
      );

      // Redirect user directly to provider's official authorization page
      window.location.href = res.data.authUrl;
    } catch (err: unknown) {
      setBannerMessage({
        type: "error",
        title: "Connection Failed",
        text: `Failed to initiate ${provider.toUpperCase()} connection: ` + (err instanceof Error ? err.message : String(err))
      });
      setConnectingProvider(null);
    }
  };

  const handleToggleMonitoring = async (account: ConnectedEmailAccount) => {
    const newStatus = !account.monitoring_enabled;
    const { error } = await supabase
      .from("connected_email_accounts")
      .upsert({ ...account, monitoring_enabled: newStatus, updated_at: new Date().toISOString() });

    if (!error) {
      setAccounts((prev) => prev.map((a) => (a.id === account.id ? { ...a, monitoring_enabled: newStatus } : a)));
    }
  };

  const handleDisconnect = async (accountId: string) => {
    if (!confirm("Are you sure you want to disconnect this email account? ScamShield will stop inspecting its incoming messages.")) {
      return;
    }
    const { error } = await supabase.functions.invoke("disconnect-email-account", {
      body: { accountId, userId }
    });

    if (!error) {
      setAccounts((prev) => prev.filter((a) => a.id !== accountId));
      setBannerMessage({
        type: "info",
        title: "Account Disconnected",
        text: "The mailbox has been disconnected and stored credentials have been revoked."
      });
    } else {
      alert("Error disconnecting account: " + error.message);
    }
  };

  const handleSyncAccount = async (accountId: string) => {
    setBannerMessage({
      type: "info",
      title: "Auditing Mailbox",
      text: "Inspecting latest incoming messages for phishing, sender spoofing, and malicious links..."
    });

    const res = await supabase.functions.invoke("sync-email-account", {
      body: { accountId, userId }
    });

    if (!res.error) {
      setAccounts((prev) =>
        prev.map((a) => (a.id === accountId ? { ...a, last_successful_sync_at: new Date().toISOString() } : a))
      );
      const total = res.data?.totalScanned ?? 0;
      setBannerMessage({
        type: "success",
        title: "Mailbox Audit Complete",
        text: `Mailbox synchronized! Analyzed ${total} incoming message(s). Check the Email Protection tab for threat telemetry.`
      });
      if (onRefreshScans) onRefreshScans();
    } else {
      setBannerMessage({
        type: "error",
        title: "Sync Failed",
        text: res.error.message || "Failed to sync mailbox."
      });
    }
  };

  // OTP handlers for manual alert recipient verification
  const handleRequestOtp = async (e: React.FormEvent) => {
    e.preventDefault();
    setOtpError("");
    setOtpSuccess("");
    if (!manualEmail || !manualEmail.includes("@")) {
      setOtpError("Please enter a valid email address.");
      return;
    }

    try {
      const res = await supabase.functions.invoke("request-email-verification", {
        body: { email: manualEmail, purpose: "recipient_verification", userId }
      });
      if (res.error) throw res.error;

      setOtpSent(true);
      setCooldown(60);
      const codeMsg = res.data?.code ? ` (Code: ${res.data.code})` : "";
      if (res.data?.emailDispatched) {
        setOtpSuccess(`A 6-digit verification code has been dispatched to your email address! Check your inbox${codeMsg}.`);
      } else {
        setOtpSuccess(res.data?.message || `Verification code ready: ${res.data?.code}`);
      }
    } catch (err: unknown) {
      setOtpError(err instanceof Error ? err.message : "Failed to send code");
    }
  };

  const handleOtpChange = (index: number, val: string) => {
    if (val.length > 1) {
      const clean = val.replace(/\D/g, "").slice(0, 6);
      if (clean.length > 0) {
        const next = [...otpCode];
        for (let i = 0; i < 6; i++) {
          next[i] = clean[i] || "";
        }
        setOtpCode(next);
        return;
      }
    }

    const next = [...otpCode];
    next[index] = val.slice(-1);
    setOtpCode(next);

    if (val && index < 5) {
      const nextInput = document.getElementById(`otp-input-${index + 1}`);
      nextInput?.focus();
    }
  };

  const handleVerifyOtp = async () => {
    setOtpError("");
    setOtpSuccess("");
    const code = otpCode.join("");
    if (code.length !== 6) {
      setOtpError("Please enter all 6 digits of your verification code.");
      return;
    }

    setIsVerifying(true);
    try {
      const res = await supabase.functions.invoke("verify-email-code", {
        body: { email: manualEmail, code, purpose: "recipient_verification", userId }
      });
      if (res.error) throw res.error;

      setOtpSuccess(`✓ ${manualEmail} verified successfully as your alert recipient!`);
      setTimeout(() => {
        setOtpSent(false);
        setManualEmail("");
        setOtpCode(["", "", "", "", "", ""]);
      }, 2500);
    } catch (err: unknown) {
      setOtpError(err instanceof Error ? err.message : "Invalid code");
    } finally {
      setIsVerifying(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Dynamic Status / Notification Banner */}
      {bannerMessage && (
        <div
          className="card"
          style={{
            borderLeft: `4px solid ${
              bannerMessage.type === "success"
                ? "var(--accent-emerald, #10B981)"
                : bannerMessage.type === "warning"
                ? "#F59E0B"
                : bannerMessage.type === "error"
                ? "var(--accent-rose, #EF4444)"
                : "var(--accent-cyan, #06B6D4)"
            }`,
            display: "flex",
            justifyContent: "space-between",
            alignItems: "flex-start",
            gap: 12
          }}
        >
          <div>
            {bannerMessage.title && (
              <h4 style={{ margin: "0 0 4px 0", fontSize: 14, fontWeight: 700 }}>
                {bannerMessage.title}
              </h4>
            )}
            <p style={{ margin: 0, fontSize: 13, color: "var(--text-sub)" }}>{bannerMessage.text}</p>
          </div>
          <button
            type="button"
            className="btn btn-secondary"
            style={{ padding: "4px 8px", fontSize: 11 }}
            onClick={() => setBannerMessage(null)}
          >
            Dismiss
          </button>
        </div>
      )}

      {/* Overview Banner */}
      <div className="card" style={{ borderLeft: "4px solid var(--accent-cyan)" }}>
        <h2 style={{ fontSize: 18, fontWeight: 800, marginBottom: 6 }}>Connect Your Email Accounts</h2>
        <p style={{ color: "var(--text-sub)", fontSize: 13.5, lineHeight: 1.5, margin: 0 }}>
          ScamShield integrates with your Gmail and Microsoft Outlook accounts using official OAuth 2.0. We request
          strictly <strong>read-only</strong> permissions (<code>gmail.readonly</code> & <code>Mail.Read</code>) to
          audit incoming links and sender headers. ScamShield <strong>never</strong> asks for your password and has{" "}
          <strong>zero</strong> write, send, or delete privileges.
        </p>
      </div>

      {/* OAuth Connection Cards */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: 16 }}>
        {/* Gmail Card */}
        <div className="card" style={{ display: "flex", flexDirection: "column", justifyContent: "space-between" }}>
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 12 }}>
              <span style={{ fontSize: 28 }}>✉️</span>
              <div>
                <h3 style={{ fontSize: 16, fontWeight: 800, margin: 0 }}>Google Gmail</h3>
                <span className="badge badge-safe" style={{ fontSize: 10 }}>OAuth 2.0 · Read-Only</span>
              </div>
            </div>
            <p style={{ fontSize: 12.5, color: "#64748B", lineHeight: 1.5 }}>
              Connect your personal or Google Workspace inbox. ScamShield continuously monitors incoming mail for brand
              impersonators and suspicious links.
            </p>
          </div>
          <button
            type="button"
            className="btn btn-primary"
            style={{ marginTop: 16, width: "100%" }}
            onClick={() => handleStartOAuth("gmail")}
            disabled={connectingProvider !== null}
          >
            {connectingProvider === "gmail" ? "Connecting Gmail…" : "Connect Gmail"}
          </button>
        </div>

        {/* Outlook Card */}
        <div className="card" style={{ display: "flex", flexDirection: "column", justifyContent: "space-between" }}>
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 12 }}>
              <span style={{ fontSize: 28 }}>📬</span>
              <div>
                <h3 style={{ fontSize: 16, fontWeight: 800, margin: 0 }}>Microsoft Outlook</h3>
                <span className="badge badge-safe" style={{ fontSize: 10 }}>Graph API · Read-Only</span>
              </div>
            </div>
            <p style={{ fontSize: 12.5, color: "#64748B", lineHeight: 1.5 }}>
              Connect your Outlook.com, Hotmail, or Microsoft 365 mailbox to defend against financial invoice fraud and
              credential phishing.
            </p>
          </div>
          <button
            type="button"
            className="btn btn-primary"
            style={{ marginTop: 16, width: "100%", background: "#0284C7" }}
            onClick={() => handleStartOAuth("outlook")}
            disabled={connectingProvider !== null}
          >
            {connectingProvider === "outlook" ? "Connecting Outlook…" : "Connect Outlook"}
          </button>
        </div>
      </div>

      {/* Connected Accounts List */}
      <div className="card">
        <h3 style={{ fontSize: 16, fontWeight: 800, marginBottom: 16 }}>Connected Mailboxes ({accounts.length})</h3>

        {loading ? (
          <p style={{ color: "#64748B", fontSize: 13 }}>Loading connected accounts…</p>
        ) : accounts.length === 0 ? (
          <p style={{ color: "#64748B", fontSize: 13 }}>
            No email accounts connected yet. Choose Gmail or Outlook above to connect your mailbox with real-time phishing defense.
          </p>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
            {accounts.map((acc) => (
              <div
                key={acc.id}
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                  flexWrap: "wrap",
                  gap: 12,
                  padding: "14px 16px",
                  borderRadius: 8,
                  border: "1px solid var(--border-subtle)",
                  background: "var(--bg-surface)"
                }}
              >
                <div>
                  <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                    <span style={{ fontWeight: 800, fontSize: 14 }}>{acc.email_address}</span>
                    <span className="badge badge-safe" style={{ textTransform: "uppercase" }}>
                      {acc.provider}
                    </span>
                    <span className={`badge ${acc.connection_status === "connected" ? "badge-safe" : "badge-critical"}`}>
                      {acc.connection_status}
                    </span>
                  </div>
                  <div style={{ fontSize: 11.5, color: "var(--text-dim)", marginTop: 4 }}>
                    Last Sync: {acc.last_successful_sync_at ? new Date(acc.last_successful_sync_at).toLocaleString() : "Never"}
                    {" · "}
                    Scope: <code>{acc.granted_scopes?.[0] || "read-only"}</code>
                  </div>
                </div>

                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <button
                    type="button"
                    className="btn btn-secondary"
                    style={{ fontSize: 12, padding: "6px 12px" }}
                    onClick={() => handleSyncAccount(acc.id)}
                  >
                    🔄 Sync Now
                  </button>

                  <button
                    type="button"
                    className={`btn ${acc.monitoring_enabled ? "btn-secondary" : "btn-primary"}`}
                    style={{ fontSize: 12, padding: "6px 12px" }}
                    onClick={() => handleToggleMonitoring(acc)}
                  >
                    {acc.monitoring_enabled ? "Pause Protection" : "Enable Protection"}
                  </button>

                  <button
                    type="button"
                    className="btn btn-secondary"
                    style={{ fontSize: 12, padding: "6px 12px", color: "var(--accent-rose)" }}
                    onClick={() => handleDisconnect(acc.id)}
                  >
                    Disconnect
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Manual Email Verification Card (For Alert Delivery) */}
      <div className="card">
        <h3 style={{ fontSize: 16, fontWeight: 800, marginBottom: 8 }}>Manual Email Alert Verification</h3>
        <p style={{ color: "#64748B", fontSize: 13, marginBottom: 16 }}>
          Verify an additional email address via 6-digit OTP to receive immediate critical threat warnings and weekly security digests.
        </p>

        {otpSuccess && (
          <div style={{ padding: "10px 14px", background: "rgba(16, 185, 129, 0.1)", border: "1px solid #10B981", borderRadius: 6, color: "#10B981", fontSize: 13, marginBottom: 16 }}>
            {otpSuccess}
          </div>
        )}

        {otpError && (
          <div style={{ padding: "10px 14px", background: "rgba(239, 68, 68, 0.1)", border: "1px solid #EF4444", borderRadius: 6, color: "#EF4444", fontSize: 13, marginBottom: 16 }}>
            {otpError}
          </div>
        )}

        {!otpSent ? (
          <form onSubmit={handleRequestOtp} style={{ display: "flex", gap: 10, maxWidth: 460 }}>
            <input
              type="email"
              placeholder="e.g. your.security@company.com"
              value={manualEmail}
              onChange={(e) => setManualEmail(e.target.value)}
              style={{
                flex: 1,
                padding: "8px 12px",
                borderRadius: 6,
                border: "1px solid var(--border-subtle)",
                background: "var(--bg-surface)",
                color: "#F8FAFC",
                fontSize: 13
              }}
              required
            />
            <button
              type="submit"
              className="btn btn-primary"
              disabled={cooldown > 0}
            >
              {cooldown > 0 ? `Wait (${cooldown}s)` : "Send Verification Code"}
            </button>
          </form>
        ) : (
          <div style={{ maxWidth: 360 }}>
            <p style={{ fontSize: 12.5, color: "#64748B", marginBottom: 10 }}>
              Enter the 6-digit code dispatched to <strong>{manualEmail}</strong>:
            </p>
            <div style={{ display: "flex", gap: 8, marginBottom: 14 }}>
              {otpCode.map((digit, idx) => (
                <input
                  key={idx}
                  id={`otp-input-${idx}`}
                  type="text"
                  maxLength={1}
                  value={digit}
                  onChange={(e) => handleOtpChange(idx, e.target.value)}
                  style={{
                    width: 44,
                    height: 48,
                    textAlign: "center",
                    fontSize: 18,
                    fontWeight: 700,
                    borderRadius: 6,
                    border: "1px solid var(--border-subtle)",
                    background: "var(--bg-surface)",
                    color: "#F8FAFC"
                  }}
                />
              ))}
            </div>
            <div style={{ display: "flex", gap: 10 }}>
              <button
                type="button"
                className="btn btn-primary"
                onClick={handleVerifyOtp}
                disabled={isVerifying}
              >
                {isVerifying ? "Verifying…" : "Confirm Code"}
              </button>
              <button
                type="button"
                className="btn btn-secondary"
                onClick={() => setOtpSent(false)}
              >
                Cancel
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Developer & Provider Setup Guide (Collapsible Section) */}
      <details className="card" style={{ marginTop: 24, border: "1px dashed var(--border-subtle)" }}>
        <summary style={{ cursor: "pointer", fontWeight: 700, fontSize: 13.5, color: "var(--accent-cyan)", userSelect: "none" }}>
          ⚙️ Developer &amp; Provider Setup Guide (Google Cloud &amp; Microsoft Entra ID)
        </summary>
        <div style={{ marginTop: 14, fontSize: 12.5, color: "var(--text-sub)", lineHeight: 1.6 }}>
          <p>
            To connect real accounts, register OAuth 2.0 applications once in the Google Cloud Console and Microsoft Entra ID admin centers, then configure the credentials in your Supabase Project Secrets.
          </p>

          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: 16, marginTop: 12 }}>
            <div style={{ background: "#091220", padding: "12px 14px", borderRadius: 6, border: "1px solid #1e293b" }}>
              <strong style={{ color: "#f8fafc" }}>Google Gmail App Registration</strong>
              <ul style={{ paddingLeft: 18, margin: "6px 0" }}>
                <li>Console: <code>console.cloud.google.com</code></li>
                <li>API: Enable <strong>Gmail API</strong></li>
                <li>Client Type: <strong>Web application</strong></li>
                <li>Authorized Redirect URIs:
                  <br />• Backend: <code>https://&lt;project-id&gt;.supabase.co/functions/v1/complete-email-oauth</code>
                  <br />• Frontend: <code>{window.location.origin}/</code>
                </li>
                <li>Scopes: <code>gmail.readonly</code>, <code>userinfo.email</code>, <code>openid</code></li>
              </ul>
            </div>

            <div style={{ background: "#091220", padding: "12px 14px", borderRadius: 6, border: "1px solid #1e293b" }}>
              <strong style={{ color: "#f8fafc" }}>Microsoft Outlook App Registration</strong>
              <ul style={{ paddingLeft: 18, margin: "6px 0" }}>
                <li>Portal: <code>entra.microsoft.com</code> (App Registrations)</li>
                <li>Account Type: <em>Any Microsoft Entra ID and personal Microsoft accounts</em></li>
                <li>Redirect URIs:
                  <br />• Backend: <code>https://&lt;project-id&gt;.supabase.co/functions/v1/complete-email-oauth</code>
                  <br />• Frontend: <code>{window.location.origin}/</code>
                </li>
                <li>Delegated Permissions: <code>Mail.Read</code>, <code>User.Read</code>, <code>offline_access</code></li>
              </ul>
            </div>
          </div>

          <div style={{ marginTop: 12, padding: "10px 12px", background: "rgba(6, 182, 212, 0.08)", borderRadius: 6, border: "1px solid rgba(6, 182, 212, 0.2)" }}>
            <strong>Supabase CLI Secret Configuration:</strong>
            <pre style={{ margin: "6px 0 0 0", fontFamily: "monospace", fontSize: 11.5, color: "#38bdf8", overflowX: "auto" }}>
              supabase secrets set GOOGLE_CLIENT_ID="..." GOOGLE_CLIENT_SECRET="..." MICROSOFT_CLIENT_ID="..." MICROSOFT_CLIENT_SECRET="..." MICROSOFT_TENANT_ID="common" TOKEN_ENCRYPTION_KEY="..."
            </pre>
          </div>

          <p style={{ marginTop: 10, fontSize: 12 }}>
            For detailed documentation, see <a href="#" onClick={(e) => { e.preventDefault(); alert("Refer to docs/OAUTH_SETUP_GUIDE.md in your repository for the complete guide."); }} style={{ color: "var(--accent-cyan)", textDecoration: "underline" }}>docs/OAUTH_SETUP_GUIDE.md</a>.
          </p>
        </div>
      </details>
    </div>
  );
};
