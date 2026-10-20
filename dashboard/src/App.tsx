import React, { useEffect, useState } from "react";
import { supabase, isLiveSupabaseConfigured } from "./lib/supabase";
import type { ScanRecord, UserPreferences } from "./lib/supabase";
import { Overview } from "./components/Overview";
import { RiskAnalytics } from "./components/RiskAnalytics";
import { AiInsights } from "./components/AiInsights";
import { ScanHistory } from "./components/ScanHistory";
import { ProfileSettings } from "./components/ProfileSettings";
import { EmailConnections } from "./components/EmailConnections";
import { EmailProtection } from "./components/EmailProtection";
import { NotificationSettings } from "./components/NotificationSettings";
import { PaymentVerification } from "./components/PaymentVerification";

type Tab =
  | "overview"
  | "payment-verification"
  | "email-connections"
  | "email-protection"
  | "notifications"
  | "analytics"
  | "insights"
  | "history"
  | "settings";

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<Tab>(() => {
    try {
      const params = new URLSearchParams(window.location.search);
      if (params.has("code") || params.has("error") || params.has("state")) {
        return "email-connections";
      }
    } catch {
      // fallback
    }
    return "overview";
  });
  const [user, setUser] = useState<{ id: string; email?: string } | null>(null);
  const [scans, setScans] = useState<ScanRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [preferences, setPreferences] = useState<UserPreferences>({
    save_scan_history: true,
    allow_ai_analysis: true,
    allow_anonymous_telemetry: false
  });

  // Auth modal states
  type AuthMode = "signin" | "register" | "forgot" | "reset";
  const [showAuthModal, setShowAuthModal] = useState(false);
  const [authMode, setAuthMode] = useState<AuthMode>("signin");
  const [authEmail, setAuthEmail] = useState("");
  const [authPassword, setAuthPassword] = useState("");
  const [resetCode, setResetCode] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [authError, setAuthError] = useState("");
  const [authSuccess, setAuthSuccess] = useState("");
  const [authLoading, setAuthLoading] = useState(false);

  useEffect(() => {
    // Check initial auth session
    supabase.auth.getSession().then(({ data }: any) => {
      const session = data?.session;
      if (session?.user) {
        setUser({ id: session.user.id, email: session.user.email });
        loadUserData(session.user.id);
      } else {
        setLoading(false);
      }
    });

    const { data: { subscription } } = supabase.auth.onAuthStateChange((_event: any, session: any) => {
      if (session?.user) {
        setUser({ id: session.user.id, email: session.user.email });
        loadUserData(session.user.id);
      } else {
        setUser(null);
        setScans([]);
        setLoading(false);
      }
    });

    return () => subscription.unsubscribe();
  }, []);

  const loadUserData = async (userId: string) => {
    setLoading(true);
    try {
      // 1. Load Scans
      const { data: scanData } = await supabase
        .from("scan_history")
        .select("*")
        .eq("user_id", userId)
        .order("created_at", { ascending: false });

      if (scanData) setScans(scanData as ScanRecord[]);

      // 2. Load Preferences
      const { data: prefData } = await supabase
        .from("user_preferences")
        .select("*")
        .eq("user_id", userId)
        .maybeSingle();

      if (prefData) {
        setPreferences({
          save_scan_history: prefData.save_scan_history ?? true,
          allow_ai_analysis: prefData.allow_ai_analysis ?? true,
          allow_anonymous_telemetry: prefData.allow_anonymous_telemetry ?? false
        });
      }
    } catch (err) {
      console.warn("Failed to query user data:", err);
    } finally {
      setLoading(false);
    }
  };

  const handleAuthSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setAuthError("");
    setAuthSuccess("");
    setAuthLoading(true);
    try {
      if (authMode === "register") {
        const { error } = await supabase.auth.signUp({
          email: authEmail,
          password: authPassword
        });
        if (error) throw error;
        setShowAuthModal(false);
      } else {
        const { error } = await supabase.auth.signInWithPassword({
          email: authEmail,
          password: authPassword
        });
        if (error) throw error;
        setShowAuthModal(false);
      }
    } catch (err: unknown) {
      setAuthError(err instanceof Error ? err.message : "Authentication failed");
    } finally {
      setAuthLoading(false);
    }
  };

  const handleForgotPasswordSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setAuthError("");
    setAuthSuccess("");
    setAuthLoading(true);
    try {
      const cleanEmail = authEmail.trim();
      if (!cleanEmail) throw new Error("Please enter your account email address.");

      const res = await supabase.auth.resetPasswordForEmail(cleanEmail);
      if (res.error) throw res.error;

      // Security: Never display or prefill verification codes in the browser UI
      setResetCode("");
      setAuthSuccess("If an account exists with this email address, password reset verification instructions have been dispatched to your email inbox.");
      setAuthMode("reset");
    } catch (err: unknown) {
      setAuthError(err instanceof Error ? err.message : "Failed to initiate password reset");
    } finally {
      setAuthLoading(false);
    }
  };

  const handleResetPasswordSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setAuthError("");
    setAuthSuccess("");
    setAuthLoading(true);
    try {
      if (!newPassword || newPassword.length < 6) {
        throw new Error("New password must be at least 6 characters.");
      }
      if (newPassword !== confirmPassword) {
        throw new Error("Passwords do not match.");
      }

      if (typeof (supabase.auth as any).updatePasswordWithCode === "function") {
        const { error } = await (supabase.auth as any).updatePasswordWithCode({
          email: authEmail,
          code: resetCode,
          newPassword
        });
        if (error) throw error;
      } else {
        const { error } = await supabase.auth.updateUser({ password: newPassword });
        if (error) throw error;
      }

      setAuthSuccess("Password updated successfully! Redirecting...");
      setTimeout(() => {
        setShowAuthModal(false);
        setAuthMode("signin");
        setAuthPassword("");
        setNewPassword("");
        setConfirmPassword("");
        setResetCode("");
      }, 1200);
    } catch (err: unknown) {
      setAuthError(err instanceof Error ? err.message : "Failed to update password");
    } finally {
      setAuthLoading(false);
    }
  };

  const handleDeleteScan = async (id: string) => {
    const { error } = await supabase.from("scan_history").delete().eq("id", id);
    if (!error) {
      setScans((prev) => prev.filter((s) => s.id !== id));
    } else {
      alert("Error deleting scan: " + error.message);
    }
  };

  const handleSubmitFeedback = async (scanId: string, feedbackType: "correct" | "false_positive" | "false_negative") => {
    if (!user) return;
    const { error } = await supabase.from("user_feedback").upsert({
      user_id: user.id,
      scan_id: scanId,
      feedback_type: feedbackType
    });
    if (error) throw error;
  };

  const handleUpdatePreferences = async (newPrefs: Partial<UserPreferences>) => {
    if (!user) return;
    const updated = { ...preferences, ...newPrefs };
    const { error } = await supabase
      .from("user_preferences")
      .upsert({ user_id: user.id, ...updated });

    if (error) throw error;
    setPreferences(updated);
  };

  const handleClearHistory = async () => {
    if (!user) return;
    const { error } = await supabase.from("scan_history").delete().eq("user_id", user.id);
    if (!error) {
      setScans([]);
      alert("All scan history cleared.");
    } else {
      alert("Error clearing history: " + error.message);
    }
  };

  const handleDeleteAccount = async () => {
    if (!user) return;
    await supabase.from("profiles").delete().eq("id", user.id);
    await supabase.auth.signOut();
    alert("Account deleted.");
  };

  const getTabLabel = (tab: Tab) => {
    switch (tab) {
      case "overview": return "Security Overview";
      case "payment-verification": return "Payment Scam Verification";
      case "email-connections": return "Connected Mailboxes";
      case "email-protection": return "Email Threat Protection";
      case "notifications": return "Alert & Delivery Settings";
      case "analytics": return "Threat Risk Analytics";
      case "insights": return "AI Threat Insights";
      case "history": return "Scan & Incident History";
      case "settings": return "System Settings";
    }
  };

  return (
    <div className="soc-layout">
      {/* Sidebar Navigation */}
      <aside className={`soc-sidebar ${sidebarOpen ? "open" : ""}`}>
        <div className="soc-brand">
          <span className="soc-logo-icon">🛡️</span>
          <div>
            <h1 className="soc-brand-title">ScamShield</h1>
            <p className="soc-brand-subtitle">SOC Command Center</p>
          </div>
        </div>

        <nav className="soc-nav">
          <span className="soc-nav-heading">Threat Operations</span>
          <button
            type="button"
            className={`soc-nav-btn ${activeTab === "overview" ? "active" : ""}`}
            onClick={() => { setActiveTab("overview"); setSidebarOpen(false); }}
          >
            <span className="soc-nav-icon">📊</span>
            <span>Dashboard Overview</span>
          </button>
          <button
            type="button"
            className={`soc-nav-btn ${activeTab === "payment-verification" ? "active" : ""}`}
            onClick={() => { setActiveTab("payment-verification"); setSidebarOpen(false); }}
          >
            <span className="soc-nav-icon">💳</span>
            <span>Payment Fraud Shield</span>
          </button>
          <button
            type="button"
            className={`soc-nav-btn ${activeTab === "email-connections" ? "active" : ""}`}
            onClick={() => { setActiveTab("email-connections"); setSidebarOpen(false); }}
          >
            <span className="soc-nav-icon">✉️</span>
            <span>Email Accounts</span>
          </button>
          <button
            type="button"
            className={`soc-nav-btn ${activeTab === "email-protection" ? "active" : ""}`}
            onClick={() => { setActiveTab("email-protection"); setSidebarOpen(false); }}
          >
            <span className="soc-nav-icon">🛡️</span>
            <span>Email Protection</span>
          </button>
          <button
            type="button"
            className={`soc-nav-btn ${activeTab === "notifications" ? "active" : ""}`}
            onClick={() => { setActiveTab("notifications"); setSidebarOpen(false); }}
          >
            <span className="soc-nav-icon">🔔</span>
            <span>Alert Notifications</span>
          </button>

          <span className="soc-nav-heading">Intelligence & Logs</span>
          <button
            type="button"
            className={`soc-nav-btn ${activeTab === "analytics" ? "active" : ""}`}
            onClick={() => { setActiveTab("analytics"); setSidebarOpen(false); }}
          >
            <span className="soc-nav-icon">📈</span>
            <span>Risk Analytics</span>
          </button>
          <button
            type="button"
            className={`soc-nav-btn ${activeTab === "insights" ? "active" : ""}`}
            onClick={() => { setActiveTab("insights"); setSidebarOpen(false); }}
          >
            <span className="soc-nav-icon">🧠</span>
            <span>AI Threat Insights</span>
          </button>
          <button
            type="button"
            className={`soc-nav-btn ${activeTab === "history" ? "active" : ""}`}
            onClick={() => { setActiveTab("history"); setSidebarOpen(false); }}
          >
            <span className="soc-nav-icon">📜</span>
            <span>Scan History</span>
          </button>

          <span className="soc-nav-heading">System</span>
          <button
            type="button"
            className={`soc-nav-btn ${activeTab === "settings" ? "active" : ""}`}
            onClick={() => { setActiveTab("settings"); setSidebarOpen(false); }}
          >
            <span className="soc-nav-icon">⚙️</span>
            <span>Preferences</span>
          </button>
        </nav>

        <div className="soc-sidebar-footer">
          <div className="soc-env-indicator">
            <span>Environment</span>
            <span style={{ color: isLiveSupabaseConfigured ? "#34d399" : "#38bdf8", display: "flex", alignItems: "center", gap: "6px" }}>
              <span>{isLiveSupabaseConfigured ? "🟢" : "⚡"}</span>
              {isLiveSupabaseConfigured ? "Cloud Active" : "Local Mode"}
            </span>
          </div>
        </div>
      </aside>

      {/* Main Container */}
      <div className="soc-main">
        {/* Top Header */}
        <header className="soc-header">
          <div className="soc-header-left">
            <button
              type="button"
              className="mobile-nav-toggle"
              onClick={() => setSidebarOpen(!sidebarOpen)}
              aria-label="Toggle Navigation"
            >
              ☰
            </button>
            <div className="soc-breadcrumb">
              <span>Threat Ops</span>
              <span>/</span>
              <strong>{getTabLabel(activeTab)}</strong>
            </div>
          </div>

          <div className="soc-search-wrap">
            <span>🔍</span>
            <input
              type="text"
              placeholder="Search threat indicators..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
          </div>

          <div className="soc-header-right">
            {user ? (
              <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                <span className="soc-user-pill">
                  <span>👤</span>
                  <span className="user-email-text">{user.email}</span>
                </span>
                <button
                  type="button"
                  className="btn btn-secondary"
                  style={{ padding: "6px 12px", fontSize: "12px" }}
                  onClick={async () => {
                    await supabase.auth.signOut();
                  }}
                >
                  Sign Out
                </button>
              </div>
            ) : (
              <button
                type="button"
                className="btn btn-primary"
                onClick={() => {
                  setAuthMode("signin");
                  setShowAuthModal(true);
                }}
              >
                Sign In / Register
              </button>
            )}
          </div>
        </header>

        {/* Content View */}
        <main className="soc-content">
          {loading ? (
            <div className="card" style={{ textAlign: "center", padding: "64px 20px" }}>
              <span style={{ fontSize: "36px", display: "block", marginBottom: "16px" }}>🛡️</span>
              <p style={{ color: "var(--text-muted)", fontSize: "14px" }}>Synchronizing threat telemetry…</p>
            </div>
          ) : !user ? (
            <div className="card" style={{ textAlign: "center", padding: "64px 24px", maxWidth: "600px", margin: "40px auto" }}>
              <span style={{ fontSize: "48px", filter: "drop-shadow(0 0 15px var(--accent-cyan))" }}>🛡️</span>
              <h2 style={{ fontSize: "22px", fontWeight: "800", color: "#f8fafc", marginTop: "16px" }}>
                ScamShield Command Center
              </h2>
              <p style={{ color: "var(--text-muted)", fontSize: "14px", lineHeight: "1.6", margin: "12px auto 24px auto" }}>
                Authenticate to access real-time fraud defense analytics, connect your mailbox for zero-day phishing detection, and audit suspicious UPI or payment requests.
              </p>
              <div style={{ display: "flex", justifyContent: "center", gap: "12px", flexWrap: "wrap" }}>
                <button
                  type="button"
                  className="btn btn-primary"
                  style={{ padding: "10px 24px" }}
                  onClick={() => {
                    setAuthMode("signin");
                    setShowAuthModal(true);
                  }}
                >
                  Sign In to SOC
                </button>
                <button
                  type="button"
                  className="btn btn-secondary"
                  style={{ padding: "10px 24px" }}
                  onClick={() => {
                    setAuthMode("register");
                    setShowAuthModal(true);
                  }}
                >
                  Create Account
                </button>
              </div>
            </div>
          ) : (
            <>
              {activeTab === "overview" && (
                <Overview scans={scans} onNavigateHistory={() => setActiveTab("history")} />
              )}
              {activeTab === "payment-verification" && (
                <PaymentVerification userId={user.id} />
              )}
              {activeTab === "email-connections" && (
                <EmailConnections userId={user.id} onRefreshScans={() => loadUserData(user.id)} />
              )}
              {activeTab === "email-protection" && (
                <EmailProtection userId={user.id} />
              )}
              {activeTab === "notifications" && (
                <NotificationSettings userId={user.id} />
              )}
              {activeTab === "analytics" && <RiskAnalytics scans={scans} />}
              {activeTab === "insights" && <AiInsights scans={scans} />}
              {activeTab === "history" && (
                <ScanHistory
                  scans={scans}
                  onDeleteScan={handleDeleteScan}
                  onSubmitFeedback={handleSubmitFeedback}
                />
              )}
              {activeTab === "settings" && (
                <ProfileSettings
                  userEmail={user.email || ""}
                  scans={scans}
                  preferences={preferences}
                  onUpdatePreferences={handleUpdatePreferences}
                  onClearHistory={handleClearHistory}
                  onDeleteAccount={handleDeleteAccount}
                  onSignOut={async () => {
                    await supabase.auth.signOut();
                  }}
                />
              )}
            </>
          )}
        </main>
      </div>

      {/* Auth Modal */}
      {showAuthModal && (
        <div className="modal-backdrop" onClick={() => setShowAuthModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            {authMode === "signin" && (
              <>
                <h2 style={{ fontSize: "18px", fontWeight: "800", color: "#f8fafc", marginBottom: "6px" }}>
                  Sign In to ScamShield
                </h2>
                <p style={{ fontSize: "13px", color: "var(--text-muted)", marginBottom: "18px" }}>
                  Access your threat defense console and synchronized scan history.
                </p>
              </>
            )}
            {authMode === "register" && (
              <>
                <h2 style={{ fontSize: "18px", fontWeight: "800", color: "#f8fafc", marginBottom: "6px" }}>
                  Create Security Account
                </h2>
                <p style={{ fontSize: "13px", color: "var(--text-muted)", marginBottom: "18px" }}>
                  Deploy ScamShield cloud intelligence and alert notifications.
                </p>
              </>
            )}
            {authMode === "forgot" && (
              <>
                <h2 style={{ fontSize: "18px", fontWeight: "800", color: "#f8fafc", marginBottom: "6px" }}>
                  Account Password Recovery
                </h2>
                <p style={{ fontSize: "13px", color: "var(--text-muted)", marginBottom: "18px" }}>
                  Enter your email address to receive secure password recovery instructions.
                </p>
              </>
            )}
            {authMode === "reset" && (
              <>
                <h2 style={{ fontSize: "18px", fontWeight: "800", color: "#f8fafc", marginBottom: "6px" }}>
                  Enter Verification Code & New Password
                </h2>
                <p style={{ fontSize: "13px", color: "var(--text-muted)", marginBottom: "18px" }}>
                  Enter the recovery code sent to your inbox and specify your new password.
                </p>
              </>
            )}

            {authError && (
              <div style={{ padding: "10px 14px", background: "rgba(239, 68, 68, 0.15)", border: "1px solid #ef4444", borderRadius: "6px", color: "#fca5a5", fontSize: "13px", marginBottom: "14px" }}>
                ⚠️ {authError}
              </div>
            )}
            {authSuccess && (
              <div style={{ padding: "10px 14px", background: "rgba(16, 185, 129, 0.15)", border: "1px solid #10b981", borderRadius: "6px", color: "#6ee7b7", fontSize: "13px", marginBottom: "14px" }}>
                ✓ {authSuccess}
              </div>
            )}

            {authMode === "forgot" ? (
              <form onSubmit={handleForgotPasswordSubmit}>
                <div style={{ marginBottom: "14px" }}>
                  <label style={{ display: "block", fontSize: "12px", fontWeight: "600", color: "#cbd5e1", marginBottom: "4px" }}>
                    Account Email Address
                  </label>
                  <input
                    type="email"
                    required
                    className="input-field"
                    value={authEmail}
                    onChange={(e) => setAuthEmail(e.target.value)}
                    placeholder="user@example.com"
                  />
                </div>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginTop: "18px" }}>
                  <button type="button" className="btn btn-ghost" onClick={() => setAuthMode("signin")}>
                    ← Back to Sign In
                  </button>
                  <button type="submit" className="btn btn-primary" disabled={authLoading}>
                    {authLoading ? "Sending Code..." : "Send Reset Code"}
                  </button>
                </div>
              </form>
            ) : authMode === "reset" ? (
              <form onSubmit={handleResetPasswordSubmit}>
                <div style={{ marginBottom: "14px" }}>
                  <label style={{ display: "block", fontSize: "12px", fontWeight: "600", color: "#cbd5e1", marginBottom: "4px" }}>
                    Verification Code (from Email)
                  </label>
                  <input
                    type="text"
                    required
                    className="input-field"
                    value={resetCode}
                    onChange={(e) => setResetCode(e.target.value)}
                    placeholder="Enter code"
                  />
                </div>
                <div style={{ marginBottom: "14px" }}>
                  <label style={{ display: "block", fontSize: "12px", fontWeight: "600", color: "#cbd5e1", marginBottom: "4px" }}>
                    New Password
                  </label>
                  <input
                    type="password"
                    required
                    minLength={6}
                    className="input-field"
                    value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)}
                    placeholder="At least 6 characters"
                  />
                </div>
                <div style={{ marginBottom: "14px" }}>
                  <label style={{ display: "block", fontSize: "12px", fontWeight: "600", color: "#cbd5e1", marginBottom: "4px" }}>
                    Confirm New Password
                  </label>
                  <input
                    type="password"
                    required
                    minLength={6}
                    className="input-field"
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    placeholder="Repeat new password"
                  />
                </div>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginTop: "18px" }}>
                  <button type="button" className="btn btn-ghost" onClick={() => setAuthMode("signin")}>
                    ← Cancel
                  </button>
                  <button type="submit" className="btn btn-primary" disabled={authLoading}>
                    {authLoading ? "Updating..." : "Update Password"}
                  </button>
                </div>
              </form>
            ) : (
              <form onSubmit={handleAuthSubmit}>
                <div style={{ marginBottom: "14px" }}>
                  <label style={{ display: "block", fontSize: "12px", fontWeight: "600", color: "#cbd5e1", marginBottom: "4px" }}>
                    Email Address
                  </label>
                  <input
                    type="email"
                    required
                    className="input-field"
                    value={authEmail}
                    onChange={(e) => setAuthEmail(e.target.value)}
                    placeholder="you@domain.com"
                  />
                </div>
                <div style={{ marginBottom: "14px" }}>
                  <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "4px" }}>
                    <label style={{ fontSize: "12px", fontWeight: "600", color: "#cbd5e1" }}>Password</label>
                    {authMode === "signin" && (
                      <button
                        type="button"
                        onClick={() => setAuthMode("forgot")}
                        style={{ background: "none", border: "none", color: "var(--accent-cyan)", fontSize: "11px", cursor: "pointer" }}
                      >
                        Forgot password?
                      </button>
                    )}
                  </div>
                  <input
                    type="password"
                    required
                    minLength={6}
                    className="input-field"
                    value={authPassword}
                    onChange={(e) => setAuthPassword(e.target.value)}
                    placeholder="Password (min 6 characters)"
                  />
                </div>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginTop: "20px" }}>
                  <button
                    type="button"
                    className="btn btn-ghost"
                    onClick={() => setAuthMode(authMode === "signin" ? "register" : "signin")}
                  >
                    {authMode === "signin" ? "Need an account? Register" : "Have an account? Sign in"}
                  </button>
                  <button type="submit" className="btn btn-primary" disabled={authLoading}>
                    {authLoading ? "Processing..." : authMode === "signin" ? "Sign In" : "Register"}
                  </button>
                </div>
              </form>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
