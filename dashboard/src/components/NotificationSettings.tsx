import React, { useState, useEffect } from "react";
import { supabase } from "../lib/supabase";
import type { NotificationPreferences, NotificationDeliveryLog } from "../lib/supabase";

interface NotificationSettingsProps {
  userId: string;
}

export const NotificationSettings: React.FC<NotificationSettingsProps> = ({ userId }) => {
  const [prefs, setPrefs] = useState<NotificationPreferences>({
    user_id: userId,
    recipient_email: "user.security@gmail.com",
    recipient_verified: true,
    suspicious_email_alerts: true,
    critical_risk_alerts: true,
    account_security_alerts: true,
    connection_status_alerts: true,
    weekly_summary: true,
    updated_at: new Date().toISOString()
  });

  const [logs, setLogs] = useState<NotificationDeliveryLog[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [saveMessage, setSaveMessage] = useState("");
  const [testingAlert, setTestingAlert] = useState(false);

  useEffect(() => {
    loadSettings();
  }, [userId]);

  const loadSettings = async () => {
    setLoading(true);
    try {
      // 1. Load preferences
      const { data: prefData } = await supabase
        .from("notification_preferences")
        .select("*")
        .eq("user_id", userId)
        .maybeSingle();

      if (prefData) setPrefs(prefData as NotificationPreferences);

      // 2. Load delivery logs
      const { data: logData } = await supabase
        .from("notification_delivery_log")
        .select("*")
        .eq("user_id", userId)
        .order("created_at", { ascending: false });

      if (logData) setLogs(logData as NotificationDeliveryLog[]);
    } catch (err) {
      console.warn("Failed to load notification settings:", err);
    } finally {
      setLoading(false);
    }
  };

  const handleToggle = (key: keyof NotificationPreferences) => {
    setPrefs((prev) => ({ ...prev, [key]: !prev[key] }));
  };

  const handleSave = async () => {
    setSaving(true);
    setSaveMessage("");
    try {
      const { error } = await supabase
        .from("notification_preferences")
        .upsert({ ...prefs, updated_at: new Date().toISOString() });

      if (error) throw error;
      setSaveMessage("Notification preferences saved successfully.");
      setTimeout(() => setSaveMessage(""), 3000);
    } catch (err: unknown) {
      alert("Failed to save preferences: " + (err instanceof Error ? err.message : String(err)));
    } finally {
      setSaving(false);
    }
  };

  const handleSendTestAlert = async () => {
    setTestingAlert(true);
    try {
      const res = await supabase.functions.invoke("process-email-notification", {
        body: {
          userId,
          notificationType: "high_risk_alert",
          payload: {
            sender: "Paytm Security <alert-support@paytrn-security.xyz>",
            subject: "[TEST ALERT] Suspicious Phishing Attempt Filtered",
            riskScore: 95,
            riskLevel: "critical",
            explanation: "This is a verified test alert dispatched from your ScamShield protection suite.",
            indicators: [{ description: "Simulated credential harvesting threat vector" }],
            recommendations: ["No action required. Your email notification pipeline is operational."],
            detectedAt: new Date().toUTCString(),
            fingerprint: "test_alert_" + Date.now()
          }
        }
      });

      if (res.error) throw res.error;
      await loadSettings();
      alert(`Test alert dispatched successfully to ${prefs.recipient_email}! Check delivery log below.`);
    } catch (err: unknown) {
      alert("Test alert failed: " + (err instanceof Error ? err.message : String(err)));
    } finally {
      setTestingAlert(false);
    }
  };

  const handleSendWeeklySummary = async () => {
    try {
      const res = await supabase.functions.invoke("send-weekly-security-summary", {
        body: { userId }
      });
      if (res.error) throw res.error;
      await loadSettings();
      alert("Weekly security summary generated and recorded in delivery log!");
    } catch (err: unknown) {
      alert("Weekly summary failed: " + (err instanceof Error ? err.message : String(err)));
    }
  };

  return (
    <div className="space-y-6">
      {/* Alert Recipient Card */}
      <div className="card">
        <h2 style={{ fontSize: 18, fontWeight: 800, marginBottom: 8 }}>Email Alert Preferences</h2>
        <p style={{ color: "var(--text-dim)", fontSize: 13, marginBottom: 16 }}>
          Choose which cybersecurity alerts you want delivered directly to your verified inbox.
        </p>

        <div style={{ display: "flex", alignItems: "center", gap: 12, padding: "14px 16px", background: "var(--bg-surface)", borderRadius: 8, border: "1px solid var(--border-subtle)", marginBottom: 20 }}>
          <span style={{ fontSize: 24 }}>📬</span>
          <div style={{ flex: 1 }}>
            <div style={{ fontSize: 11, fontWeight: 700, color: "var(--text-dim)", textTransform: "uppercase" }}>Notification Recipient</div>
            <div style={{ fontSize: 15, fontWeight: 800, color: "var(--text-pure)" }}>{prefs.recipient_email || "No recipient configured"}</div>
          </div>
          <span className={`badge ${prefs.recipient_verified ? "badge-safe" : "badge-critical"}`}>
            {prefs.recipient_verified ? "✓ Verified Recipient" : "⚠️ Needs Verification"}
          </span>
        </div>

        {/* Toggle Options */}
        <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <div>
              <div style={{ fontWeight: 700, fontSize: 14 }}>🚨 Critical Phishing Threats</div>
              <div style={{ fontSize: 12, color: "#64748B" }}>Immediate email notifications for severe credential theft and brand spoofing</div>
            </div>
            <input
              type="checkbox"
              style={{ width: 18, height: 18, cursor: "pointer" }}
              checked={prefs.critical_risk_alerts}
              onChange={() => handleToggle("critical_risk_alerts")}
            />
          </div>

          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <div>
              <div style={{ fontWeight: 700, fontSize: 14 }}>⚠️ Suspicious Email Alerts</div>
              <div style={{ fontSize: 12, color: "#64748B" }}>Notifications when incoming emails contain risky links or invoice requests</div>
            </div>
            <input
              type="checkbox"
              style={{ width: 18, height: 18, cursor: "pointer" }}
              checked={prefs.suspicious_email_alerts}
              onChange={() => handleToggle("suspicious_email_alerts")}
            />
          </div>

          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <div>
              <div style={{ fontWeight: 700, fontSize: 14 }}>🔐 Account Security Alerts</div>
              <div style={{ fontSize: 12, color: "#64748B" }}>Alerts for new sign-ins from unrecognized devices or IP addresses</div>
            </div>
            <input
              type="checkbox"
              style={{ width: 18, height: 18, cursor: "pointer" }}
              checked={prefs.account_security_alerts}
              onChange={() => handleToggle("account_security_alerts")}
            />
          </div>

          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <div>
              <div style={{ fontWeight: 700, fontSize: 14 }}>🔄 Mailbox Connection Status</div>
              <div style={{ fontSize: 12, color: "#64748B" }}>Notice when a Gmail or Outlook OAuth session expires or is revoked</div>
            </div>
            <input
              type="checkbox"
              style={{ width: 18, height: 18, cursor: "pointer" }}
              checked={prefs.connection_status_alerts}
              onChange={() => handleToggle("connection_status_alerts")}
            />
          </div>

          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <div>
              <div style={{ fontWeight: 700, fontSize: 14 }}>📊 Weekly Cyber Defense Digest</div>
              <div style={{ fontSize: 12, color: "#64748B" }}>Every Monday morning summary of blocked threats and scam analytics</div>
            </div>
            <input
              type="checkbox"
              style={{ width: 18, height: 18, cursor: "pointer" }}
              checked={prefs.weekly_summary}
              onChange={() => handleToggle("weekly_summary")}
            />
          </div>
        </div>

        <div style={{ display: "flex", gap: 12, marginTop: 24, alignItems: "center" }}>
          <button className="btn btn-primary" onClick={handleSave} disabled={saving}>
            {saving ? "Saving…" : "Save Notification Preferences"}
          </button>
          <button className="btn btn-ghost" onClick={handleSendTestAlert} disabled={testingAlert}>
            {testingAlert ? "Sending Test…" : "🚀 Send Test Alert"}
          </button>
          <button className="btn btn-ghost" onClick={handleSendWeeklySummary}>
            📊 Trigger Weekly Summary
          </button>
          {saveMessage && <span style={{ color: "#166534", fontSize: 12, fontWeight: 700 }}>{saveMessage}</span>}
        </div>
      </div>

      {/* Delivery Logs Table */}
      <div className="card">
        <h3 style={{ fontSize: 16, fontWeight: 800, marginBottom: 16 }}>Notification Delivery Log ({logs.length})</h3>

        {loading ? (
          <p style={{ color: "#64748B", fontSize: 13 }}>Loading delivery log…</p>
        ) : logs.length === 0 ? (
          <p style={{ color: "#64748B", fontSize: 13 }}>No alerts dispatched yet.</p>
        ) : (
          <div style={{ overflowX: "auto" }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Type</th>
                  <th>Deduplication Key</th>
                  <th>Delivery Status</th>
                  <th>Attempts</th>
                  <th>Dispatched At</th>
                </tr>
              </thead>
              <tbody>
                {logs.map((log) => (
                  <tr key={log.id}>
                    <td style={{ fontWeight: 700 }}>{log.notification_type}</td>
                    <td style={{ fontFamily: "monospace", fontSize: 11.5, color: "#64748B" }}>
                      {log.deduplication_key}
                    </td>
                    <td>
                      <span className={`badge ${log.delivery_status === "delivered" ? "badge-safe" : "badge-critical"}`}>
                        {log.delivery_status.toUpperCase()}
                      </span>
                    </td>
                    <td>{log.attempt_count}</td>
                    <td style={{ fontSize: 12, color: "#64748B" }}>
                      {log.sent_at ? new Date(log.sent_at).toLocaleString() : new Date(log.created_at).toLocaleString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
