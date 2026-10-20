import React, { useState, useEffect } from "react";
import { supabase } from "../lib/supabase";
import type { EmailScanResult } from "../lib/supabase";

interface EmailProtectionProps {
  userId: string;
}

export const EmailProtection: React.FC<EmailProtectionProps> = ({ userId }) => {
  const [scans, setScans] = useState<EmailScanResult[]>([]);
  const [loading, setLoading] = useState(true);

  // Manual Email Scanner Form State
  const [sender, setSender] = useState("");
  const [subject, setSubject] = useState("");
  const [bodyText, setBodyText] = useState("");
  const [scanning, setScanning] = useState(false);
  const [activeResult, setActiveResult] = useState<EmailScanResult | null>(null);

  useEffect(() => {
    loadScans();
  }, [userId]);

  const loadScans = async () => {
    setLoading(true);
    try {
      const { data } = await supabase
        .from("email_scan_results")
        .select("*")
        .order("created_at", { ascending: false });

      if (data) setScans(data as EmailScanResult[]);
    } catch (err) {
      console.warn("Failed to load email scans:", err);
    } finally {
      setLoading(false);
    }
  };

  const handleScanSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!sender || !subject) return;

    setScanning(true);
    try {
      const res = await supabase.functions.invoke("scan-email", {
        body: {
          userId,
          sender,
          subject,
          bodyText,
          allowAi: true
        }
      });

      if (res.error) throw res.error;
      const scanResult = res.data?.scan;

      if (scanResult) {
        setActiveResult(scanResult);
        setScans((prev) => [scanResult, ...prev.filter((s) => s.id !== scanResult.id)]);
      }
    } catch (err: unknown) {
      alert("Email scan failed: " + (err instanceof Error ? err.message : String(err)));
    } finally {
      setScanning(false);
    }
  };

  const applySample = (type: "paytm" | "invoice" | "safe") => {
    if (type === "paytm") {
      setSender("Paytm Security <alert-support@paytrn-security.xyz>");
      setSubject("URGENT: Your KYC is expired. Re-verify OTP to prevent blocking");
      setBodyText("Dear Customer, your Paytm wallet will be permanently deactivated today. Please share your OTP verification code immediately at http://paytrn-security.xyz/verify to restore access.");
    } else if (type === "invoice") {
      setSender("Billing Dept <invoices@cloud-service-billing.top>");
      setSubject("Invoice #98201 Overdue - Immediate wire transfer required");
      setBodyText("Your company invoice #98201 has not been paid. Remit \$4,200 immediately to the attached account or your enterprise services will terminate.");
    } else {
      setSender("GitHub <notifications@github.com>");
      setSubject("[GitHub] Security advisory published for repository dependency");
      setBodyText("A security advisory has been published affecting one of your repository dependencies. Review the pull request at https://github.com/security/advisories.");
    }
  };

  const totalScanned = scans.length;
  const criticalCount = scans.filter((s) => s.risk_score >= 75).length;
  const highCount = scans.filter((s) => s.risk_score >= 50 && s.risk_score < 75).length;
  const safeCount = scans.filter((s) => s.risk_score < 25).length;

  return (
    <div className="space-y-6">
      {/* Metric Cards */}
      <div className="analytics-grid">
        <div className="card">
          <p className="metric-label">Emails Analyzed</p>
          <div className="metric-value">{totalScanned}</div>
          <span className="badge badge-safe">Inbox Guard</span>
        </div>
        <div className="card">
          <p className="metric-label">Critical Phishing</p>
          <div className="metric-value" style={{ color: "#DC2626" }}>{criticalCount}</div>
          <span className="badge badge-critical">Immediate Threat</span>
        </div>
        <div className="card">
          <p className="metric-label">High-Risk Extortion</p>
          <div className="metric-value" style={{ color: "#D97706" }}>{highCount}</div>
          <span className="badge badge-high">Caution Advised</span>
        </div>
        <div className="card">
          <p className="metric-label">Safe & Legitimate</p>
          <div className="metric-value" style={{ color: "#16A34A" }}>{safeCount}</div>
          <span className="badge badge-safe">Verified</span>
        </div>
      </div>

      {/* Manual Email Inspection Tool */}
      <div className="card">
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
          <div>
            <h3 style={{ fontSize: 16, fontWeight: 800, margin: 0 }}>Inspect Suspicious Email</h3>
            <p style={{ color: "#64748B", fontSize: 12.5, margin: "4px 0 0" }}>
              Test any message, invoice, or notification before clicking links or replying.
            </p>
          </div>
          <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
            <span style={{ fontSize: 11, fontWeight: 700, color: "#64748B", alignSelf: "center" }}>Quick Samples:</span>
            <button type="button" className="chip chip-danger" onClick={() => applySample("paytm")}>
              Paytm Spoof
            </button>
            <button type="button" className="chip chip-danger" onClick={() => applySample("invoice")}>
              Invoice Fraud
            </button>
            <button type="button" className="chip chip-safe" onClick={() => applySample("safe")}>
              GitHub Safe
            </button>
          </div>
        </div>

        <form onSubmit={handleScanSubmit} style={{ display: "flex", flexDirection: "column", gap: 12 }}>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
            <div>
              <label style={{ fontSize: 11, fontWeight: 700, display: "block", marginBottom: 4 }}>Sender (From)</label>
              <input
                type="text"
                className="input-field"
                style={{ width: "100%" }}
                placeholder="Support <alerts@paypal-security.xyz>"
                required
                value={sender}
                onChange={(e) => setSender(e.target.value)}
              />
            </div>
            <div>
              <label style={{ fontSize: 11, fontWeight: 700, display: "block", marginBottom: 4 }}>Subject</label>
              <input
                type="text"
                className="input-field"
                style={{ width: "100%" }}
                placeholder="Urgent account security verification"
                required
                value={subject}
                onChange={(e) => setSubject(e.target.value)}
              />
            </div>
          </div>

          <div>
            <label style={{ fontSize: 11, fontWeight: 700, display: "block", marginBottom: 4 }}>Email Body Text</label>
            <textarea
              className="input-field"
              style={{ width: "100%", height: 80, resize: "vertical", fontFamily: "inherit" }}
              placeholder="Paste email content, message body, or extortion instructions here…"
              value={bodyText}
              onChange={(e) => setBodyText(e.target.value)}
            />
          </div>

          <button type="submit" className="btn btn-primary" style={{ alignSelf: "flex-start" }} disabled={scanning}>
            {scanning ? "Analyzing Threat Indicators…" : "🛡️ Audit Email Content"}
          </button>
        </form>
      </div>

      {/* Active Scan Result Card */}
      {activeResult && (
        <div
          className="card"
          style={{
            borderLeft: `4px solid ${activeResult.risk_score >= 50 ? "var(--risk-critical-text)" : "var(--risk-safe-text)"}`,
            background: activeResult.risk_score >= 50 ? "rgba(239, 68, 68, 0.08)" : "rgba(16, 185, 129, 0.06)"
          }}
        >
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
            <div>
              <span className={`badge badge-${activeResult.risk_level}`} style={{ fontSize: 12 }}>
                {activeResult.risk_level.toUpperCase()} RISK · SCORE {activeResult.risk_score}/100
              </span>
              <h3 style={{ fontSize: 17, fontWeight: 800, marginTop: 6, marginBottom: 2 }}>
                {activeResult.subject_redacted}
              </h3>
              <p style={{ fontSize: 12, color: "var(--text-dim)", margin: 0 }}>From: {activeResult.sender_address}</p>
            </div>
            <button className="btn btn-ghost" style={{ fontSize: 11 }} onClick={() => setActiveResult(null)}>
              ✕ Dismiss
            </button>
          </div>

          <p style={{ fontSize: 13.5, color: "var(--text-sub)", lineHeight: 1.5, marginBottom: 14 }}>
            {activeResult.explanation}
          </p>

          {activeResult.indicators.length > 0 && (
            <div style={{ marginBottom: 14 }}>
              <div style={{ fontSize: 11, fontWeight: 700, textTransform: "uppercase", color: "var(--text-dim)", marginBottom: 6 }}>
                Detected Risk Indicators:
              </div>
              <ul style={{ margin: 0, paddingLeft: 18, fontSize: 13, color: "var(--risk-critical-text)", lineHeight: 1.6 }}>
                {activeResult.indicators.map((ind, i) => (
                  <li key={i}>
                    <strong>[{ind.indicator_type}]</strong> {ind.description}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {activeResult.recommended_actions.length > 0 && (
            <div>
              <div style={{ fontSize: 11, fontWeight: 700, textTransform: "uppercase", color: "var(--text-dim)", marginBottom: 6 }}>
                Safety Recommendations:
              </div>
              <ul style={{ margin: 0, paddingLeft: 18, fontSize: 13, color: "var(--risk-safe-text)", lineHeight: 1.6 }}>
                {activeResult.recommended_actions.map((act, i) => (
                  <li key={i}>{act}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      {/* Scanned Emails History Table */}
      <div className="card">
        <h3 style={{ fontSize: 16, fontWeight: 800, marginBottom: 16 }}>Scanned Email Detections ({scans.length})</h3>

        {loading ? (
          <p style={{ color: "var(--text-dim)", fontSize: 13 }}>Loading email scan records…</p>
        ) : scans.length === 0 ? (
          <p style={{ color: "var(--text-dim)", fontSize: 13 }}>No email scans recorded yet.</p>
        ) : (
          <div className="table-responsive">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Sender</th>
                  <th>Subject</th>
                  <th>Risk Score</th>
                  <th>Indicators</th>
                  <th>Scanned At</th>
                </tr>
              </thead>
              <tbody>
                {scans.map((s) => (
                  <tr key={s.id} onClick={() => setActiveResult(s)} style={{ cursor: "pointer" }}>
                    <td style={{ fontWeight: 600 }}>{s.sender_address}</td>
                    <td>{s.subject_redacted}</td>
                    <td>
                      <span className={`badge badge-${s.risk_level}`}>
                        {s.risk_score} · {s.risk_level.toUpperCase()}
                      </span>
                    </td>
                    <td style={{ fontSize: 12, color: "var(--text-dim)" }}>
                      {s.indicators.length > 0 ? `${s.indicators.length} signals` : "Clean"}
                    </td>
                    <td style={{ fontSize: 12, color: "var(--text-dim)" }}>
                      {new Date(s.scanned_at || s.created_at).toLocaleString()}
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
