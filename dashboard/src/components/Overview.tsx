import React from "react";
import type { ScanRecord } from "../lib/supabase";

interface OverviewProps {
  scans: ScanRecord[];
  onNavigateHistory: () => void;
}

export const Overview: React.FC<OverviewProps> = ({ scans, onNavigateHistory }) => {
  const total = scans.length;
  const critical = scans.filter((s) => s.risk_level === "critical").length;
  const high = scans.filter((s) => s.risk_level === "high").length;
  const medium = scans.filter((s) => s.risk_level === "medium").length;
  const low = scans.filter((s) => s.risk_level === "low").length;

  const threatCount = critical + high;
  const safeCount = low + (scans.filter((s) => (s as any).risk_level === "safe").length);
  const threatRate = total > 0 ? Math.round((threatCount / total) * 100) : 0;
  const safeHealthScore = Math.max(0, 100 - threatRate);

  // SVG Gauge calculation
  const radius = 64;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (safeHealthScore / 100) * circumference;

  const recent = scans.slice(0, 6);

  // Gather unique detected flags across recent scans
  const detectedFlags: string[] = [];
  scans.forEach((s) => {
    (s.indicators || []).forEach((ind) => {
      const label = ind.indicator_type || ind.description;
      if (label && !detectedFlags.includes(label)) {
        detectedFlags.push(label);
      }
    });
  });


  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "24px" }}>
      {/* 4 Top Metric Cards (Anarisk & VaultGuard style) */}
      <div className="grid-4">
        <div className="card">
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <span className="card-title">Total Threats Audited</span>
            <span className="trend-pill">All time</span>
          </div>
          <div className="stat-value">{total}</div>
          <div className="stat-sub">Across links, SMS, UPI & emails</div>
        </div>

        <div className="card">
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <span className="card-title">Critical Blocked</span>
            <span className="trend-pill">Recorded</span>
          </div>
          <div className="stat-value" style={{ color: "#f87171" }}>{critical}</div>
          <div className="stat-sub">High-confidence credential traps</div>
        </div>

        <div className="card">
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <span className="card-title">Threat Exposure Rate</span>
            <span className="trend-pill" style={{ background: threatRate > 30 ? "rgba(239, 68, 68, 0.15)" : "rgba(16, 185, 129, 0.15)", color: threatRate > 30 ? "#f87171" : "#34d399" }}>
              {threatRate > 30 ? "Elevated" : "Controlled"}
            </span>
          </div>
          <div className="stat-value" style={{ color: threatRate > 30 ? "#fb923c" : "#34d399" }}>
            {threatRate}%
          </div>
          <div className="stat-sub">{threatCount} high or critical encounters</div>
        </div>

        <div className="card">
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <span className="card-title">Verified Safe Traffic</span>
            <span className="trend-pill">Low risk</span>
          </div>
          <div className="stat-value" style={{ color: "#34d399" }}>{safeCount}</div>
          <div className="stat-sub">{low} low risk · {medium} medium risk</div>
        </div>
      </div>

      {/* Security Health & Flag Detection Dual Cards (Inspired by Truth Lens & Anarisk) */}
      <div className="grid-2">
        {/* Left: Overall Trust & Risk Score Gauge */}
        <div className="card" style={{ display: "flex", flexDirection: "column", justifyContent: "space-between" }}>
          <div>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "16px" }}>
              <h3 style={{ fontSize: "15px", fontWeight: "700", color: "var(--text-main)" }}>
                Threat Defense Health
              </h3>
              <span className="badge badge-low">Based on scan history</span>
            </div>

            <div style={{ display: "flex", alignItems: "center", gap: "28px", flexWrap: "wrap", margin: "16px 0" }}>
              {/* Radial Score Gauge */}
              <div className="radial-gauge-container">
                <svg width="160" height="160" style={{ transform: "rotate(-90deg)" }}>
                  <circle
                    cx="80"
                    cy="80"
                    r={radius}
                    stroke="var(--bg-surface)"
                    strokeWidth="12"
                    fill="transparent"
                  />
                  <circle
                    cx="80"
                    cy="80"
                    r={radius}
                    stroke={safeHealthScore > 70 ? "var(--accent-emerald)" : safeHealthScore > 40 ? "var(--accent-cyan)" : "#ef4444"}
                    strokeWidth="12"
                    strokeDasharray={circumference}
                    strokeDashoffset={strokeDashoffset}
                    strokeLinecap="round"
                    fill="transparent"
                    style={{ transition: "stroke-dashoffset 0.8s ease" }}
                  />
                </svg>
                <div className="radial-gauge-text">
                  <div className="radial-gauge-score">{safeHealthScore}</div>
                  <div className="radial-gauge-label">Trust Index</div>
                </div>
              </div>

              {/* Category Breakdown Progress Bars */}
              <div style={{ flex: 1, minWidth: "180px" }}>
                <div style={{ fontSize: "12px", color: "var(--text-sub)", display: "flex", justifyContent: "space-between" }}>
                  <span>Phishing & Lookalikes</span>
                  <strong style={{ color: critical > 0 ? "#f87171" : "#34d399" }}>{critical > 0 ? "Flagged" : "Clear"}</strong>
                </div>
                <div className="progress-bar-bg">
                  <div className="progress-bar-fill" style={{ width: `${Math.min(100, critical * 35)}%`, background: "#ef4444" }} />
                </div>

                <div style={{ fontSize: "12px", color: "var(--text-sub)", display: "flex", justifyContent: "space-between" }}>
                  <span>Payment / UPI Fraud</span>
                  <strong style={{ color: high > 0 ? "#fb923c" : "#34d399" }}>{high > 0 ? "Suspicious" : "Clear"}</strong>
                </div>
                <div className="progress-bar-bg">
                  <div className="progress-bar-fill" style={{ width: `${Math.min(100, high * 25)}%`, background: "#f59e0b" }} />
                </div>

                <div style={{ fontSize: "12px", color: "var(--text-sub)", display: "flex", justifyContent: "space-between" }}>
                  <span>Credential Theft / OTP</span>
                  <strong style={{ color: "#34d399" }}>Shield Active</strong>
                </div>
                <div className="progress-bar-bg">
                  <div className="progress-bar-fill" style={{ width: "95%", background: "#10b981" }} />
                </div>
              </div>
            </div>
          </div>

          <p style={{ margin: 0, fontSize: "12px", color: "var(--text-dim)", lineHeight: "1.5" }}>
            Calculated from multi-vector analysis: brand homoglyphs, throwaway TLDs, reverse collect triggers, and sender DKIM/SPF alignment.
          </p>
        </div>

        {/* Right: Detected Incident Flags (Truth Lens style) */}
        <div className="card" style={{ display: "flex", flexDirection: "column", justifyContent: "space-between" }}>
          <div>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "14px" }}>
              <h3 style={{ fontSize: "15px", fontWeight: "700", color: "var(--text-main)", display: "flex", alignItems: "center", gap: "8px" }}>
                Monitored Threat Signatures
              </h3>
              <span style={{ fontSize: "11px", color: "var(--accent-cyan)", fontWeight: "600" }}>From recorded scans</span>
            </div>

            <p style={{ fontSize: "13px", color: "var(--text-muted)", marginBottom: "14px", lineHeight: "1.5" }}>
              Indicators reported by completed scans. No signature is shown as detected unless it appears in recorded scan evidence.
            </p>

            {detectedFlags.length ? (
              <div style={{ display: "flex", flexWrap: "wrap", gap: "6px" }}>
                {detectedFlags.slice(0, 8).map((flag, idx) => (
                  <span key={idx} className="detected-flag-chip">{flag}</span>
                ))}
              </div>
            ) : (
              <div className="empty-state" style={{ padding: "20px 12px", border: "1px dashed var(--border-subtle)", borderRadius: "10px", color: "var(--text-muted)" }}>
                No indicators recorded yet. Run a scan to populate this panel.
              </div>
            )}
          </div>

          <div style={{ marginTop: "16px", padding: "10px 14px", background: "rgba(6, 182, 212, 0.08)", border: "1px solid rgba(6, 182, 212, 0.2)", borderRadius: "8px" }}>
            <span style={{ fontSize: "12px", color: "var(--text-sub)", display: "block" }}>
              <strong>Interpretation:</strong> A low or empty scan history is not proof that a website, message, or payment is safe.
            </span>
          </div>
        </div>
      </div>

      {/* Recent Incidents Table (VaultGuard style) */}
      <div className="card">
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "16px", flexWrap: "wrap", gap: "10px" }}>
          <div>
            <h3 style={{ fontSize: "16px", fontWeight: "700", color: "var(--text-main)", margin: 0 }}>
              Recent Security Interceptions
            </h3>
            <span style={{ fontSize: "12px", color: "var(--text-dim)" }}>Live stream of URL, payment, and message audits</span>
          </div>
          <button type="button" className="btn btn-ghost" onClick={onNavigateHistory}>
            View All Incident Logs →
          </button>
        </div>

        {recent.length === 0 ? (
          <div style={{ textAlign: "center", color: "var(--text-dim)", padding: "40px 0", fontSize: "13px" }}>
            No scans recorded yet. Start a scan in the extension to build your security history. An empty history does not indicate that traffic is safe.
          </div>
        ) : (
          <div style={{ overflowX: "auto" }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Vector</th>
                  <th>Target / Domain</th>
                  <th>Risk Score</th>
                  <th>Severity Level</th>
                  <th>Detection Method</th>
                  <th>Recorded At</th>
                </tr>
              </thead>
              <tbody>
                {recent.map((s) => (
                  <tr key={s.id}>
                    <td style={{ fontWeight: "700", textTransform: "uppercase", fontSize: "11px", color: "var(--accent-cyan)" }}>
                      {s.scan_type}
                    </td>
                    <td style={{ maxWidth: "280px", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis", color: "var(--text-main)" }}>
                      {s.normalized_domain || s.submitted_content}
                    </td>
                    <td style={{ fontWeight: "800", color: s.risk_score > 60 ? "#f87171" : s.risk_score > 20 ? "#fbbf24" : "#34d399" }}>
                      {s.risk_score} / 100
                    </td>
                    <td>
                      <span className={`badge badge-${s.risk_level}`}>{s.risk_level}</span>
                    </td>
                    <td style={{ fontSize: "11px", color: "var(--text-muted)", textTransform: "uppercase" }}>
                      {s.detection_method}
                    </td>
                    <td style={{ fontSize: "12px", color: "var(--text-dim)" }}>
                      {new Date(s.created_at).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" })}
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
