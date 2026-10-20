import React from "react";
import type { ScanRecord } from "../lib/supabase";

interface AiInsightsProps {
  scans: ScanRecord[];
}

export const AiInsights: React.FC<AiInsightsProps> = ({ scans }) => {
  if (scans.length === 0) {
    return (
      <div className="card" style={{ textAlign: "center", padding: "48px 24px" }}>
        <span style={{ fontSize: 40 }}>🤖</span>
        <h2 style={{ fontSize: 18, fontWeight: 800, marginTop: 12 }}>No Security Telemetry Available Yet</h2>
        <p style={{ color: "#64748B", maxWidth: 500, margin: "8px auto 0", fontSize: 13, lineHeight: 1.5 }}>
          ScamShield AI generates personalized security insights only after analyzing your saved scans.
          Audit a website or message with the extension to populate this view with real evidence.
        </p>
      </div>
    );
  }

  const criticalScans = scans.filter((s) => s.risk_level === "critical");
  const otpThreats = scans.filter((s) =>
    s.indicators?.some((i) => i.indicator_type === "OTP_REQUEST")
  );
  const brandLookalikes = scans.filter((s) =>
    s.indicators?.some((i) => i.indicator_type === "BRAND_IMPERSONATION")
  );
  const rawIpThreats = scans.filter((s) =>
    s.indicators?.some((i) => i.indicator_type === "SUSPICIOUS_IP_URL")
  );

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      {/* Primary Executive Summary */}
      <div className="insight-card safe">
        <h3 className="insight-title">🛡️ Personalized Threat Exposure Report</h3>
        <p className="insight-desc">
          Based on <strong>{scans.length} verified scan records</strong>, ScamShield evaluated your exposure.
          {criticalScans.length > 0
            ? ` You encountered ${criticalScans.length} critical severity threat vectors requiring defensive vigilance.`
            : " No active critical compromises or high-probability phishing vectors were identified in your recent history."}
        </p>
        <div style={{ display: "flex", gap: 16, fontSize: 12, color: "#64748B" }}>
          <span><strong>Reporting Window:</strong> Active user history</span>
          <span><strong>AI Confidence:</strong> High (Rule & Signal Corroborated)</span>
        </div>
      </div>

      {/* Pattern 1: OTP Theft */}
      {otpThreats.length > 0 && (
        <div className="insight-card critical">
          <h3 className="insight-title">⚠️ Targeted Credential & OTP Harvesting Identified</h3>
          <p className="insight-desc">
            You encountered <strong>{otpThreats.length} attempt(s)</strong> requesting one-time verification passwords (OTP) or authentication codes.
            Legitimate institutions will never solicit your OTP via unverified SMS or web forms.
          </p>
          <ul className="insight-recs">
            <li>Never disclose one-time passwords even if callers claim to be fraud prevention specialists.</li>
            <li>Enable hardware security keys (FIDO2/WebAuthn) where supported.</li>
          </ul>
        </div>
      )}

      {/* Pattern 2: Look-alike Domains */}
      {brandLookalikes.length > 0 && (
        <div className="insight-card warning">
          <h3 className="insight-title">🔍 Typo-Squatting & Look-Alike Brand Mimicry</h3>
          <p className="insight-desc">
            Detected <strong>{brandLookalikes.length} link(s)</strong> imitating trusted banking, shopping, or technology brands.
            Attackers rely on subtle character swaps (e.g. <code>paytrn</code> instead of <code>paytm</code>).
          </p>
          <ul className="insight-recs">
            <li>Always check the domain address bar before logging in.</li>
            <li>Use browser bookmarks for frequently visited financial and shopping portals.</li>
          </ul>
        </div>
      )}

      {/* Pattern 3: Raw IP Infrastructure */}
      {rawIpThreats.length > 0 && (
        <div className="insight-card critical">
          <h3 className="insight-title">🌐 Raw IP Web Destination Warnings</h3>
          <p className="insight-desc">
            Detected <strong>{rawIpThreats.length} link(s)</strong> pointing directly to numerical IP addresses instead of registered domain names.
            Standard commercial services do not direct customers to raw IP addresses.
          </p>
          <ul className="insight-recs">
            <li>Refrain from clicking raw IP URLs; they often host disposable command-and-control phishing kits.</li>
          </ul>
        </div>
      )}

      {/* Security Limitations Disclosure */}
      <div className="card" style={{ background: "rgba(255, 255, 255, 0.02)", borderStyle: "dashed" }}>
        <p style={{ fontSize: 12, color: "var(--text-dim)", lineHeight: 1.5 }}>
          <strong>Transparency Notice:</strong> ScamShield risk scores and AI security insights are deterministic indicators based on pattern analysis and threat intelligence. They represent risk estimations, not legal proof of intent. Always confirm sensitive inquiries through official public customer support channels.
        </p>
      </div>
    </div>
  );
};
