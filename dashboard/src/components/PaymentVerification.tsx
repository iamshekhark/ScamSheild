import React, { useState, useEffect } from "react";
import { supabase } from "../lib/supabase";
import type { PaymentScanRecord } from "../lib/supabase";

interface PaymentVerificationProps {
  userId: string;
}

export const PaymentVerification: React.FC<PaymentVerificationProps> = ({ userId }) => {
  const [activeInputTab, setActiveInputTab] = useState<"upi_id" | "payment_url" | "qr_code" | "message" | "screenshot">("upi_id");
  const [inputValue, setInputValue] = useState("");
  const [screenshotFileName, setScreenshotFileName] = useState("");
  const [isScanning, setIsScanning] = useState(false);
  const [currentResult, setCurrentResult] = useState<PaymentScanRecord | null>(null);
  const [errorMsg, setErrorMsg] = useState("");

  const [paymentScans, setPaymentScans] = useState<PaymentScanRecord[]>([]);
  const [loadingHistory, setLoadingHistory] = useState(true);

  useEffect(() => {
    loadPaymentScans();
  }, [userId]);

  const loadPaymentScans = async () => {
    setLoadingHistory(true);
    try {
      const { data } = await supabase
        .from("payment_scan_results")
        .select("*")
        .eq("user_id", userId)
        .order("created_at", { ascending: false });

      if (data) {
        setPaymentScans(data as PaymentScanRecord[]);
      }
    } catch (err) {
      console.warn("Failed to load payment scans:", err);
    } finally {
      setLoadingHistory(false);
    }
  };

  const handleVerifyPayment = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg("");
    const clean = inputValue.trim();

    if (!clean) {
      setErrorMsg("Please enter or paste the payment details to scan.");
      return;
    }

    setIsScanning(true);
    try {
      const res = await supabase.functions.invoke("verify-payment-risk", {
        body: {
          content: clean,
          input_type: activeInputTab,
          allow_ai: true,
          userId
        }
      });

      if (res.error) throw res.error;
      if (res.data?.error) throw new Error(res.data.error);

      setCurrentResult(res.data as PaymentScanRecord);
      await loadPaymentScans();
    } catch (err: unknown) {
      setErrorMsg(err instanceof Error ? err.message : "Payment verification failed");
    } finally {
      setIsScanning(false);
    }
  };

  const handleDeleteScan = async (scanId: string) => {
    const { error } = await supabase.from("payment_scan_results").delete().eq("id", scanId);
    if (!error) {
      setPaymentScans((prev) => prev.filter((s) => s.id !== scanId));
      if (currentResult?.id === scanId) setCurrentResult(null);
    } else {
      alert("Error deleting scan record: " + error.message);
    }
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setScreenshotFileName(file.name);
    // When a screenshot image is uploaded, simulate extracting detected confirmation text
    const sampleOcrText = `Payment Successful! Transferred to Merchant Support Office. Transaction Reference / UTR: Pending. Check payment apps for update.`;
    setInputValue(sampleOcrText);
  };

  const getScoreBadgeColor = (level: string) => {
    switch (level) {
      case "critical": return "badge-critical";
      case "high": return "badge-high";
      case "medium": return "badge-medium";
      case "low": return "badge-low";
      default: return "badge-safe";
    }
  };

  return (
    <div className="section-container" style={{ display: "flex", flexDirection: "column", gap: "24px" }}>
      {/* Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: "12px" }}>
        <div>
          <h2 style={{ fontSize: "22px", fontWeight: "700", color: "#f8fafc", margin: "0 0 6px 0", display: "flex", alignItems: "center", gap: "10px" }}>
            <span>💳</span> Payment Scam Verification
          </h2>
          <p style={{ color: "#94a3b8", fontSize: "14px", margin: 0, maxWidth: "700px" }}>
            Verify UPI IDs, payment links, QR codes, collect requests, and payment messages before authorizing transfers. ScamShield inspects deception indicators while keeping payment settlement status strictly separate.
          </p>
        </div>
      </div>

      {/* Input Type Tabs */}
      <div className="card" style={{ padding: "20px" }}>
        <div style={{ display: "flex", gap: "8px", borderBottom: "1px solid #334155", paddingBottom: "14px", marginBottom: "18px", overflowX: "auto" }}>
          <button
            type="button"
            className={`btn-subtab ${activeInputTab === "upi_id" ? "active" : ""}`}
            onClick={() => { setActiveInputTab("upi_id"); setInputValue(""); setCurrentResult(null); }}
          >
            🆔 UPI ID / VPA
          </button>
          <button
            type="button"
            className={`btn-subtab ${activeInputTab === "qr_code" ? "active" : ""}`}
            onClick={() => { setActiveInputTab("qr_code"); setInputValue(""); setCurrentResult(null); }}
          >
            🏁 QR Code / URI
          </button>
          <button
            type="button"
            className={`btn-subtab ${activeInputTab === "payment_url" ? "active" : ""}`}
            onClick={() => { setActiveInputTab("payment_url"); setInputValue(""); setCurrentResult(null); }}
          >
            🔗 Payment Link / URL
          </button>
          <button
            type="button"
            className={`btn-subtab ${activeInputTab === "message" ? "active" : ""}`}
            onClick={() => { setActiveInputTab("message"); setInputValue(""); setCurrentResult(null); }}
          >
            💬 SMS / WhatsApp Message
          </button>
          <button
            type="button"
            className={`btn-subtab ${activeInputTab === "screenshot" ? "active" : ""}`}
            onClick={() => { setActiveInputTab("screenshot"); setInputValue(""); setCurrentResult(null); }}
          >
            🖼️ Screenshot / Confirmation
          </button>
        </div>

        {/* Verification Form */}
        <form onSubmit={handleVerifyPayment}>
          {activeInputTab === "upi_id" && (
            <div>
              <label style={{ display: "block", fontSize: "13px", fontWeight: "600", color: "#cbd5e1", marginBottom: "6px" }}>
                Enter UPI Identifier (VPA):
              </label>
              <input
                type="text"
                className="input-field"
                placeholder="e.g. refund-desk-paytm@ybl or merchant@okhdfcbank"
                value={inputValue}
                onChange={(e) => setInputValue(e.target.value)}
              />
              <span style={{ fontSize: "12px", color: "#64748b", marginTop: "4px", display: "block" }}>
                Checks for fake refund handles, brand impersonation, deceptive bank suffixes, and known threat lists.
              </span>
            </div>
          )}

          {activeInputTab === "qr_code" && (
            <div>
              <label style={{ display: "block", fontSize: "13px", fontWeight: "600", color: "#cbd5e1", marginBottom: "6px" }}>
                Paste Scanned QR Code URI or Text:
              </label>
              <input
                type="text"
                className="input-field"
                placeholder="e.g. upi://pay?pa=merchant@ybl&pn=Store&am=500&tn=Refund..."
                value={inputValue}
                onChange={(e) => setInputValue(e.target.value)}
              />
              <span style={{ fontSize: "12px", color: "#64748b", marginTop: "4px", display: "block" }}>
                Detects deceptive collect requests, name mismatches, and fraudulent notes asking for UPI PIN entry.
              </span>
            </div>
          )}

          {activeInputTab === "payment_url" && (
            <div>
              <label style={{ display: "block", fontSize: "13px", fontWeight: "600", color: "#cbd5e1", marginBottom: "6px" }}>
                Payment Gateway or Link URL:
              </label>
              <input
                type="text"
                className="input-field"
                placeholder="https://paytm-security-claim.top/order/9482"
                value={inputValue}
                onChange={(e) => setInputValue(e.target.value)}
              />
              <span style={{ fontSize: "12px", color: "#64748b", marginTop: "4px", display: "block" }}>
                Screens for phishing payment gateways, throwaway domains, and fake cashback portals.
              </span>
            </div>
          )}

          {activeInputTab === "message" && (
            <div>
              <label style={{ display: "block", fontSize: "13px", fontWeight: "600", color: "#cbd5e1", marginBottom: "6px" }}>
                Paste SMS, WhatsApp, or Payment Instruction Message:
              </label>
              <textarea
                className="input-field"
                rows={4}
                placeholder="Paste suspicious payment request message (e.g. Electricity bill disconnect threat, lottery prize claim, AnyDesk KYC request)..."
                value={inputValue}
                onChange={(e) => setInputValue(e.target.value)}
              />
            </div>
          )}

          {activeInputTab === "screenshot" && (
            <div>
              <label style={{ display: "block", fontSize: "13px", fontWeight: "600", color: "#cbd5e1", marginBottom: "6px" }}>
                Upload Payment Screenshot or Paste Confirmation Text:
              </label>
              <div style={{ display: "flex", gap: "12px", alignItems: "center", marginBottom: "10px" }}>
                <input
                  type="file"
                  accept="image/*"
                  onChange={handleFileUpload}
                  style={{ color: "#94a3b8", fontSize: "13px" }}
                />
                {screenshotFileName && (
                  <span style={{ fontSize: "12px", color: "#38bdf8" }}>✓ Loaded: {screenshotFileName}</span>
                )}
              </div>
              <textarea
                className="input-field"
                rows={3}
                placeholder="Extracted screenshot text (e.g., 'Paid ₹5,000 to Store Manager...')"
                value={inputValue}
                onChange={(e) => setInputValue(e.target.value)}
              />
            </div>
          )}

          {errorMsg && (
            <div style={{ marginTop: "12px", padding: "10px 14px", background: "rgba(239, 68, 68, 0.15)", border: "1px solid #ef4444", borderRadius: "6px", color: "#fca5a5", fontSize: "13px" }}>
              ⚠️ {errorMsg}
            </div>
          )}

          <div style={{ marginTop: "16px", display: "flex", justifyContent: "flex-end" }}>
            <button
              type="submit"
              className="btn btn-primary"
              disabled={isScanning}
              style={{ padding: "8px 24px", display: "flex", alignItems: "center", gap: "8px" }}
            >
              {isScanning ? "Analyzing Payment Security..." : "🔍 Verify Payment Security"}
            </button>
          </div>
        </form>
      </div>

      {/* Live Scan Result Card */}
      {currentResult && (
        <div className="card" style={{ padding: "20px", borderLeft: `4px solid ${currentResult.risk_score > 60 ? "#ef4444" : currentResult.risk_score > 20 ? "#f59e0b" : "#10b981"}` }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: "12px", marginBottom: "14px" }}>
            <div>
              <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                <span className={`badge ${getScoreBadgeColor(currentResult.risk_level)}`} style={{ textTransform: "uppercase", fontSize: "12px", padding: "4px 10px" }}>
                  {currentResult.risk_level} RISK
                </span>
                <span style={{ fontSize: "18px", fontWeight: "700", color: "#f8fafc" }}>
                  Risk Score: {currentResult.risk_score} / 100
                </span>
                <span style={{ fontSize: "12px", background: "#1e293b", padding: "3px 8px", borderRadius: "4px", color: "#94a3b8" }}>
                  Engine: {currentResult.detection_method.toUpperCase()}
                </span>
              </div>
              {currentResult.normalized_payee && (
                <div style={{ marginTop: "6px", fontSize: "14px", color: "#cbd5e1" }}>
                  <strong>Payee Identifier:</strong> <code style={{ color: "#38bdf8" }}>{currentResult.normalized_payee}</code>
                </div>
              )}
              {currentResult.payment_domain && (
                <div style={{ marginTop: "4px", fontSize: "14px", color: "#cbd5e1" }}>
                  <strong>Domain:</strong> <code style={{ color: "#f59e0b" }}>{currentResult.payment_domain}</code>
                </div>
              )}
            </div>

            {/* Crucial separation between scam risk and payment settlement status */}
            <div style={{ background: "rgba(30, 41, 59, 0.8)", border: "1px solid #334155", borderRadius: "8px", padding: "10px 14px", maxWidth: "340px" }}>
              <div style={{ fontSize: "11px", fontWeight: "700", textTransform: "uppercase", color: "#94a3b8", marginBottom: "4px" }}>
                Settlement Status
              </div>
              <div style={{ fontSize: "13px", fontWeight: "600", color: "#e2e8f0", display: "flex", alignItems: "center", gap: "6px" }}>
                <span>🔒</span> {currentResult.payment_status.toUpperCase()}
              </div>
              <p style={{ margin: "4px 0 0 0", fontSize: "11px", color: "#64748b", lineHeight: "1.4" }}>
                Payment status is not independently verified by a bank gateway. ScamShield analyzes scam risk only.
              </p>
            </div>
          </div>

          {/* Explanation */}
          <div style={{ background: "#0f172a", borderRadius: "6px", padding: "12px 16px", marginBottom: "14px" }}>
            <p style={{ margin: 0, fontSize: "13px", color: "#e2e8f0", lineHeight: "1.5" }}>
              {currentResult.explanation}
            </p>
          </div>

          {/* Indicators / Evidence */}
          {currentResult.indicators && currentResult.indicators.length > 0 && (
            <div style={{ marginBottom: "14px" }}>
              <h4 style={{ fontSize: "13px", fontWeight: "600", color: "#cbd5e1", margin: "0 0 8px 0" }}>
                Detection Evidence:
              </h4>
              <ul style={{ margin: 0, paddingLeft: "18px", color: "#94a3b8", fontSize: "13px" }}>
                {currentResult.indicators.map((ind, idx) => (
                  <li key={idx} style={{ marginBottom: "4px" }}>
                    <strong style={{ color: "#f8fafc" }}>[{ind.evidence_type}]:</strong> {ind.description}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Recommended Safety Actions */}
          {currentResult.recommended_actions && currentResult.recommended_actions.length > 0 && (
            <div style={{ background: "rgba(16, 185, 129, 0.08)", border: "1px solid rgba(16, 185, 129, 0.2)", borderRadius: "6px", padding: "12px 16px" }}>
              <h4 style={{ fontSize: "13px", fontWeight: "600", color: "#34d399", margin: "0 0 6px 0" }}>
                Recommended Safety Precautions:
              </h4>
              <ul style={{ margin: 0, paddingLeft: "18px", color: "#cbd5e1", fontSize: "13px" }}>
                {currentResult.recommended_actions.map((act, idx) => (
                  <li key={idx} style={{ marginBottom: "3px" }}>{act}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      {/* Payment Scan History Table */}
      <div className="card" style={{ padding: "20px" }}>
        <h3 style={{ fontSize: "16px", fontWeight: "700", color: "#f8fafc", margin: "0 0 14px 0" }}>
          Recent Payment Scam Checks
        </h3>

        {loadingHistory ? (
          <div style={{ textAlign: "center", padding: "24px", color: "#94a3b8" }}>Loading scan records...</div>
        ) : paymentScans.length === 0 ? (
          <div style={{ textAlign: "center", padding: "24px", color: "#64748b", fontSize: "13px" }}>
            No payment scans recorded yet. Enter a UPI ID or payment link above to assess fraud risk.
          </div>
        ) : (
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "13px" }}>
              <thead>
                <tr style={{ borderBottom: "1px solid #334155", color: "#94a3b8", textAlign: "left" }}>
                  <th style={{ padding: "8px 12px" }}>Type</th>
                  <th style={{ padding: "8px 12px" }}>Target / Payee</th>
                  <th style={{ padding: "8px 12px" }}>Risk Score</th>
                  <th style={{ padding: "8px 12px" }}>Settlement Status</th>
                  <th style={{ padding: "8px 12px" }}>Scanned At</th>
                  <th style={{ padding: "8px 12px", textAlign: "right" }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {paymentScans.map((s) => (
                  <tr key={s.id} style={{ borderBottom: "1px solid #1e293b" }}>
                    <td style={{ padding: "10px 12px", textTransform: "uppercase", fontSize: "11px", fontWeight: "700", color: "#38bdf8" }}>
                      {s.input_type}
                    </td>
                    <td style={{ padding: "10px 12px", color: "#f8fafc", maxWidth: "240px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                      {s.normalized_payee || s.payment_domain || "Instruction payload"}
                    </td>
                    <td style={{ padding: "10px 12px" }}>
                      <span className={`badge ${getScoreBadgeColor(s.risk_level)}`} style={{ fontSize: "11px", padding: "2px 8px" }}>
                        {s.risk_score} / 100 ({s.risk_level.toUpperCase()})
                      </span>
                    </td>
                    <td style={{ padding: "10px 12px", color: "#94a3b8", fontSize: "12px" }}>
                      <span style={{ background: "#0f172a", padding: "2px 6px", borderRadius: "4px" }}>
                        {s.payment_status}
                      </span>
                    </td>
                    <td style={{ padding: "10px 12px", color: "#64748b", fontSize: "12px" }}>
                      {new Date(s.created_at).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" })}
                    </td>
                    <td style={{ padding: "10px 12px", textAlign: "right" }}>
                      <button
                        type="button"
                        onClick={() => handleDeleteScan(s.id)}
                        style={{ background: "none", border: "none", color: "#ef4444", cursor: "pointer", fontSize: "13px" }}
                        title="Delete record"
                      >
                        🗑️
                      </button>
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
