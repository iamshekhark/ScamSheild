import React, { useState } from "react";
import type { ScanRecord } from "../lib/supabase";

interface ScanHistoryProps {
  scans: ScanRecord[];
  onDeleteScan: (id: string) => Promise<void>;
  onSubmitFeedback: (scanId: string, type: "correct" | "false_positive" | "false_negative") => Promise<void>;
}

export const ScanHistory: React.FC<ScanHistoryProps> = ({
  scans,
  onDeleteScan,
  onSubmitFeedback,
}) => {
  const [searchTerm, setSearchTerm] = useState("");
  const [riskFilter, setRiskFilter] = useState("all");
  const [selectedScan, setSelectedScan] = useState<ScanRecord | null>(null);
  const [feedbackSuccess, setFeedbackSuccess] = useState<string | null>(null);

  const filtered = scans.filter((s) => {
    const matchesSearch =
      (s.submitted_content || "").toLowerCase().includes(searchTerm.toLowerCase()) ||
      (s.normalized_domain || "").toLowerCase().includes(searchTerm.toLowerCase());
    const matchesRisk = riskFilter === "all" || s.risk_level === riskFilter;
    return matchesSearch && matchesRisk;
  });

  const handleFeedback = async (type: "correct" | "false_positive" | "false_negative") => {
    if (!selectedScan) return;
    try {
      await onSubmitFeedback(selectedScan.id, type);
      setFeedbackSuccess("Thank you! Feedback recorded.");
      setTimeout(() => setFeedbackSuccess(null), 3000);
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : "Feedback submission failed");
    }
  };

  const handleDelete = async (id: string) => {
    if (confirm("Are you sure you want to delete this scan record?")) {
      await onDeleteScan(id);
      if (selectedScan?.id === id) setSelectedScan(null);
    }
  };

  return (
    <div>
      <div className="filter-row">
        <input
          type="text"
          className="input-field"
          style={{ flex: 1, minWidth: 240 }}
          placeholder="Search by URL, domain, or message content…"
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
        />

        <select
          value={riskFilter}
          onChange={(e) => setRiskFilter(e.target.value)}
          className="input-field"
        >
          <option value="all">All Risk Levels</option>
          <option value="low">Low Risk</option>
          <option value="medium">Medium Risk</option>
          <option value="high">High Risk</option>
          <option value="critical">Critical Risk</option>
        </select>
      </div>

      <div className="card">
        {filtered.length === 0 ? (
          <p style={{ textAlign: "center", color: "#64748B", padding: "48px 0" }}>
            No scan records match the selected filters.
          </p>
        ) : (
          <div className="table-responsive">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Type</th>
                  <th>Target / Domain</th>
                  <th>Score</th>
                  <th>Severity</th>
                  <th>Method</th>
                  <th>Scanned On</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((s) => (
                  <tr key={s.id}>
                    <td style={{ fontWeight: 700, textTransform: "uppercase", fontSize: 11 }}>{s.scan_type}</td>
                    <td style={{ maxWidth: 320, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                      {s.normalized_domain || s.submitted_content}
                    </td>
                    <td style={{ fontWeight: 800 }}>{s.risk_score}</td>
                    <td>
                      <span className={`badge badge-${s.risk_level}`}>{s.risk_level}</span>
                    </td>
                    <td style={{ fontSize: 11, color: "#64748B", textTransform: "uppercase" }}>{s.detection_method}</td>
                    <td style={{ fontSize: 12, color: "#64748B" }}>{new Date(s.created_at).toLocaleDateString()}</td>
                    <td>
                      <button
                        className="btn btn-ghost"
                        style={{ padding: "4px 8px", fontSize: 11, marginRight: 6 }}
                        onClick={() => setSelectedScan(s)}
                      >
                        Details
                      </button>
                      <button
                        className="btn btn-danger"
                        style={{ padding: "4px 8px", fontSize: 11 }}
                        onClick={() => handleDelete(s.id)}
                      >
                        Delete
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Detail Modal */}
      {selectedScan && (
        <div className="modal-overlay" onClick={() => setSelectedScan(null)}>
          <div className="modal-content" style={{ maxWidth: 540 }} onClick={(e) => e.stopPropagation()}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
              <h2 style={{ fontSize: 18, fontWeight: 800 }}>Scan Audit Details</h2>
              <button className="btn btn-ghost" onClick={() => setSelectedScan(null)}>✕</button>
            </div>

            <div style={{ marginBottom: 12 }}>
              <span className={`badge badge-${selectedScan.risk_level}`} style={{ marginRight: 8 }}>
                {selectedScan.risk_level} ({selectedScan.risk_score}/100)
              </span>
              <span style={{ fontSize: 12, color: "#64748B" }}>
                Method: {selectedScan.detection_method.toUpperCase()}
              </span>
            </div>

            <div style={{ background: "var(--bg-surface)", border: "1px solid var(--border-subtle)", padding: 12, borderRadius: 8, fontSize: 12, wordBreak: "break-all", marginBottom: 16 }}>
              <strong>Submitted Content:</strong>
              <p style={{ marginTop: 4, color: "var(--text-sub)" }}>{selectedScan.submitted_content}</p>
            </div>

            {selectedScan.explanation && (
              <div style={{ marginBottom: 16 }}>
                <strong style={{ fontSize: 12, textTransform: "uppercase", color: "#64748B" }}>Explanation:</strong>
                <p style={{ fontSize: 13, marginTop: 4, lineHeight: 1.4 }}>{selectedScan.explanation}</p>
              </div>
            )}

            <div style={{ marginBottom: 16 }}>
              <strong style={{ fontSize: 12, textTransform: "uppercase", color: "#64748B" }}>Warning Signs:</strong>
              <ul style={{ marginTop: 6, display: "flex", flexDirection: "column", gap: 6, listStyle: "none" }}>
                {selectedScan.indicators?.length > 0 ? (
                  selectedScan.indicators.map((ind, idx) => (
                    <li key={idx} style={{ fontSize: 12, display: "flex", gap: 6 }}>
                      <span className={`badge badge-${ind.severity}`}>{ind.severity}</span>
                      <span>{ind.description}</span>
                    </li>
                  ))
                ) : (
                  <li style={{ fontSize: 12, color: "#166534" }}>✅ No scam indicators detected.</li>
                )}
              </ul>
            </div>

            {/* Accuracy Feedback */}
            <div style={{ borderTop: "1px solid #E2E8F0", paddingTop: 12, marginTop: 16 }}>
              <span style={{ fontSize: 12, fontWeight: 700, color: "#64748B" }}>Rate Detection Accuracy:</span>
              <div style={{ display: "flex", gap: 8, marginTop: 8 }}>
                <button className="btn btn-ghost" onClick={() => handleFeedback("correct")}>👍 Accurate</button>
                <button className="btn btn-ghost" onClick={() => handleFeedback("false_positive")}>⚠️ False Alarm</button>
                <button className="btn btn-ghost" onClick={() => handleFeedback("false_negative")}>❌ Missed Scam</button>
              </div>
              {feedbackSuccess && (
                <p style={{ color: "#16A34A", fontSize: 12, marginTop: 6 }}>{feedbackSuccess}</p>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
