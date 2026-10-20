import React, { useState } from "react";
import type { ScanRecord } from "../lib/supabase";

interface RiskAnalyticsProps {
  scans: ScanRecord[];
}

export const RiskAnalytics: React.FC<RiskAnalyticsProps> = ({ scans }) => {
  const [filterType, setFilterType] = useState<string>("all");

  const filtered = scans.filter((s) => filterType === "all" || s.scan_type === filterType);

  const counts = {
    low: filtered.filter((s) => s.risk_level === "low").length,
    medium: filtered.filter((s) => s.risk_level === "medium").length,
    high: filtered.filter((s) => s.risk_level === "high").length,
    critical: filtered.filter((s) => s.risk_level === "critical").length,
  };

  const maxRisk = Math.max(1, counts.low, counts.medium, counts.high, counts.critical);

  // Indicator category breakdown
  const categoryMap: Record<string, number> = {};
  filtered.forEach((s) => {
    s.indicators?.forEach((ind) => {
      const type = ind.indicator_type || "UNKNOWN";
      categoryMap[type] = (categoryMap[type] || 0) + 1;
    });
  });

  const categories = Object.entries(categoryMap).sort((a, b) => b[1] - a[1]);
  const maxCat = Math.max(1, ...categories.map((c) => c[1]));

  return (
    <div>
      <div className="filter-row">
        <label style={{ fontSize: 13, fontWeight: 700, color: "#64748B" }}>Filter by Input Type:</label>
        <select
          value={filterType}
          onChange={(e) => setFilterType(e.target.value)}
          className="input-field"
        >
          <option value="all">All Scan Types ({scans.length})</option>
          <option value="url">URLs</option>
          <option value="text">Text / SMS</option>
          <option value="email">Emails</option>
          <option value="message">Messages</option>
          <option value="screenshot">Screenshots</option>
        </select>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20 }}>
        {/* Risk Distribution Chart */}
        <div className="card">
          <h2 style={{ fontSize: 16, fontWeight: 800, marginBottom: 16 }}>Risk Severity Distribution</h2>
          <div className="chart-bar-container">
            <div className="chart-bar-col">
              <span className="chart-bar-count">{counts.low}</span>
              <div
                className="chart-bar-rect"
                style={{ height: `${(counts.low / maxRisk) * 100}%`, background: "#22C55E" }}
              />
              <span className="chart-bar-label">Low (0-24)</span>
            </div>

            <div className="chart-bar-col">
              <span className="chart-bar-count">{counts.medium}</span>
              <div
                className="chart-bar-rect"
                style={{ height: `${(counts.medium / maxRisk) * 100}%`, background: "#F59E0B" }}
              />
              <span className="chart-bar-label">Med (25-49)</span>
            </div>

            <div className="chart-bar-col">
              <span className="chart-bar-count">{counts.high}</span>
              <div
                className="chart-bar-rect"
                style={{ height: `${(counts.high / maxRisk) * 100}%`, background: "#EA580C" }}
              />
              <span className="chart-bar-label">High (50-74)</span>
            </div>

            <div className="chart-bar-col">
              <span className="chart-bar-count">{counts.critical}</span>
              <div
                className="chart-bar-rect"
                style={{ height: `${(counts.critical / maxRisk) * 100}%`, background: "#EF4444" }}
              />
              <span className="chart-bar-label">Crit (75-100)</span>
            </div>
          </div>
        </div>

        {/* Top Scam Categories */}
        <div className="card">
          <h2 style={{ fontSize: 16, fontWeight: 800, marginBottom: 16 }}>Top Triggered Scam Indicators</h2>
          {categories.length === 0 ? (
            <p style={{ textAlign: "center", color: "#64748B", padding: "40px 0" }}>
              No threat indicators detected yet in filtered scans.
            </p>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
              {categories.slice(0, 5).map(([cat, count]) => (
                <div key={cat}>
                  <div style={{ display: "flex", justifyContent: "space-between", fontSize: 12, fontWeight: 700, marginBottom: 4 }}>
                    <span>{cat.replace(/_/g, " ")}</span>
                    <span style={{ color: "#64748B" }}>{count} times</span>
                  </div>
                  <div style={{ height: 8, background: "#E2E8F0", borderRadius: 4, overflow: "hidden" }}>
                    <div
                      style={{
                        height: "100%",
                        width: `${(count / maxCat) * 100}%`,
                        background: "#1F4FD8",
                        borderRadius: 4
                      }}
                    />
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
