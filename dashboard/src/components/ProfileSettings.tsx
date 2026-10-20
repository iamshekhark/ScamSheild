import React, { useState } from "react";
import type { UserPreferences, ScanRecord } from "../lib/supabase";

interface ProfileSettingsProps {
  userEmail: string;
  scans: ScanRecord[];
  preferences: UserPreferences;
  onUpdatePreferences: (newPrefs: Partial<UserPreferences>) => Promise<void>;
  onClearHistory: () => Promise<void>;
  onDeleteAccount: () => Promise<void>;
  onSignOut: () => Promise<void>;
}

export const ProfileSettings: React.FC<ProfileSettingsProps> = ({
  userEmail,
  scans,
  preferences,
  onUpdatePreferences,
  onClearHistory,
  onDeleteAccount,
  onSignOut,
}) => {
  const [theme, setTheme] = useState("system");
  const [saveHistory, setSaveHistory] = useState(preferences.save_scan_history);
  const [allowAi, setAllowAi] = useState(preferences.allow_ai_analysis);
  const [isSaving, setIsSaving] = useState(false);

  const handleSave = async () => {
    setIsSaving(true);
    try {
      await onUpdatePreferences({
        save_scan_history: saveHistory,
        allow_ai_analysis: allowAi,
      });
      alert("Preferences saved successfully.");
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : "Failed to update preferences");
    } finally {
      setIsSaving(false);
    }
  };

  const handleExportData = () => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(scans, null, 2));
    const downloadAnchor = document.createElement("a");
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `scamshield_export_${new Date().toISOString().slice(0, 10)}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  return (
    <div style={{ maxWidth: 720, margin: "0 auto", display: "flex", flexDirection: "column", gap: 20 }}>
      {/* Account Profile Card */}
      <div className="card">
        <h2 style={{ fontSize: 18, fontWeight: 800, marginBottom: 16 }}>User Profile & Authentication</h2>
        <div style={{ display: "flex", alignItems: "center", gap: 16, marginBottom: 16 }}>
          <div style={{ width: 48, height: 48, borderRadius: "50%", background: "rgba(6, 182, 212, 0.12)", border: "1px solid rgba(6, 182, 212, 0.3)", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 22 }}>
            👤
          </div>
          <div>
            <p style={{ fontWeight: 800, fontSize: 16 }}>{userEmail}</p>
            <p style={{ color: "var(--text-dim)", fontSize: 12 }}>Connected via Supabase Auth</p>
          </div>
        </div>

        <button className="btn btn-ghost" onClick={onSignOut}>Sign Out</button>
      </div>

      {/* Preferences & Privacy Controls */}
      <div className="card">
        <h2 style={{ fontSize: 18, fontWeight: 800, marginBottom: 16 }}>Privacy & Security Preferences</h2>
        
        <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
          <div>
            <label style={{ fontSize: 13, fontWeight: 700, display: "block", marginBottom: 6 }}>Dashboard Theme</label>
            <select className="input-field" value={theme} onChange={(e) => setTheme(e.target.value)}>
              <option value="system">System Default</option>
              <option value="light">Light Mode</option>
              <option value="dark">Dark Mode</option>
            </select>
          </div>

          <div style={{ display: "flex", alignItems: "flex-start", gap: 12 }}>
            <input
              type="checkbox"
              id="pref-save"
              style={{ marginTop: 3 }}
              checked={saveHistory}
              onChange={(e) => setSaveHistory(e.target.checked)}
            />
            <div>
              <label htmlFor="pref-save" style={{ fontWeight: 700, fontSize: 13, cursor: "pointer" }}>
                Persist Scan History to Database
              </label>
              <p style={{ fontSize: 12, color: "#64748B", marginTop: 2 }}>
                When enabled, your scans are encrypted and saved under Row Level Security for personalized trends.
              </p>
            </div>
          </div>

          <div style={{ display: "flex", alignItems: "flex-start", gap: 12 }}>
            <input
              type="checkbox"
              id="pref-ai"
              style={{ marginTop: 3 }}
              checked={allowAi}
              onChange={(e) => setAllowAi(e.target.checked)}
            />
            <div>
              <label htmlFor="pref-ai" style={{ fontWeight: 700, fontSize: 13, cursor: "pointer" }}>
                Enable Server-Side AI Scam Explanations
              </label>
              <p style={{ fontSize: 12, color: "#64748B", marginTop: 2 }}>
                Allows our secure backend model to generate detailed plain-language fraud explanations.
              </p>
            </div>
          </div>

          <button className="btn btn-primary" style={{ alignSelf: "flex-start" }} onClick={handleSave} disabled={isSaving}>
            {isSaving ? "Saving…" : "Save Preferences"}
          </button>
        </div>
      </div>

      {/* Data Management & GDPR Controls */}
      <div className="card">
        <h2 style={{ fontSize: 18, fontWeight: 800, marginBottom: 16 }}>Data Export & Erasure Controls</h2>
        <p style={{ fontSize: 13, color: "#64748B", marginBottom: 16, lineHeight: 1.5 }}>
          In accordance with privacy standards (GDPR / CCPA), you hold full ownership of your data. You may download your complete telemetry history or permanently erase your account.
        </p>

        <div style={{ display: "flex", flexWrap: "wrap", gap: 12 }}>
          <button className="btn btn-ghost" onClick={handleExportData}>
            📥 Export My Scan Data (JSON)
          </button>
          <button
            className="btn btn-danger"
            onClick={() => {
              if (confirm("Are you sure you want to clear all your saved scans? This cannot be undone.")) {
                onClearHistory();
              }
            }}
          >
            Clear All Scan History
          </button>
          <button
            className="btn btn-danger"
            style={{ background: "#DC2626", color: "#FFFFFF" }}
            onClick={() => {
              if (confirm("PERMANENT ACTION: Are you sure you want to delete your entire account and all records?")) {
                onDeleteAccount();
              }
            }}
          >
            Delete Account Permanently
          </button>
        </div>
      </div>
    </div>
  );
};
