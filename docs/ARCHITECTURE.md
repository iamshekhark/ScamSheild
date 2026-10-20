# ScamShield — System Architecture & Data Flow

```mermaid
flowchart TD
    subgraph ClientLayer ["1. Client Interfaces"]
        Ext["Browser Extension (MV3)<br/>Chrome, Edge, Brave, Firefox<br/>Popup / Context Menu / Background Worker"]
        Dash["Web Insights Dashboard<br/>React 18 + TypeScript + Vite<br/>Overview, Analytics, History, Settings"]
    end

    subgraph AuthLayer ["2. Identity & Access Layer"]
        SupaAuth["Supabase Auth (GoTrue)<br/>JWT Session Tokens · Row Level Security"]
    end

    subgraph EdgeLayer ["3. Backend Edge Functions (Deno / TypeScript)"]
        F1["analyze-scam<br/>Hybrid Ensemble: Rules + AI + Threat Intel"]
        F2["get-scan-history<br/>Paginated User-Scoped Scans"]
        F3["generate-insights<br/>Evidence-Based Trend Summaries"]
        F4["submit-feedback<br/>Accuracy & False Alarm Feedback"]
        F5["delete-account-data<br/>GDPR Erasure & Single Scan Deletion"]
        F6["threat-check<br/>Known Threat Indicator Lookups"]
    end

    subgraph StorageLayer ["4. Persistent Storage (PostgreSQL)"]
        T1[("profiles")]
        T2[("scan_history")]
        T3[("scam_indicators")]
        T4[("user_preferences")]
        T5[("threat_intelligence")]
        T6[("ai_insights")]
        T7[("user_feedback")]
    end

    subgraph AiLayer ["5. Server-Side AI Intelligence"]
        AI["Gemini / OpenAI Model<br/>Strict Prompt-Injection Isolated Execution"]
    end

    Ext -->|"1-Click Audit / Link / Text"| F1
    Ext -->|"Sync Local State"| SupaAuth
    Dash -->|"Telemetry & User Controls"| EdgeLayer
    Dash -->|"Auth & Realtime"| SupaAuth

    F1 -->|"Ensemble Scoring"| AI
    F1 -->|"Threat Query & Scans Persistence"| StorageLayer
    F2 --> StorageLayer
    F3 --> StorageLayer
    F4 --> StorageLayer
    F5 --> StorageLayer
    F6 --> StorageLayer
    SupaAuth -->|"User Provisioning Trigger"| T1
```

---

## Component Responsibilities

| Component | Responsibility | Privacy & Security Boundary |
|---|---|---|
| **Extension (`extension/`)** | Zero-latency local auditing, URL/Text input, tab inspection, context menus, offline engine fallback | Minimum permissions (`activeTab`, `storage`, `contextMenus`). Never transmits credentials or unconsented data. |
| **Edge Functions (`supabase/functions/`)** | Hybrid score calculation, threat intel correlation, bounded AI calls with prompt injection defenses | Stateless serverless execution. Never exposes privileged keys to client devices. |
| **Database (`supabase/migrations/`)** | Profiles, Scans, Indicators, Preferences, Insights | PostgreSQL with strict Row Level Security (RLS) on all user tables. |
| **Dashboard (`dashboard/`)** | Executive risk overview, trend visualization, export/deletion controls | Authenticated user session scoping via Supabase Auth JWT. |
