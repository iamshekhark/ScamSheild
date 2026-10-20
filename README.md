# ScamShield — Full-Stack AI Scam & Phishing Detection Platform

> **Explainable Multimodal Scam Detection, Browser Extension, Cloud Sync & Personalized Security Insights Dashboard**

---

## 🌟 Architecture Overview

```text
scamshield-extension/
├── extension/             Universal Browser Extension (Manifest V3)
│   ├── manifest.json      Multi-browser configuration (Chrome, Edge, Brave, Firefox)
│   ├── popup.html/css/js  Tabbed UI: Scanner, History, Account, Settings
│   ├── rules.js           Deterministic Offline Detection Engine
│   ├── auth.js            Supabase Auth Client & Session Manager
│   ├── api.js             Service Layer with offline fallback
│   ├── storage.js         Secure Chrome Storage Wrapper
│   └── background.js      Context menus & toolbar security badge
├── dashboard/             Web Insights Dashboard (React 18 + TypeScript + Vite)
│   ├── src/components/    Overview, RiskAnalytics, AiInsights, ScanHistory, ProfileSettings
│   └── src/lib/           Supabase client, types, and analytics services
├── supabase/              Backend Infrastructure
│   ├── config.toml        Local Supabase configuration
│   ├── migrations/        PostgreSQL schema with Row Level Security (RLS)
│   └── functions/         Supabase Edge Functions (Deno / TypeScript)
│       ├── analyze-scam/  Hybrid pipeline: Rules + Threat Intel + AI
│       ├── get-scan-history/ Paginated scans per user
│       ├── generate-insights/ Evidence-based risk summaries
│       ├── submit-feedback/ Accuracy feedback loops
│       ├── delete-account-data/ GDPR erasure and scan deletion
│       └── threat-check/  Fast threat intelligence lookups
├── tests/                 Automated unit and integration test suite
├── docs/                  Architecture diagrams, Threat Model & Security policies
└── .env.example           Environment variables template
```

---

## 🚀 Quick Start Guide

### 1. Load the Browser Extension
1. Open your browser:
   - Chrome / Brave: `chrome://extensions` (or `brave://extensions`)
   - Edge: `edge://extensions`
2. Turn ON **"Developer mode"** in the top-right corner.
3. Click **"Load unpacked"** and select the folder:
   ```text
   C:\vs code\scamshield-extension\extension
   ```
4. Pin **ScamShield** to your toolbar!
   - Works immediately in **⚡ Offline Engine mode** with 0 backend dependencies.
   - Or toggle to **🌐 Server Mode** in Settings.

---

### 2. Run the Web Insights Dashboard
```bash
cd "C:\vs code\scamshield-extension\dashboard"
npm install
npm run dev
```
Open **[http://localhost:5173](http://localhost:5173)** to access the dashboard.
To create a production build:
```bash
npm run build
```

---

### 3. Deploy the Backend (Supabase)

#### Option A: Apply Migrations to Your Supabase Project
1. Log in to your [Supabase Dashboard](https://supabase.com/dashboard).
2. Go to **SQL Editor** -> Click **New Query**.
3. Copy the contents of:
   ```text
   supabase/migrations/20261018000000_init_scamshield_schema.sql
   ```
4. Click **Run**. This establishes:
   - All 7 database tables (`profiles`, `scan_history`, `scam_indicators`, `user_feedback`, `user_preferences`, `threat_intelligence`, `ai_insights`)
   - Row Level Security (RLS) policies
   - Automated user provisioning triggers (`handle_new_user`)

#### Option B: Deploy Edge Functions
Set your project secrets in Supabase CLI or dashboard:
```bash
supabase secrets set AI_API_KEY="your-gemini-or-openai-api-key" AI_MODEL="gemini-1.5-flash"
supabase functions deploy analyze-scam
supabase functions deploy get-scan-history
supabase functions deploy generate-insights
supabase functions deploy submit-feedback
supabase functions deploy delete-account-data
supabase functions deploy threat-check
```

---

## 🧪 Automated Tests

Run the complete test suite:
```bash
cd "C:\vs code\scamshield-extension"

# Test core deterministic rules & score normalization
node --test tests/rules.test.js

# Test storage, auth boundaries, and privacy defaults
node --test tests/auth_security.test.js
```

---

## 🛡️ Security & Privacy Guardrails

- **Zero-Latency Offline Mode:** Guest users scan without network transmission using the embedded `rules.js` engine.
- **Isolated Untrusted Payloads:** Scanned text and URLs are treated as data, preventing prompt injection against AI models.
- **Strict Row Level Security (RLS):** Every user can only read or delete their own scans.
- **GDPR / CCPA Erasure:** 1-click JSON export and permanent account data erasure available in Settings.
