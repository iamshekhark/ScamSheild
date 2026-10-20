# ScamShield — Security & Privacy Architecture

## 1. Threat Model & Defense Strategy

### A. Prompt Injection Defense
Scanned messages, SMS, and website content are treated as **untrusted data payloads** and never as system instructions.
- All scanned content transmitted to the server-side AI provider is enclosed in isolated delimiters (`"""`).
- Edge Function system prompts strictly instruct the model to ignore instructions contained inside submitted content.
- Deterministic rules run first: if high-confidence threats (such as OTP extraction, known brand phishing, or raw IP hosts) are identified, rule evidence cannot be suppressed by AI output.

### B. Prevention of Server-Side Request Forgery (SSRF)
- The ScamShield backend does **not blindly fetch or scrape submitted URLs**.
- URL analysis is performed offline / lexically (parsing scheme, hostname, TLD, subdomain depth, entropy, look-alike Levenshtein distances) and cross-referenced with internal threat intelligence tables.
- No arbitrary internal microservices, loopback IPs (`127.0.0.1`), or cloud metadata endpoints (`169.254.169.254`) can be accessed by user-submitted links.

### C. Row Level Security (RLS) & Multi-Tenant Isolation
Every user-owned table (`profiles`, `user_preferences`, `scan_history`, `scam_indicators`, `user_feedback`, `ai_insights`) enforces PostgreSQL Row Level Security:
- Policies mandate `USING (auth.uid() = user_id)`.
- Users cannot read, tamper with, or delete scans belonging to other accounts, even if IDs are altered in client requests.
- The `threat_intelligence` table is read-only for public/authenticated users and writable only by internal server processes (`service_role`).

### D. Data Minimization & Privacy Controls
- Guest mode runs 100% locally using the client-side `rules.js` engine. No guest scan is ever uploaded without explicit user consent.
- Submitted scan contents are minimized and capped before storage.
- Users can toggle `save_scan_history` and `allow_ai_analysis` in their settings at any time.
- Full GDPR erasure and data export (JSON) are built directly into the Settings panel.
