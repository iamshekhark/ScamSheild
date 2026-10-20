// ScamShield Nodemailer Mail Microservice
// Express HTTP server with API-key authentication, rate limiting, and branded email dispatch

require("dotenv").config();
const express = require("express");
const { MailerService } = require("./mailer");
const {
  verificationCodeEmail,
  passwordResetEmail,
  welcomeEmail,
  awarenessAdvisoryEmail,
  highRiskAlertEmail
} = require("./templates");

const PORT = parseInt(process.env.PORT || "8787", 10);
const API_KEY = process.env.MAIL_SERVICE_API_KEY || "";
const RATE_LIMIT_MAX = parseInt(process.env.RATE_LIMIT_PER_MINUTE || "60", 10);

const app = express();

// ---------------------------------------------------------------------------
// 0. Cross-Origin Resource Sharing (CORS) Middleware
// ---------------------------------------------------------------------------
const ALLOWED_ORIGINS = new Set([
  "http://localhost:5173",
  "http://localhost:5174",
  "http://127.0.0.1:5173",
  "http://127.0.0.1:5174",
  "http://localhost:3000"
]);
if (process.env.ALLOWED_ORIGIN) {
  process.env.ALLOWED_ORIGIN.split(",").forEach((o) => ALLOWED_ORIGINS.add(o.trim()));
}

function isOriginAllowed(origin) {
  if (!origin) return false;
  if (ALLOWED_ORIGINS.has(origin)) return true;
  if (origin.startsWith("chrome-extension://")) return true;
  if (origin.endsWith(".onrender.com")) return true;
  if (origin.endsWith(".vercel.app")) return true;
  return false;
}

app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && isOriginAllowed(origin)) {
    res.header("Access-Control-Allow-Origin", origin);
    res.header("Vary", "Origin");
    res.header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key");
  }
  if (req.method === "OPTIONS") {
    if (origin && isOriginAllowed(origin)) {
      return res.sendStatus(204);
    }
    return res.status(403).json({ error: "Origin not allowed by CORS" });
  }
  next();
});

app.use(express.json({ limit: "500kb" }));

const mailer = new MailerService();

// ---------------------------------------------------------------------------
// 1. In-Memory Sliding-Window Rate Limiter
// ---------------------------------------------------------------------------
const rateLimitMap = new Map();

function rateLimiter(req, res, next) {
  if (req.method === "OPTIONS") return next();

  const ip = req.ip || req.connection.remoteAddress || "unknown";
  const now = Date.now();
  const windowMs = 60 * 1000;

  let record = rateLimitMap.get(ip);
  if (!record || now - record.startTime > windowMs) {
    record = { startTime: now, count: 1 };
    rateLimitMap.set(ip, record);
    return next();
  }

  record.count += 1;
  if (record.count > RATE_LIMIT_MAX) {
    return res.status(429).json({
      error: "Too Many Requests",
      message: `Rate limit exceeded. Maximum ${RATE_LIMIT_MAX} requests per minute allowed.`
    });
  }

  next();
}

// ---------------------------------------------------------------------------
// 2. Server-to-Server API Key Authentication Middleware
// ---------------------------------------------------------------------------
function requireApiKey(req, res, next) {
  const origin = req.headers.origin || "";
  const isLocalOrigin = origin.startsWith("http://localhost:") || origin.startsWith("http://127.0.0.1:") || origin.startsWith("chrome-extension://");
  const isAllowedOrigin = isOriginAllowed(origin) || isLocalOrigin;
  const isLocalIp = req.ip === "127.0.0.1" || req.ip === "::1" || req.ip === "::ffff:127.0.0.1";

  // Allow health endpoint, preflight OPTIONS, local OAuth PKCE flow, and local UI dispatch without API key
  if (req.path === "/health" || req.method === "OPTIONS" || req.path.startsWith("/oauth/") || isAllowedOrigin || isLocalIp) {
    return next();
  }

  // If no API_KEY configured on server, warn and reject in production
  if (!API_KEY) {
    console.warn("[MailService] WARNING: MAIL_SERVICE_API_KEY is not set on the server.");
    return res.status(500).json({
      error: "Server Configuration Error",
      message: "MAIL_SERVICE_API_KEY is not configured on the mail service."
    });
  }

  const authHeader = req.headers["authorization"] || "";
  const xApiKey = req.headers["x-api-key"] || "";

  let providedKey = "";
  if (xApiKey) {
    providedKey = xApiKey;
  } else if (authHeader.startsWith("Bearer ")) {
    providedKey = authHeader.replace(/^Bearer\s+/i, "").trim();
  }

  if (!providedKey || providedKey !== API_KEY) {
    return res.status(401).json({
      error: "Unauthorized",
      message: "Invalid or missing API key."
    });
  }

  next();
}

// Apply Middlewares
app.use(rateLimiter);
app.use(requireApiKey);

// ---------------------------------------------------------------------------
// 3. API Endpoints
// ---------------------------------------------------------------------------

// Health & Status Check
app.get("/health", async (req, res) => {
  const connStatus = await mailer.verifyConnection();
  res.status(200).json({
    status: "ok",
    service: "scamshield-mail-service",
    version: "1.0.0",
    smtp: connStatus
  });
});

// Generic Transactional Email Dispatch (compatible with Supabase emailSender)
app.post("/send", async (req, res) => {
  try {
    const { to, subject, html, text, notificationType, deduplicationKey } = req.body || {};

    if (!to || (!html && !text)) {
      return res.status(400).json({
        error: "Bad Request",
        message: "Missing required fields: 'to' and either 'html' or 'text' are required."
      });
    }

    const result = await mailer.sendMail({
      to,
      subject: subject || "ScamShield Security Notification",
      html,
      text
    });

    return res.status(200).json({
      success: true,
      messageId: result.messageId,
      accepted: result.accepted
    });
  } catch (err) {
    console.error("[MailService /send] Error:", err.message);
    return res.status(500).json({
      success: false,
      error: err.message
    });
  }
});

// Branded 6-Digit OTP Verification Code Dispatch
app.post("/send-verification-code", async (req, res) => {
  try {
    const { email, code, purpose = "registration", expiryMinutes = 10 } = req.body || {};

    if (!email || !mailer.validateEmail(email)) {
      return res.status(400).json({
        error: "Bad Request",
        message: "Valid 'email' address is required."
      });
    }

    if (!code || typeof code !== "string" || !/^\d{6}$/.test(code.trim())) {
      return res.status(400).json({
        error: "Bad Request",
        message: "A 6-digit numeric verification 'code' is required."
      });
    }

    const template = verificationCodeEmail({
      code: code.trim(),
      email: email.trim(),
      purpose,
      expiryMinutes
    });

    const result = await mailer.sendMail({
      to: email.trim(),
      subject: template.subject,
      html: template.html,
      text: template.text
    });

    return res.status(200).json({
      success: true,
      email: email.trim(),
      purpose,
      messageId: result.messageId
    });
  } catch (err) {
    console.error("[MailService /send-verification-code] Error:", err.message);
    return res.status(500).json({
      success: false,
      error: err.message
    });
  }
});

// Dedicated Password Reset / Change Password OTP Dispatch
app.post("/send-password-reset", async (req, res) => {
  try {
    const { email, code, expiryMinutes = 10 } = req.body || {};

    if (!email || !mailer.validateEmail(email)) {
      return res.status(400).json({
        error: "Bad Request",
        message: "Valid 'email' address is required."
      });
    }

    if (!code || typeof code !== "string" || !/^\d{6}$/.test(code.trim())) {
      return res.status(400).json({
        error: "Bad Request",
        message: "A 6-digit numeric verification 'code' is required."
      });
    }

    const template = passwordResetEmail({
      email: email.trim(),
      code: code.trim(),
      expiryMinutes
    });

    const result = await mailer.sendMail({
      to: email.trim(),
      subject: template.subject,
      html: template.html,
      text: template.text
    });

    return res.status(200).json({
      success: true,
      email: email.trim(),
      messageId: result.messageId
    });
  } catch (err) {
    console.error("[MailService /send-password-reset] Error:", err.message);
    return res.status(500).json({
      success: false,
      error: err.message
    });
  }
});

// Welcome / Onboarding Email Dispatch
app.post("/send-welcome", async (req, res) => {
  try {
    const { name, email } = req.body || {};

    if (!email || !mailer.validateEmail(email)) {
      return res.status(400).json({
        error: "Bad Request",
        message: "Valid 'email' address is required."
      });
    }

    const template = welcomeEmail({
      name: name || "Security Defender",
      email: email.trim()
    });

    const result = await mailer.sendMail({
      to: email.trim(),
      subject: template.subject,
      html: template.html,
      text: template.text
    });

    return res.status(200).json({
      success: true,
      email: email.trim(),
      messageId: result.messageId
    });
  } catch (err) {
    console.error("[MailService /send-welcome] Error:", err.message);
    return res.status(500).json({
      success: false,
      error: err.message
    });
  }
});

// Cyber Awareness & Security Advisory Bulletin Dispatch
app.post("/send-awareness", async (req, res) => {
  try {
    const { email, title, topic, summary, tips } = req.body || {};

    if (!email || !mailer.validateEmail(email)) {
      return res.status(400).json({
        error: "Bad Request",
        message: "Valid 'email' address is required."
      });
    }

    const template = awarenessAdvisoryEmail({
      email: email.trim(),
      title,
      topic,
      summary,
      tips
    });

    const result = await mailer.sendMail({
      to: email.trim(),
      subject: template.subject,
      html: template.html,
      text: template.text
    });

    return res.status(200).json({
      success: true,
      email: email.trim(),
      topic: template.subject,
      messageId: result.messageId
    });
  } catch (err) {
    console.error("[MailService /send-awareness] Error:", err.message);
    return res.status(500).json({
      success: false,
      error: err.message
    });
  }
});

// Branded Security & Phishing Alert Dispatch
app.post("/send-alert", async (req, res) => {
  try {
    const { to, sender, subject, riskScore, riskLevel, explanation } = req.body || {};

    if (!to || !mailer.validateEmail(to)) {
      return res.status(400).json({
        error: "Bad Request",
        message: "Valid 'to' recipient email address is required."
      });
    }

    const template = highRiskAlertEmail({
      sender,
      subject,
      riskScore,
      riskLevel,
      explanation
    });

    const result = await mailer.sendMail({
      to: to.trim(),
      subject: template.subject,
      html: template.html,
      text: template.text
    });

    return res.status(200).json({
      success: true,
      recipient: to.trim(),
      messageId: result.messageId
    });
  } catch (err) {
    console.error("[MailService /send-alert] Error:", err.message);
    return res.status(500).json({
      success: false,
      error: err.message
    });
  }
});

// ---------------------------------------------------------------------------
// 6. OAuth Token Exchange & Email Audit Service (Encrypted Persistence & Heuristics)
// ---------------------------------------------------------------------------
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const TOKEN_CACHE_FILE = process.env.TOKEN_CACHE_FILE || path.join(__dirname, "..", ".token_cache.json");

function getStorageEncryptionKey() {
  const secret = process.env.TOKEN_ENCRYPTION_KEY || process.env.MAIL_SERVICE_API_KEY;
  if (!secret) {
    throw new Error("CRITICAL_SECURITY_ERROR: TOKEN_ENCRYPTION_KEY or MAIL_SERVICE_API_KEY must be configured for encrypted token cache.");
  }
  return crypto.createHash("sha256").update(String(secret)).digest();
}

function encryptCachePayload(plainText) {
  const key = getStorageEncryptionKey();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  let encrypted = cipher.update(plainText, "utf8", "hex");
  encrypted += cipher.final("hex");
  const authTag = cipher.getAuthTag().toString("hex");
  return {
    version: "aes-256-gcm",
    iv: iv.toString("hex"),
    tag: authTag,
    data: encrypted
  };
}

function decryptCachePayload(envelope) {
  if (!envelope || envelope.version !== "aes-256-gcm" || !envelope.iv || !envelope.tag || !envelope.data) {
    throw new Error("Invalid or unencrypted token cache envelope");
  }
  const key = getStorageEncryptionKey();
  const iv = Buffer.from(envelope.iv, "hex");
  const authTag = Buffer.from(envelope.tag, "hex");
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(authTag);
  let decrypted = decipher.update(envelope.data, "hex", "utf8");
  decrypted += decipher.final("utf8");
  return decrypted;
}

function loadStoredTokens() {
  try {
    if (fs.existsSync(TOKEN_CACHE_FILE)) {
      const raw = fs.readFileSync(TOKEN_CACHE_FILE, "utf-8");
      const envelope = JSON.parse(raw);
      const decryptedJson = decryptCachePayload(envelope);
      const obj = JSON.parse(decryptedJson);
      return new Map(Object.entries(obj));
    }
  } catch (err) {
    console.warn("[MailService] Warning: Could not load encrypted token cache:", err.message);
  }
  return new Map();
}

function persistStoredTokens(tokensMap) {
  const obj = Object.fromEntries(tokensMap);
  const envelope = encryptCachePayload(JSON.stringify(obj));
  fs.writeFileSync(TOKEN_CACHE_FILE, JSON.stringify(envelope, null, 2), { mode: 0o600 });
}

const mailTokens = loadStoredTokens();

function setMailToken(email, data) {
  mailTokens.set(email, data);
  persistStoredTokens(mailTokens);
}

function evaluateEmailRules(sender, subject, bodyText) {
  const indicators = [];
  let score = 0;
  const content = `${sender} ${subject} ${bodyText}`.toLowerCase();

  // 1. Sender Spoofing / Impersonation
  if (sender.includes("<") && sender.includes(">")) {
    const displayName = sender.split("<")[0].trim().toLowerCase();
    const address = sender.split("<")[1].replace(">", "").trim().toLowerCase();

    const trustedBrands = ["paypal", "paytm", "amazon", "apple", "google", "microsoft", "netflix", "hdfc", "sbi"];
    for (const b of trustedBrands) {
      if (displayName.includes(b) && !address.endsWith(`@${b}.com`)) {
        indicators.push({
          indicator_type: "SENDER_IMPERSONATION",
          description: `Sender displays brand '${b.toUpperCase()}' but originates from untrusted domain '${address}'`,
          severity: "critical"
        });
        score += 55;
        break;
      }
    }
  }

  // 2. Urgent Extortion / Account Suspension
  if (/(account.*suspend|account.*block|verify.*immediately|urgent action required|terminate.*access)/i.test(content)) {
    indicators.push({
      indicator_type: "URGENT_EXTORTION",
      description: "Aggressive urgency wording threatening account suspension or service termination",
      severity: "high"
    });
    score += 35;
  }

  // 3. OTP or Password Harvesting
  if (/(share.*otp|enter.*otp|provide.*password|send.*code|wire.*funds|crypto.*transfer)/i.test(content)) {
    indicators.push({
      indicator_type: "CREDENTIAL_HARVESTING",
      description: "Requests confidential OTP verification codes, credentials, or wire transfers",
      severity: "critical"
    });
    score += 50;
  }

  // 4. Overdue Invoices
  if (/(invoice.*attached|payment.*overdue|wire.*amount|gift card|bitcoin wallet)/i.test(content)) {
    indicators.push({
      indicator_type: "FINANCIAL_FRAUD",
      description: "Mentions unsolicited invoice, overdue bill, or cryptocurrency transaction",
      severity: "medium"
    });
    score += 25;
  }

  const finalScore = Math.min(100, score);
  let riskLevel = "safe";
  if (finalScore >= 75) riskLevel = "critical";
  else if (finalScore >= 50) riskLevel = "high";
  else if (finalScore >= 25) riskLevel = "medium";
  else if (finalScore > 0) riskLevel = "low";

  const explanation = finalScore > 50
    ? "High-risk scam indicators detected in message headers and content."
    : finalScore > 0
    ? "Low-level promotional or unsolicited pattern detected."
    : "Legitimate email with authentic sender headers and no suspicious links or urgent extortion detected.";

  const recommendations = finalScore > 50
    ? ["Do not click links or reply to this email.", "Mark as Phishing in your email provider."]
    : ["Standard safe email. No action required."];

  return { score: finalScore, level: riskLevel, indicators, explanation, recommendations };
}

async function fetchAndAuditGmailMessages(accessToken) {
  try {
    const listRes = await fetch("https://gmail.googleapis.com/gmail/v1/users/me/messages?maxResults=10", {
      headers: { Authorization: `Bearer ${accessToken}` }
    });
    if (listRes.status === 401) {
      const err = new Error("Gmail access token expired or unauthorized");
      err.status = 401;
      throw err;
    }
    if (!listRes.ok) {
      console.warn("[Gmail API] list messages status:", listRes.status);
      return [];
    }
    const listData = await listRes.json();
    const messages = listData.messages || [];
    const auditResults = [];

    for (const item of messages) {
      try {
        const msgRes = await fetch(`https://gmail.googleapis.com/gmail/v1/users/me/messages/${item.id}?format=metadata&metadataHeaders=From&metadataHeaders=Subject&metadataHeaders=Date`, {
          headers: { Authorization: `Bearer ${accessToken}` }
        });
        if (!msgRes.ok) continue;
        const msgData = await msgRes.json();
        const headers = msgData.payload?.headers || [];
        const fromHeader = headers.find((h) => h.name.toLowerCase() === "from")?.value || "Unknown Sender";
        const subjectHeader = headers.find((h) => h.name.toLowerCase() === "subject")?.value || "No Subject";
        const dateHeader = headers.find((h) => h.name.toLowerCase() === "date")?.value;
        const snippet = msgData.snippet || "";

        const audit = evaluateEmailRules(fromHeader, subjectHeader, snippet);

        auditResults.push({
          provider_message_id: item.id,
          sender_address: fromHeader,
          subject_redacted: subjectHeader,
          risk_score: audit.score,
          risk_level: audit.level,
          detection_method: "rules",
          indicators: audit.indicators,
          explanation: audit.explanation,
          recommended_actions: audit.recommendations,
          scanned_at: new Date().toISOString(),
          created_at: dateHeader ? new Date(dateHeader).toISOString() : new Date().toISOString()
        });
      } catch (itemErr) {
        console.warn("[Gmail Audit] error reading message:", item.id, itemErr.message);
      }
    }
    return auditResults;
  } catch (err) {
    if (err.status === 401) throw err;
    console.warn("[Gmail API] fetch error:", err.message);
    return [];
  }
}

async function fetchAndAuditOutlookMessages(accessToken) {
  try {
    const listRes = await fetch("https://graph.microsoft.com/v1.0/me/messages?$top=10&$select=id,from,subject,bodyPreview,receivedDateTime", {
      headers: { Authorization: `Bearer ${accessToken}` }
    });
    if (listRes.status === 401) {
      const err = new Error("Outlook access token expired or unauthorized");
      err.status = 401;
      throw err;
    }
    if (!listRes.ok) {
      console.warn("[Outlook Graph API] messages list status:", listRes.status);
      return [];
    }
    const listData = await listRes.json();
    const messages = listData.value || [];
    const auditResults = [];

    for (const msg of messages) {
      try {
        const fromName = msg.from?.emailAddress?.name || "";
        const fromAddr = msg.from?.emailAddress?.address || "";
        const fromHeader = fromName && fromAddr ? `${fromName} <${fromAddr}>` : (fromAddr || fromName || "Unknown Sender");
        const subjectHeader = msg.subject || "No Subject";
        const snippet = msg.bodyPreview || "";
        const dateHeader = msg.receivedDateTime;

        const audit = evaluateEmailRules(fromHeader, subjectHeader, snippet);

        auditResults.push({
          provider_message_id: msg.id,
          sender_address: fromHeader,
          subject_redacted: subjectHeader,
          risk_score: audit.score,
          risk_level: audit.level,
          detection_method: "rules",
          indicators: audit.indicators,
          explanation: audit.explanation,
          recommended_actions: audit.recommendations,
          scanned_at: new Date().toISOString(),
          created_at: dateHeader ? new Date(dateHeader).toISOString() : new Date().toISOString()
        });
      } catch (itemErr) {
        console.warn("[Outlook Audit] error reading message:", msg.id, itemErr.message);
      }
    }
    return auditResults;
  } catch (err) {
    if (err.status === 401) throw err;
    console.warn("[Outlook Graph API] fetch error:", err.message);
    return [];
  }
}

async function refreshProviderToken(email, tokenEntry) {
  if (!tokenEntry || !tokenEntry.refreshToken) {
    throw new Error("No refresh token available for account");
  }

  const cleanEmail = email.toLowerCase().trim();
  const provider = tokenEntry.provider;

  if (provider === "gmail") {
    const clientId = process.env.GOOGLE_CLIENT_ID || process.env.VITE_GOOGLE_CLIENT_ID || "";
    const clientSecret = process.env.GOOGLE_CLIENT_SECRET || "";
    if (!clientId || !clientSecret) {
      throw new Error("Google OAuth credentials are not configured in environment");
    }

    const res = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: clientId,
        client_secret: clientSecret,
        refresh_token: tokenEntry.refreshToken,
        grant_type: "refresh_token"
      })
    });

    const data = await res.json();
    if (!res.ok) {
      tokenEntry.connectionStatus = "error";
      tokenEntry.lastError = data.error_description || data.error || "Token refresh failed";
      persistStoredTokens(mailTokens);
      const err = new Error(data.error_description || data.error || "Google token refresh failed");
      err.code = data.error === "invalid_grant" ? "REVOKED_CONSENT" : "REFRESH_FAILED";
      throw err;
    }

    tokenEntry.accessToken = data.access_token;
    if (data.refresh_token) {
      tokenEntry.refreshToken = data.refresh_token;
    }
    tokenEntry.expiresAt = Date.now() + (data.expires_in || 3600) * 1000;
    tokenEntry.connectionStatus = "connected";
    tokenEntry.lastError = null;
    persistStoredTokens(mailTokens);

    return {
      success: true,
      provider: "gmail",
      expiresIn: data.expires_in || 3600
    };
  } else if (provider === "outlook") {
    const clientId = process.env.MICROSOFT_CLIENT_ID || process.env.AZURE_CLIENT_ID || "";
    const clientSecret = process.env.MICROSOFT_CLIENT_SECRET || process.env.AZURE_CLIENT_SECRET || "";
    const tenantId = process.env.MICROSOFT_TENANT_ID || "common";
    if (!clientId || !clientSecret) {
      throw new Error("Microsoft OAuth credentials are not configured in environment");
    }

    const res = await fetch(`https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: clientId,
        client_secret: clientSecret,
        refresh_token: tokenEntry.refreshToken,
        grant_type: "refresh_token"
      })
    });

    const data = await res.json();
    if (!res.ok) {
      tokenEntry.connectionStatus = "error";
      tokenEntry.lastError = data.error_description || data.error || "Token refresh failed";
      persistStoredTokens(mailTokens);
      const err = new Error(data.error_description || data.error || "Microsoft token refresh failed");
      err.code = data.error === "invalid_grant" ? "REVOKED_CONSENT" : "REFRESH_FAILED";
      throw err;
    }

    tokenEntry.accessToken = data.access_token;
    if (data.refresh_token) {
      tokenEntry.refreshToken = data.refresh_token;
    }
    tokenEntry.expiresAt = Date.now() + (data.expires_in || 3600) * 1000;
    tokenEntry.connectionStatus = "connected";
    tokenEntry.lastError = null;
    persistStoredTokens(mailTokens);

    return {
      success: true,
      provider: "outlook",
      expiresIn: data.expires_in || 3600
    };
  } else {
    throw new Error(`Unsupported provider: ${provider}`);
  }
}

app.post("/oauth/exchange-token", async (req, res) => {
  try {
    const { provider, code, codeVerifier, redirectUri } = req.body || {};

    if (!code || !provider) {
      return res.status(400).json({ success: false, error: "Missing required parameters: code or provider" });
    }

    if (provider === "gmail") {
      const clientId = process.env.GOOGLE_CLIENT_ID || process.env.VITE_GOOGLE_CLIENT_ID || "";
      const clientSecret = process.env.GOOGLE_CLIENT_SECRET || "";

      if (!clientId) {
        return res.status(503).json({
          success: false,
          error: "GOOGLE_CLIENT_ID is not configured. Please set GOOGLE_CLIENT_ID in mail-service/.env."
        });
      }

      if (!clientSecret) {
        return res.status(503).json({
          success: false,
          error: "GOOGLE_CLIENT_SECRET is not configured in mail-service/.env. Please paste your Google Client Secret."
        });
      }

      // 1. Exchange code with Google OAuth 2.0 Token Endpoint
      const tokenParams = new URLSearchParams({
        code,
        client_id: clientId,
        client_secret: clientSecret,
        redirect_uri: redirectUri || "http://localhost:5174/",
        grant_type: "authorization_code"
      });
      if (codeVerifier) {
        tokenParams.set("code_verifier", codeVerifier);
      }

      const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: tokenParams
      });

      const tokenData = await tokenRes.json();
      if (!tokenRes.ok) {
        console.error("[OAuth Exchange] Google error:", tokenData);
        return res.status(400).json({
          success: false,
          error: tokenData.error_description || tokenData.error || "Google token exchange failed"
        });
      }

      // 2. Fetch authenticated profile directly from Google
      const userRes = await fetch("https://www.googleapis.com/oauth2/v2/userinfo", {
        headers: { Authorization: `Bearer ${tokenData.access_token}` }
      });
      const userData = await userRes.json();

      if (!userData || !userData.email) {
        return res.status(400).json({ success: false, error: "Failed to retrieve verified email from Google" });
      }

      const email = userData.email.toLowerCase().trim();
      setMailToken(email, {
        accessToken: tokenData.access_token,
        refreshToken: tokenData.refresh_token,
        provider: "gmail"
      });

      // 3. Inspect recent incoming messages in real-time
      const scannedMessages = await fetchAndAuditGmailMessages(tokenData.access_token);

      return res.status(200).json({
        success: true,
        provider: "gmail",
        email,
        providerAccountId: userData.id || email,
        scopes: (tokenData.scope || "").split(" "),
        scannedMessages
      });
    }

    if (provider === "outlook") {
      const clientId = process.env.MICROSOFT_CLIENT_ID || process.env.AZURE_CLIENT_ID || "";
      const clientSecret = process.env.MICROSOFT_CLIENT_SECRET || process.env.AZURE_CLIENT_SECRET || "";
      const tenantId = process.env.MICROSOFT_TENANT_ID || "common";

      if (!clientId || !clientSecret) {
        return res.status(503).json({
          success: false,
          error: "MICROSOFT_CLIENT_ID or MICROSOFT_CLIENT_SECRET is not configured in mail-service/.env"
        });
      }

      const tokenParams = new URLSearchParams({
        client_id: clientId,
        client_secret: clientSecret,
        code,
        redirect_uri: redirectUri || "http://localhost:5174/",
        grant_type: "authorization_code"
      });
      if (codeVerifier) {
        tokenParams.set("code_verifier", codeVerifier);
      }

      const tokenRes = await fetch(`https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: tokenParams
      });

      const tokenData = await tokenRes.json();
      if (!tokenRes.ok) {
        return res.status(400).json({
          success: false,
          error: tokenData.error_description || tokenData.error || "Microsoft token exchange failed"
        });
      }

      const userRes = await fetch("https://graph.microsoft.com/v1.0/me", {
        headers: { Authorization: `Bearer ${tokenData.access_token}` }
      });
      const userData = await userRes.json();
      const rawEmail = userData?.mail || userData?.userPrincipalName;

      if (!rawEmail) {
        return res.status(400).json({ success: false, error: "Failed to retrieve verified email from Microsoft Graph" });
      }

      const email = rawEmail.toLowerCase().trim();
      setMailToken(email, {
        accessToken: tokenData.access_token,
        refreshToken: tokenData.refresh_token,
        provider: "outlook"
      });

      // Fetch and audit latest Outlook messages with read-only permissions
      const scannedMessages = await fetchAndAuditOutlookMessages(tokenData.access_token);

      return res.status(200).json({
        success: true,
        provider: "outlook",
        email,
        providerAccountId: userData.id || email,
        scopes: (tokenData.scope || "").split(" "),
        scannedMessages
      });
    }

    return res.status(400).json({ success: false, error: `Unsupported provider: ${provider}` });
  } catch (err) {
    console.error("[OAuth Exchange] Error:", err.message);
    return res.status(500).json({ success: false, error: err.message });
  }
});

app.post("/oauth/sync-mailbox", async (req, res) => {
  try {
    const { email } = req.body || {};
    const cleanEmail = (email || "").toLowerCase().trim();
    const tokenEntry = mailTokens.get(cleanEmail);

    if (!tokenEntry || !tokenEntry.accessToken) {
      return res.status(200).json({
        success: true,
        count: 0,
        scannedMessages: [],
        message: "No cached token for this session. Connect mailbox to refresh credentials."
      });
    }

    let scans = [];
    try {
      if (tokenEntry.provider === "gmail") {
        scans = await fetchAndAuditGmailMessages(tokenEntry.accessToken);
      } else if (tokenEntry.provider === "outlook") {
        scans = await fetchAndAuditOutlookMessages(tokenEntry.accessToken);
      }
    } catch (fetchErr) {
      if (fetchErr.status === 401 && tokenEntry.refreshToken) {
        // Attempt bounded token refresh
        try {
          await refreshProviderToken(cleanEmail, tokenEntry);
          if (tokenEntry.provider === "gmail") {
            scans = await fetchAndAuditGmailMessages(tokenEntry.accessToken);
          } else {
            scans = await fetchAndAuditOutlookMessages(tokenEntry.accessToken);
          }
        } catch (refreshErr) {
          return res.status(401).json({
            success: false,
            error: "Session expired or consent revoked. Reauthorization required.",
            code: "REAUTHORIZATION_REQUIRED"
          });
        }
      } else {
        throw fetchErr;
      }
    }

    return res.status(200).json({
      success: true,
      count: scans.length,
      scannedMessages: scans
    });
  } catch (err) {
    console.error("[Sync Mailbox] Error:", err.message);
    return res.status(500).json({ success: false, error: err.message });
  }
});

app.post("/oauth/refresh-token", async (req, res) => {
  try {
    const { email } = req.body || {};
    const cleanEmail = (email || "").toLowerCase().trim();
    const tokenEntry = mailTokens.get(cleanEmail);

    if (!tokenEntry || !tokenEntry.refreshToken) {
      return res.status(404).json({
        success: false,
        error: "No refresh token found for this account. Reconnection required.",
        code: "NO_REFRESH_TOKEN"
      });
    }

    const result = await refreshProviderToken(cleanEmail, tokenEntry);
    return res.status(200).json({
      success: true,
      provider: tokenEntry.provider,
      email: cleanEmail,
      refreshed: true,
      expiresIn: result.expiresIn
    });
  } catch (err) {
    const statusCode = err.code === "REVOKED_CONSENT" ? 401 : 500;
    return res.status(statusCode).json({
      success: false,
      error: err.message,
      code: err.code || "REFRESH_FAILED"
    });
  }
});

app.post("/oauth/disconnect", async (req, res) => {
  try {
    const { email } = req.body || {};
    const cleanEmail = (email || "").toLowerCase().trim();

    if (mailTokens.has(cleanEmail)) {
      mailTokens.delete(cleanEmail);
      persistStoredTokens(mailTokens);
    }

    return res.status(200).json({
      success: true,
      disconnected: true,
      email: cleanEmail
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

// Start listener only when run directly (not during tests)
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`🛡️ ScamShield Mail Service listening on port ${PORT}`);
    console.log(`   SMTP configured: ${mailer.isConfigured()}`);
    console.log(`   API Key required: ${Boolean(API_KEY)}`);
  });
}

module.exports = {
  app,
  mailer,
  rateLimitMap,
  getStorageEncryptionKey,
  encryptCachePayload,
  decryptCachePayload,
  loadStoredTokens,
  persistStoredTokens,
  mailTokens,
  setMailToken,
  refreshProviderToken,
  evaluateEmailRules,
  fetchAndAuditGmailMessages,
  fetchAndAuditOutlookMessages
};
