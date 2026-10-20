// ScamShield Email Templates: Dark Navy, Cyan, and Emerald Branding
// Includes high-fidelity HTML and clean plain-text alternatives

function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

const BRAND = {
  bgBase: "#060913",
  bgElevated: "#0B1120",
  bgCard: "#0F172A",
  borderSubtle: "#1E293B",
  textPrimary: "#F8FAFC",
  textSecondary: "#CBD5E1",
  textMuted: "#94A3B8",
  accentCyan: "#06B6D4",
  accentEmerald: "#10B981",
  accentRed: "#EF4444"
};

/**
 * 6-Digit OTP Email Verification Template
 */
function verificationCodeEmail({ code, email, purpose = "registration", expiryMinutes = 10 }) {
  const safeCode = escapeHtml(code);
  const safeEmail = escapeHtml(email);
  const purposeLabel = purpose === "password_reset"
    ? "Password Recovery"
    : purpose === "mailbox_connection"
    ? "Mailbox Connection Verification"
    : purpose === "recipient_verification"
    ? "Security Alerts Recipient Verification"
    : "Account Verification";

  const subject = `[ScamShield] ${safeCode} is your ${purposeLabel} code`;

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${subject}</title>
</head>
<body style="margin:0;padding:0;background-color:${BRAND.bgBase};font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;color:${BRAND.textPrimary};">
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background-color:${BRAND.bgBase};padding:40px 12px;">
    <tr>
      <td align="center">
        <table role="presentation" width="100%" style="max-width:540px;background-color:${BRAND.bgElevated};border:1px solid ${BRAND.borderSubtle};border-radius:12px;overflow:hidden;box-shadow:0 12px 30px rgba(0,0,0,0.5);" cellspacing="0" cellpadding="0" border="0">
          <!-- Header -->
          <tr>
            <td style="padding:28px 32px;background:linear-gradient(180deg,#0e172a 0%,${BRAND.bgElevated} 100%);border-bottom:1px solid ${BRAND.borderSubtle};">
              <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
                <tr>
                  <td>
                    <div style="display:inline-block;vertical-align:middle;">
                      <span style="font-size:20px;font-weight:800;letter-spacing:1px;color:${BRAND.textPrimary};">SCAM<span style="color:${BRAND.accentCyan};">SHIELD</span></span>
                      <div style="font-size:11px;color:${BRAND.accentEmerald};font-weight:600;letter-spacing:0.5px;text-transform:uppercase;margin-top:2px;">AI Cyber Defense Center</div>
                    </div>
                  </td>
                  <td align="right">
                    <span style="display:inline-block;padding:4px 10px;border-radius:20px;background:rgba(6,182,212,0.12);border:1px solid rgba(6,182,212,0.3);color:${BRAND.accentCyan};font-size:11px;font-weight:600;letter-spacing:0.5px;">AUTHENTICATED</span>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- Body -->
          <tr>
            <td style="padding:32px;">
              <h1 style="font-size:20px;font-weight:700;color:${BRAND.textPrimary};margin:0 0 12px 0;">${purposeLabel}</h1>
              <p style="font-size:14px;line-height:1.6;color:${BRAND.textSecondary};margin:0 0 24px 0;">
                We received a request to verify the email address <strong style="color:${BRAND.textPrimary};">${safeEmail}</strong> for your ScamShield account. Use the single-use code below to proceed:
              </p>

              <!-- OTP Code Display Card -->
              <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="margin:24px 0;">
                <tr>
                  <td align="center" style="background-color:${BRAND.bgCard};border:1px solid rgba(6,182,212,0.35);border-radius:10px;padding:24px 16px;">
                    <div style="font-size:11px;font-weight:700;letter-spacing:1.5px;color:${BRAND.textMuted};text-transform:uppercase;margin-bottom:8px;">One-Time Verification Code</div>
                    <div style="font-size:36px;font-weight:800;letter-spacing:10px;color:${BRAND.accentCyan};font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;">${safeCode}</div>
                    <div style="font-size:12px;color:${BRAND.textMuted};margin-top:8px;">Expires in ${expiryMinutes} minutes • Single-use only</div>
                  </td>
                </tr>
              </table>

              <!-- Security Warning -->
              <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background:rgba(239,68,68,0.08);border:1px solid rgba(239,68,68,0.3);border-radius:8px;margin:24px 0 16px 0;">
                <tr>
                  <td style="padding:14px 16px;">
                    <div style="font-size:12px;line-height:1.5;color:#fca5a5;">
                      <strong>⚠️ Security Notice:</strong> Never share this code with anyone. ScamShield staff, bank representatives, or police will NEVER ask you for your verification code or UPI PIN.
                    </div>
                  </td>
                </tr>
              </table>

              <p style="font-size:12px;line-height:1.6;color:${BRAND.textMuted};margin:16px 0 0 0;">
                If you did not request this verification code, you can safely ignore this email. No changes will be applied to your account.
              </p>
            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td style="padding:20px 32px;background-color:${BRAND.bgBase};border-top:1px solid ${BRAND.borderSubtle};">
              <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
                <tr>
                  <td style="font-size:11px;color:${BRAND.textMuted};line-height:1.5;">
                    ScamShield Defense Platform • Automated Security Dispatch<br>
                    Protected by AES-256-GCM token encryption & zero-trust heuristics.
                  </td>
                </tr>
              </table>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>`;

  const text = `SCAMSHIELD SECURITY — ${purposeLabel.toUpperCase()}
======================================================
Your verification code is: ${code}

This code is valid for ${expiryMinutes} minutes and can only be used once.

Target Email: ${email}

SECURITY NOTICE:
Never share this code with anyone. ScamShield agents, banks, or law enforcement will NEVER ask for this verification code.

If you did not request this verification, please disregard this email.
`;

  return { subject, html, text };
}

/**
 * High-Risk Phishing / Payment Fraud Alert Template
 */
function highRiskAlertEmail(payload) {
  const safeSender = escapeHtml(payload.sender || "Unknown Source");
  const safeSubject = escapeHtml(payload.subject || "No Subject");
  const safeExplanation = escapeHtml(payload.explanation || "Critical fraud indicators detected.");
  const riskScore = Math.max(0, Math.min(100, Number(payload.riskScore || 85)));
  const riskLevel = (payload.riskLevel || "critical").toUpperCase();

  const emailSubject = `🚨 [CRITICAL ALERT] ScamShield detected high-risk threat: ${safeSubject}`;

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>${emailSubject}</title>
</head>
<body style="margin:0;padding:0;background-color:${BRAND.bgBase};font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;color:${BRAND.textPrimary};">
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background-color:${BRAND.bgBase};padding:40px 12px;">
    <tr>
      <td align="center">
        <table role="presentation" width="100%" style="max-width:540px;background-color:${BRAND.bgElevated};border:1px solid rgba(239,68,68,0.4);border-radius:12px;overflow:hidden;" cellspacing="0" cellpadding="0" border="0">
          <tr>
            <td style="padding:24px 32px;background:rgba(239,68,68,0.12);border-bottom:1px solid rgba(239,68,68,0.3);">
              <span style="font-size:18px;font-weight:800;color:#fca5a5;">🚨 High-Risk Threat Intercepted</span>
            </td>
          </tr>
          <tr>
            <td style="padding:32px;">
              <p style="font-size:14px;color:${BRAND.textSecondary};margin:0 0 16px 0;">
                ScamShield detected a dangerous message targeting your mailbox or payment handle.
              </p>
              <div style="background-color:${BRAND.bgCard};border-left:4px solid ${BRAND.accentRed};padding:16px;border-radius:6px;margin:16px 0;">
                <div style="font-size:12px;color:${BRAND.textMuted};">Source / Sender</div>
                <div style="font-size:14px;font-weight:700;color:${BRAND.textPrimary};margin-bottom:8px;">${safeSender}</div>
                <div style="font-size:12px;color:${BRAND.textMuted};">Subject / Content</div>
                <div style="font-size:14px;color:${BRAND.textSecondary};margin-bottom:8px;">${safeSubject}</div>
                <div style="font-size:12px;color:${BRAND.textMuted};">Risk Severity</div>
                <div style="font-size:16px;font-weight:800;color:#f87171;">${riskLevel} (${riskScore}/100)</div>
              </div>
              <p style="font-size:13px;line-height:1.5;color:${BRAND.textSecondary};">${safeExplanation}</p>
              <div style="background:rgba(16,185,129,0.1);border:1px solid rgba(16,185,129,0.3);padding:14px;border-radius:6px;margin-top:20px;">
                <strong style="color:${BRAND.accentEmerald};font-size:12px;text-transform:uppercase;">Recommended Action:</strong>
                <p style="font-size:12px;color:${BRAND.textSecondary};margin:4px 0 0 0;">Do not click any embedded links, do not download attachments, and never divulge OTPs or PINs.</p>
              </div>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>`;

  const text = `🚨 SCAMSHIELD CRITICAL SECURITY ALERT
=============================================
Sender: ${payload.sender}
Subject: ${payload.subject}
Severity: ${riskLevel} (${riskScore}/100)

Explanation:
${payload.explanation}

Recommended Action:
Do not open attachments or click links. Never share your OTP, password, or UPI PIN.
`;

  return { subject: emailSubject, html, text };
}

/**
 * Password Reset / Change Password OTP Email Template
 */
function passwordResetEmail({ email, code, expiryMinutes = 10 }) {
  const safeCode = escapeHtml(code);
  const safeEmail = escapeHtml(email);
  const subject = `[ScamShield Security] ${safeCode} is your Password Reset Code`;

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>${subject}</title>
</head>
<body style="margin:0;padding:0;background-color:${BRAND.bgBase};font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;color:${BRAND.textPrimary};">
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background-color:${BRAND.bgBase};padding:40px 12px;">
    <tr>
      <td align="center">
        <table role="presentation" width="100%" style="max-width:540px;background-color:${BRAND.bgElevated};border:1px solid ${BRAND.borderSubtle};border-radius:12px;overflow:hidden;box-shadow:0 12px 30px rgba(0,0,0,0.5);" cellspacing="0" cellpadding="0" border="0">
          <tr>
            <td style="padding:28px 32px;background:linear-gradient(180deg,#0e172a 0%,${BRAND.bgElevated} 100%);border-bottom:1px solid ${BRAND.borderSubtle};">
              <span style="font-size:20px;font-weight:800;letter-spacing:1px;color:${BRAND.textPrimary};">SCAM<span style="color:${BRAND.accentCyan};">SHIELD</span></span>
              <div style="font-size:11px;color:#f59e0b;font-weight:600;letter-spacing:0.5px;text-transform:uppercase;margin-top:2px;">Account Security Alert</div>
            </td>
          </tr>
          <tr>
            <td style="padding:32px;">
              <h1 style="font-size:20px;font-weight:700;color:${BRAND.textPrimary};margin:0 0 12px 0;">Password Reset Request</h1>
              <p style="font-size:14px;line-height:1.6;color:${BRAND.textSecondary};margin:0 0 20px 0;">
                We received a request to change the password for your ScamShield account associated with <strong style="color:${BRAND.textPrimary};">${safeEmail}</strong>.
              </p>

              <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="margin:20px 0;">
                <tr>
                  <td align="center" style="background-color:${BRAND.bgCard};border:1px solid rgba(245,158,11,0.4);border-radius:10px;padding:24px 16px;">
                    <div style="font-size:11px;font-weight:700;letter-spacing:1.5px;color:${BRAND.textMuted};text-transform:uppercase;margin-bottom:8px;">Single-Use Reset Code</div>
                    <div style="font-size:36px;font-weight:800;letter-spacing:10px;color:#fbbf24;font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;">${safeCode}</div>
                    <div style="font-size:12px;color:${BRAND.textMuted};margin-top:8px;">Valid for ${expiryMinutes} minutes • Single-use only</div>
                  </td>
                </tr>
              </table>

              <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background:rgba(239,68,68,0.08);border:1px solid rgba(239,68,68,0.3);border-radius:8px;margin:20px 0;">
                <tr>
                  <td style="padding:14px 16px;">
                    <div style="font-size:12px;line-height:1.5;color:#fca5a5;">
                      <strong>⚠️ Important:</strong> If you did not initiate this password change, your account credentials may be compromised. Disregard this code and review your account security immediately.
                    </div>
                  </td>
                </tr>
              </table>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>`;

  const text = `SCAMSHIELD — PASSWORD RESET CODE
====================================
Your single-use password reset code is: ${code}

Target Account: ${email}
Valid for: ${expiryMinutes} minutes

SECURITY NOTICE:
If you did not request a password change, please disregard this email. Your current password will remain unchanged.
`;

  return { subject, html, text };
}

/**
 * Welcome / Onboarding Email Template
 */
function welcomeEmail({ name = "Security Defender", email }) {
  const safeName = escapeHtml(name);
  const safeEmail = escapeHtml(email);
  const subject = `🛡️ Welcome to ScamShield — Your Cyber Fraud Defense Suite`;

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>${subject}</title>
</head>
<body style="margin:0;padding:0;background-color:${BRAND.bgBase};font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;color:${BRAND.textPrimary};">
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background-color:${BRAND.bgBase};padding:40px 12px;">
    <tr>
      <td align="center">
        <table role="presentation" width="100%" style="max-width:540px;background-color:${BRAND.bgElevated};border:1px solid ${BRAND.borderSubtle};border-radius:12px;overflow:hidden;box-shadow:0 12px 30px rgba(0,0,0,0.5);" cellspacing="0" cellpadding="0" border="0">
          <tr>
            <td style="padding:28px 32px;background:linear-gradient(180deg,#0e172a 0%,${BRAND.bgElevated} 100%);border-bottom:1px solid ${BRAND.borderSubtle};">
              <span style="font-size:20px;font-weight:800;letter-spacing:1px;color:${BRAND.textPrimary};">SCAM<span style="color:${BRAND.accentCyan};">SHIELD</span></span>
              <div style="font-size:11px;color:${BRAND.accentEmerald};font-weight:600;letter-spacing:0.5px;text-transform:uppercase;margin-top:2px;">AI Cyber Defense Console</div>
            </td>
          </tr>
          <tr>
            <td style="padding:32px;">
              <h1 style="font-size:22px;font-weight:800;color:${BRAND.textPrimary};margin:0 0 12px 0;">Welcome, ${safeName}! 👋</h1>
              <p style="font-size:14px;line-height:1.6;color:${BRAND.textSecondary};margin:0 0 24px 0;">
                Your ScamShield cyber defense account for <strong style="color:${BRAND.textPrimary};">${safeEmail}</strong> is now active. You are protected by explainable fraud detection, brand lookalike filters, and zero-trust verification.
              </p>

              <div style="background-color:${BRAND.bgCard};border:1px solid ${BRAND.borderSubtle};border-radius:8px;padding:20px;margin-bottom:24px;">
                <div style="font-size:13px;font-weight:700;color:${BRAND.accentCyan};text-transform:uppercase;letter-spacing:1px;margin-bottom:12px;">⚡ Key Capabilities Activated:</div>
                <ul style="margin:0;padding-left:18px;font-size:13px;line-height:1.8;color:${BRAND.textSecondary};">
                  <li><strong>Active Tab & URL Scanner:</strong> Pinpoints phishing lookalikes before you enter credentials.</li>
                  <li><strong>UPI & Payment Defense:</strong> Detects reverse-collect QR traps and brand-impersonating VPAs.</li>
                  <li><strong>Mailbox Phishing Guard:</strong> Scans Gmail & Outlook for zero-day credential harvesting.</li>
                  <li><strong>Digital Arrest & Extortion Filters:</strong> Flags fake CBI/police video-call extortion pretexts.</li>
                </ul>
              </div>

              <p style="font-size:13px;line-height:1.6;color:${BRAND.textMuted};margin:0;">
                Stay safe online! Need help or want to audit a suspicious link? Open the ScamShield extension anytime.
              </p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>`;

  const text = `WELCOME TO SCAMSHIELD — YOUR CYBER DEFENSE SUITE
==================================================
Hello ${name},

Your ScamShield protection account for ${email} is now activated!

Key Capabilities Activated:
1. Active Tab & Link Scanner: Detects credential-harvesting phishing domains.
2. UPI & Payment Defense: Alerts you to reverse-collect fraud and impersonated VPAs.
3. Mailbox Phishing Guard: Inspects incoming emails for sender spoofing and urgent extortion.
4. Digital Arrest Extortion Defense: Filters coercive law-enforcement impersonation scams.

Stay safe online! Open your ScamShield Chrome Extension anytime to audit links, messages, or payments.
`;

  return { subject, html, text };
}

/**
 * Cyber Awareness / Security Advisory Bulletin Template
 */
function awarenessAdvisoryEmail({
  email,
  title = "Cyber Threat Bulletin: Beware of Emerging Scam Vectors",
  topic = "Digital Arrest & UPI Reverse-Collect Traps",
  summary,
  tips = []
}) {
  const safeTitle = escapeHtml(title);
  const safeTopic = escapeHtml(topic);
  const safeSummary = escapeHtml(summary || "Cyber criminals are deploying advanced deception techniques targeting online banking, UPI payments, and messaging apps. Review our safety briefing below to keep your accounts secure.");

  const subject = `🛡️ [ScamShield Advisory] ${safeTopic}`;

  const renderedTips = tips.length > 0
    ? tips.map((t) => `<li style="margin-bottom:8px;">${escapeHtml(t)}</li>`).join("")
    : `<li style="margin-bottom:8px;"><strong>Never enter your UPI PIN to receive money:</strong> In UPI, entering a PIN ALWAYS debits your bank account.</li>
       <li style="margin-bottom:8px;"><strong>Law enforcement never conducts 'Digital Arrests' over video calls:</strong> Police, CBI, and Customs never demand money transfers via Skype or WhatsApp.</li>
       <li style="margin-bottom:8px;"><strong>Never install AnyDesk or TeamViewer on stranger requests:</strong> Screen sharing apps allow scammers full remote control of your banking apps.</li>`;

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>${subject}</title>
</head>
<body style="margin:0;padding:0;background-color:${BRAND.bgBase};font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;color:${BRAND.textPrimary};">
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background-color:${BRAND.bgBase};padding:40px 12px;">
    <tr>
      <td align="center">
        <table role="presentation" width="100%" style="max-width:540px;background-color:${BRAND.bgElevated};border:1px solid ${BRAND.borderSubtle};border-radius:12px;overflow:hidden;box-shadow:0 12px 30px rgba(0,0,0,0.5);" cellspacing="0" cellpadding="0" border="0">
          <tr>
            <td style="padding:28px 32px;background:linear-gradient(180deg,#0e172a 0%,${BRAND.bgElevated} 100%);border-bottom:1px solid ${BRAND.borderSubtle};">
              <span style="font-size:20px;font-weight:800;letter-spacing:1px;color:${BRAND.textPrimary};">SCAM<span style="color:${BRAND.accentCyan};">SHIELD</span></span>
              <div style="font-size:11px;color:${BRAND.accentEmerald};font-weight:600;letter-spacing:0.5px;text-transform:uppercase;margin-top:2px;">Periodic Threat Intelligence Advisory</div>
            </td>
          </tr>
          <tr>
            <td style="padding:32px;">
              <h1 style="font-size:18px;font-weight:800;color:${BRAND.textPrimary};margin:0 0 8px 0;">${safeTitle}</h1>
              <div style="display:inline-block;padding:3px 8px;border-radius:12px;background:rgba(6,182,212,0.15);color:${BRAND.accentCyan};font-size:11px;font-weight:700;margin-bottom:16px;">TOPIC: ${safeTopic}</div>

              <p style="font-size:14px;line-height:1.6;color:${BRAND.textSecondary};margin:0 0 20px 0;">
                ${safeSummary}
              </p>

              <div style="background-color:${BRAND.bgCard};border-left:4px solid ${BRAND.accentEmerald};border-radius:4px;padding:18px;margin-bottom:20px;">
                <div style="font-size:13px;font-weight:700;color:${BRAND.accentEmerald};text-transform:uppercase;margin-bottom:10px;">🛡️ Safety Rules to Remember:</div>
                <ul style="margin:0;padding-left:18px;font-size:13px;line-height:1.6;color:${BRAND.textSecondary};">
                  ${renderedTips}
                </ul>
              </div>

              <p style="font-size:12px;line-height:1.6;color:${BRAND.textMuted};margin:16px 0 0 0;">
                You are receiving this security bulletin as a registered ScamShield user. You can manage your notification preferences anytime from your dashboard.
              </p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>`;

  const text = `SCAMSHIELD CYBER THREAT ADVISORY: ${topic.toUpperCase()}
======================================================
${title}

${summary || "Cyber criminals are deploying advanced deception techniques targeting online banking, UPI payments, and messaging apps."}

KEY SAFETY RULES:
1. Never enter your UPI PIN to receive funds. Entering PIN ALWAYS debits money.
2. Law enforcement never puts citizens under 'Digital Arrest' on video calls.
3. Never install remote access software (AnyDesk, TeamViewer) on incoming calls.

Stay safe!
The ScamShield Cyber Defense Team
`;

  return { subject, html, text };
}

module.exports = {
  verificationCodeEmail,
  passwordResetEmail,
  welcomeEmail,
  awarenessAdvisoryEmail,
  highRiskAlertEmail,
  BRAND
};

