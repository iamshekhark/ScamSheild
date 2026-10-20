// ScamShield Branded Responsive Transactional Email Templates
// Securely escapes all user-controlled text, strips dangerous links, and formats alerts.

function escapeHtml(str: string): string {
  return (str || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function baseLayout(title: string, bodyContent: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${escapeHtml(title)}</title>
  <style>
    body { margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #F8FAFC; color: #0F172A; }
    .container { max-width: 580px; margin: 32px auto; background: #FFFFFF; border-radius: 12px; border: 1px solid #E2E8F0; overflow: hidden; box-shadow: 0 4px 12px rgba(0,0,0,0.03); }
    .header { background: #0F172A; padding: 24px 32px; text-align: left; }
    .brand-logo { font-size: 24px; vertical-align: middle; }
    .brand-title { color: #FFFFFF; font-size: 18px; font-weight: 800; letter-spacing: -0.5px; margin-left: 8px; vertical-align: middle; display: inline-block; }
    .content { padding: 32px; }
    .footer { background: #F1F5F9; padding: 20px 32px; font-size: 12px; color: #64748B; text-align: center; border-top: 1px solid #E2E8F0; }
    .code-box { background: #F1F5F9; border: 1px dashed #CBD5E1; border-radius: 8px; padding: 18px; text-align: center; margin: 24px 0; }
    .otp-code { font-family: monospace; font-size: 32px; font-weight: 800; letter-spacing: 6px; color: #2563EB; }
    .badge { display: inline-block; padding: 4px 10px; border-radius: 9999px; font-size: 11px; font-weight: 800; text-transform: uppercase; }
    .badge-critical { background: #FEE2E2; color: #991B1B; }
    .badge-high { background: #FFEDD5; color: #9A3412; }
    .badge-warning { background: #FEF3C7; color: #92400E; }
    .alert-card { border-left: 4px solid #EF4444; background: #FEF2F2; padding: 16px; border-radius: 4px; margin: 20px 0; }
    .btn { display: inline-block; background: #2563EB; color: #FFFFFF !important; text-decoration: none; padding: 12px 24px; border-radius: 6px; font-weight: 700; font-size: 14px; margin: 16px 0; }
    .btn:hover { background: #1D4ED8; }
    .recs-list { padding-left: 20px; line-height: 1.6; }
    .subtle-info { font-size: 12px; color: #64748B; margin-top: 24px; line-height: 1.5; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <span class="brand-logo">🛡️</span>
      <span class="brand-title">ScamShield Cyber Defense</span>
    </div>
    <div class="content">
      ${bodyContent}
    </div>
    <div class="footer">
      <p style="margin: 0 0 6px;">You received this automated security email from your ScamShield protection service.</p>
      <p style="margin: 0;">Never share your security codes or passwords with anyone.</p>
    </div>
  </div>
</body>
</html>`;
}

export const EmailTemplates = {
  // 1. Verification Code Email
  verificationCode(code: string, purpose: string, expiresMinutes = 5): { subject: string; html: string } {
    const purposeTitle = purpose === "registration" 
      ? "Verify your new ScamShield account"
      : purpose === "recipient_verification"
      ? "Verify your alert notification email"
      : "Security verification code";

    const body = `
      <h2 style="margin-top:0; font-size: 20px; color: #0F172A;">Your Verification Code</h2>
      <p style="font-size: 14px; color: #475569; line-height: 1.5;">
        Please enter the six-digit verification code below to complete your ${escapeHtml(purpose.replace(/_/g, " "))}.
      </p>
      <div class="code-box">
        <div class="otp-code">${escapeHtml(code)}</div>
        <p style="margin: 6px 0 0; font-size: 12px; color: #64748B;">Expires in ${expiresMinutes} minutes · Single use only</p>
      </div>
      <p class="subtle-info">
        If you did not request this verification code, please ignore this email or review your account security immediately.
      </p>
    `;
    return { subject: `[ScamShield] ${purposeTitle}: ${code}`, html: baseLayout("Verification Code", body) };
  },

  // 2. Welcome Message
  welcome(displayName: string): { subject: string; html: string } {
    const body = `
      <h2 style="margin-top:0; font-size: 20px; color: #0F172A;">Welcome to ScamShield! 🛡️</h2>
      <p style="font-size: 14px; color: #475569; line-height: 1.5;">
        Hello <strong>${escapeHtml(displayName || "Defender")}</strong>, your cyber defense platform is now fully activated.
      </p>
      <p style="font-size: 14px; color: #475569; line-height: 1.5;">
        ScamShield safeguards your digital identity against phishing websites, extortion messages, impersonators, and deceptive email links in real time.
      </p>
      <div style="margin: 24px 0;">
        <a href="http://localhost:5173" class="btn">Open Your Cyber Dashboard</a>
      </div>
      <ul class="recs-list" style="font-size: 13px; color: #475569;">
        <li>Connect Gmail or Outlook for automated phishing protection</li>
        <li>Review your risk trends and weekly security insights</li>
        <li>Audit suspicious links and SMS text anytime in the scanner</li>
      </ul>
    `;
    return { subject: "Welcome to ScamShield — Your Cyber-Safety Shield is Active", html: baseLayout("Welcome", body) };
  },

  // 3. High-Risk Phishing Alert
  highRiskAlert(details: {
    sender: string;
    subject: string;
    riskScore: number;
    riskLevel: string;
    explanation: string;
    indicators: Array<{ description: string }>;
    recommendations: string[];
    detectedAt: string;
  }): { subject: string; html: string } {
    const indicatorsHtml = details.indicators && details.indicators.length > 0
      ? details.indicators.map((i) => `<li>${escapeHtml(i.description)}</li>`).join("")
      : "<li>Deceptive patterns matching known social engineering scams</li>";

    const recsHtml = details.recommendations && details.recommendations.length > 0
      ? details.recommendations.map((r) => `<li>${escapeHtml(r)}</li>`).join("")
      : "<li>Do not open any attachments or click embedded links.</li><li>Report this message to your security provider.</li>";

    const body = `
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom: 12px;">
        <span class="badge badge-${details.riskLevel.toLowerCase()}">${escapeHtml(details.riskLevel.toUpperCase())} RISK · SCORE ${details.riskScore}/100</span>
        <span style="font-size: 12px; color: #64748B;">${escapeHtml(details.detectedAt)}</span>
      </div>
      <h2 style="margin: 0 0 12px; font-size: 20px; color: #991B1B;">⚠️ Suspicious Phishing Threat Detected</h2>
      <p style="font-size: 14px; color: #334155; line-height: 1.5;">
        ScamShield identified an incoming message with high probability of fraudulent intent or credential theft.
      </p>

      <div class="alert-card">
        <p style="margin: 0 0 6px; font-size: 13px;"><strong>Sender:</strong> <span style="font-family:monospace;">${escapeHtml(details.sender)}</span></p>
        <p style="margin: 0; font-size: 13px;"><strong>Subject:</strong> <em>${escapeHtml(details.subject)}</em></p>
      </div>

      <h3 style="font-size: 14px; color: #0F172A; margin: 18px 0 8px;">Analysis & Explanation</h3>
      <p style="font-size: 13.5px; color: #475569; line-height: 1.5; margin: 0 0 14px;">
        ${escapeHtml(details.explanation)}
      </p>

      <h3 style="font-size: 14px; color: #0F172A; margin: 14px 0 8px;">Detected Risk Indicators</h3>
      <ul class="recs-list" style="font-size: 13px; color: #B91C1C;">
        ${indicatorsHtml}
      </ul>

      <h3 style="font-size: 14px; color: #0F172A; margin: 14px 0 8px;">Recommended Actions</h3>
      <ul class="recs-list" style="font-size: 13px; color: #15803D;">
        ${recsHtml}
      </ul>

      <div style="margin: 24px 0; text-align: center;">
        <a href="http://localhost:5173" class="btn" style="background: #DC2626;">View Incident in Dashboard</a>
      </div>
      <p class="subtle-info">
        Note: For your protection, dangerous links in the original message have been suppressed in this security digest.
      </p>
    `;
    return {
      subject: `🚨 [SECURITY ALERT] ${details.riskLevel.toUpperCase()} Phishing Detected: ${escapeHtml(details.subject.slice(0, 40))}`,
      html: baseLayout("Phishing Alert", body)
    };
  },

  // 4. Suspicious Email Summary (Batch/Periodic)
  suspiciousEmailSummary(scannedCount: number, threatsFound: number): { subject: string; html: string } {
    const body = `
      <h2 style="margin-top:0; font-size: 20px; color: #0F172A;">Inbox Security Scan Complete</h2>
      <p style="font-size: 14px; color: #475569; line-height: 1.5;">
        Your connected mailbox was checked for phishing, fraudulent invoices, and credential harvesting threats.
      </p>
      <div style="display: flex; gap: 16px; margin: 20px 0;">
        <div style="flex: 1; background: #F8FAFC; border: 1px solid #E2E8F0; padding: 16px; border-radius: 8px; text-align: center;">
          <div style="font-size: 28px; font-weight: 800; color: #0F172A;">${scannedCount}</div>
          <div style="font-size: 11px; text-transform: uppercase; color: #64748B; font-weight: 700;">Emails Analyzed</div>
        </div>
        <div style="flex: 1; background: #FEF2F2; border: 1px solid #FECACA; padding: 16px; border-radius: 8px; text-align: center;">
          <div style="font-size: 28px; font-weight: 800; color: #DC2626;">${threatsFound}</div>
          <div style="font-size: 11px; text-transform: uppercase; color: #991B1B; font-weight: 700;">Threats Flagged</div>
        </div>
      </div>
      <div style="margin-top: 24px;">
        <a href="http://localhost:5173" class="btn">View Protection Report</a>
      </div>
    `;
    return { subject: `[ScamShield] Mailbox Scan: ${threatsFound} threats flagged across ${scannedCount} emails`, html: baseLayout("Scan Summary", body) };
  },

  // 5. New Login Security Alert
  newLoginAlert(ip: string, userAgent: string, time: string): { subject: string; html: string } {
    const body = `
      <h2 style="margin-top:0; font-size: 20px; color: #0F172A;">New Sign-In Detected</h2>
      <p style="font-size: 14px; color: #475569; line-height: 1.5;">
        A new sign-in was registered on your ScamShield account.
      </p>
      <div class="alert-card" style="border-left-color: #2563EB; background: #EFF6FF;">
        <p style="margin: 0 0 6px; font-size: 13px;"><strong>Time (UTC):</strong> ${escapeHtml(time)}</p>
        <p style="margin: 0 0 6px; font-size: 13px;"><strong>IP Address:</strong> ${escapeHtml(ip)}</p>
        <p style="margin: 0; font-size: 13px;"><strong>Device / Browser:</strong> ${escapeHtml(userAgent)}</p>
      </div>
      <p class="subtle-info">
        If this was you, no action is needed. If you did not authorize this access, reset your password immediately.
      </p>
    `;
    return { subject: "Security Alert: New Sign-in to Your ScamShield Account", html: baseLayout("Login Alert", body) };
  },

  // 6. Mailbox Connection Revoked
  mailboxRevoked(provider: string, email: string): { subject: string; html: string } {
    const body = `
      <h2 style="margin-top:0; font-size: 20px; color: #DC2626;">Mailbox Access Revoked or Expired</h2>
      <p style="font-size: 14px; color: #475569; line-height: 1.5;">
        ScamShield's connection to your <strong>${escapeHtml(provider.toUpperCase())}</strong> mailbox (${escapeHtml(email)}) has ended.
      </p>
      <p style="font-size: 14px; color: #475569; line-height: 1.5;">
        This occurs when OAuth tokens expire or permission is revoked in your email provider settings. While disconnected, incoming email scam monitoring is paused.
      </p>
      <div style="margin: 24px 0;">
        <a href="http://localhost:5173" class="btn">Reconnect Mailbox</a>
      </div>
    `;
    return { subject: `[Action Required] ${provider.toUpperCase()} Mailbox Connection Revoked`, html: baseLayout("Connection Revoked", body) };
  },

  // 7. Weekly Security Report
  weeklyReport(stats: { totalScans: number; threatsBlocked: number; topCategory: string }): { subject: string; html: string } {
    const body = `
      <h2 style="margin-top:0; font-size: 20px; color: #0F172A;">Your Weekly Cyber Defense Summary</h2>
      <p style="font-size: 14px; color: #475569; line-height: 1.5;">
        Here is your 7-day security digest from ScamShield protection.
      </p>
      <div style="background: #F1F5F9; border-radius: 8px; padding: 20px; margin: 20px 0;">
        <div style="font-size: 13px; color: #475569; margin-bottom: 8px;">Total Audits & Scans: <strong>${stats.totalScans}</strong></div>
        <div style="font-size: 13px; color: #475569; margin-bottom: 8px;">Malicious Links / Emails Filtered: <strong style="color:#DC2626;">${stats.threatsBlocked}</strong></div>
        <div style="font-size: 13px; color: #475569;">Most Common Threat Vector: <strong>${escapeHtml(stats.topCategory || "Phishing URLs")}</strong></div>
      </div>
      <a href="http://localhost:5173" class="btn">Open Insights Dashboard</a>
    `;
    return { subject: `[ScamShield] Weekly Summary: ${stats.threatsBlocked} threats neutralized`, html: baseLayout("Weekly Summary", body) };
  }
};
