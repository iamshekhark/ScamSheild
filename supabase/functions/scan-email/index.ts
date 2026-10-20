// Supabase Edge Function: scan-email
// Hybrid email security analysis: phishing heuristics, impersonation detection, AI explanation

import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { corsHeaders, handleCors } from "../_shared/cors.ts";
import { EmailTemplates } from "../_shared/emailTemplates.ts";
import { sendTransactionalEmail } from "../_shared/emailSender.ts";
import { getAuthenticatedUser } from "../_shared/authHelper.ts";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL") || "";
const SUPABASE_SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || "";
const AI_API_KEY = Deno.env.get("AI_API_KEY") || Deno.env.get("GEMINI_API_KEY") || "";

interface EmailIndicator {
  indicator_type: string;
  description: string;
  severity: "low" | "medium" | "high" | "critical";
}

function evaluateEmailRules(sender: string, subject: string, bodyText: string): {
  score: number;
  indicators: EmailIndicator[];
  explanation: string;
  recommendations: string[];
} {
  const indicators: EmailIndicator[] = [];
  let score = 0;
  const content = `${sender} ${subject} ${bodyText}`.toLowerCase();

  // 1. Sender Spoofing / Impersonation
  if (sender.includes("<") && sender.includes(">")) {
    const displayName = sender.split("<")[0].trim().toLowerCase();
    const address = sender.split("<")[1].replace(">", "").trim().toLowerCase();

    const trustedBrands = [
      { name: "Paytm", token: "paytm", domains: ["paytm.com", "paytmbank.com"] },
      { name: "Amazon", token: "amazon", domains: ["amazon.com", "amazon.in", "amazon.co.uk", "amazon.de"] },
      { name: "PayPal", token: "paypal", domains: ["paypal.com", "paypal.me"] },
      { name: "SBI", token: "sbi", domains: ["onlinesbi.sbi", "sbi.co.in", "sbi.bank.in"] },
      { name: "HDFC", token: "hdfc", domains: ["hdfcbank.com", "hdfcbank.net"] },
      { name: "Netflix", token: "netflix", domains: ["netflix.com"] },
      { name: "Google", token: "google", domains: ["google.com", "google.co.in", "gmail.com"] },
      { name: "Microsoft", token: "microsoft", domains: ["microsoft.com", "microsoftonline.com", "live.com", "office.com", "outlook.com"] },
      { name: "Apple", token: "apple", domains: ["apple.com", "icloud.com"] }
    ];
    for (const b of trustedBrands) {
      if (displayName.includes(b.token)) {
        const senderDomain = address.includes("@") ? address.split("@")[1].trim() : address;
        const isOfficial = b.domains.some((d) => senderDomain === d || senderDomain.endsWith("." + d));
        if (!isOfficial) {
          indicators.push({
            indicator_type: "SENDER_IMPERSONATION",
            description: `Sender displays brand '${b.name}' but originates from untrusted domain '${address}'`,
            severity: "critical"
          });
          score += 55;
          break;
        }
      }
    }
  }

  // 2. Urgent Account Suspension / Extortion
  if (/(account.*suspend|account.*block|verify.*immediately|urgent action required|terminate.*access)/i.test(content)) {
    indicators.push({
      indicator_type: "URGENT_EXTORTION",
      description: "Aggressive urgency wording threatening account suspension or service termination",
      severity: "high"
    });
    score += 35;
  }

  // 3. OTP or Password Divulgence
  if (/(share.*otp|enter.*otp|provide.*password|send.*code|wire.*funds|crypto.*transfer)/i.test(content)) {
    indicators.push({
      indicator_type: "CREDENTIAL_HARVESTING",
      description: "Requests confidential OTP verification codes, credentials, or wire transfers",
      severity: "critical"
    });
    score += 50;
  }

  // 4. Fake Invoices / Overdue Payment Scam
  if (/(invoice.*attached|payment.*overdue|wire.*amount|gift card|bitcoin wallet)/i.test(content)) {
    indicators.push({
      indicator_type: "FINANCIAL_FRAUD",
      description: "Mentions unsolicited invoice, overdue bill, or cryptocurrency transaction",
      severity: "medium"
    });
    score += 25;
  }

  // 5. Suspicious TLD / Links embedded in text
  const urlMatches = content.match(/https?:\/\/[^\s]+/g) || [];
  for (const u of urlMatches) {
    if (/\.(xyz|top|buzz|click|club|tk|ml|cf|gq|icu)\b/i.test(u)) {
      indicators.push({
        indicator_type: "SUSPICIOUS_LINK",
        description: `Contains embedded link pointing to risky throwaway domain [${u.slice(0, 30)}...]`,
        severity: "high"
      });
      score += 30;
      break;
    }
  }

  score = Math.min(100, Math.max(0, score));

  let explanation = "";
  if (score >= 75) {
    explanation = "Critical threat: high likelihood of credential theft or executive impersonation scam.";
  } else if (score >= 50) {
    explanation = "High risk: contains deceptive urgency and suspicious external link indicators.";
  } else if (score >= 25) {
    explanation = "Medium risk: contains promotional or financial terminology requiring caution.";
  } else {
    explanation = "Standard email: no deceptive impersonation or phishing patterns identified.";
  }

  const recommendations = score >= 50 ? [
    "Do not click any links or download attached files.",
    "Do not reply with passwords, OTPs, or financial information.",
    "Verify the sender's authentic domain directly via official channels."
  ] : [
    "Exercise standard caution before opening external attachments."
  ];

  return { score, indicators, explanation, recommendations };
}

serve(async (req) => {
  const corsRes = handleCors(req);
  if (corsRes) return corsRes;

  try {
    const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);
    const authUser = await getAuthenticatedUser(req, supabase);

    const {
      connectedAccountId,
      providerMessageId,
      sender,
      subject,
      bodyText = "",
      allowAi = true
    } = await req.json();

    if (!sender || !subject) {
      return new Response(JSON.stringify({ error: "Missing sender or subject" }), {
        status: 400,
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    const { score, indicators, explanation, recommendations } = evaluateEmailRules(sender, subject, bodyText);

    let riskLevel: "low" | "medium" | "high" | "critical" = "low";
    if (score >= 75) riskLevel = "critical";
    else if (score >= 50) riskLevel = "high";
    else if (score >= 25) riskLevel = "medium";

    const ORDER: Array<"low" | "medium" | "high" | "critical"> = ["low", "medium", "high", "critical"];
    for (const ind of indicators) {
      if (ORDER.indexOf(ind.severity) > ORDER.indexOf(riskLevel)) {
        riskLevel = ind.severity;
      }
    }

    // Minimized subject and fingerprint
    const subjectRedacted = subject.length > 80 ? subject.slice(0, 77) + "…" : subject;
    const msgId = providerMessageId || `manual_msg_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`;

    const enc = new TextEncoder();
    const fpDigest = await crypto.subtle.digest("SHA-256", enc.encode(`${sender}:${subject}:${msgId}`));
    const fingerprint = Array.from(new Uint8Array(fpDigest)).map((b) => b.toString(16).padStart(2, "0")).join("");

    let scanRecord = null;
    const effectiveUserId = authUser?.id || null;

    // Save scan result only if authenticated (prevents FK violation with auth.users)
    if (effectiveUserId) {
      let validConnectedAccountId: string | null = null;
      if (connectedAccountId) {
        const { data: acct } = await supabase
          .from("connected_email_accounts")
          .select("id")
          .eq("id", connectedAccountId)
          .eq("user_id", effectiveUserId)
          .maybeSingle();
        if (acct?.id) validConnectedAccountId = acct.id;
      }

      const { data: savedRecord } = await supabase
        .from("email_scan_results")
        .upsert({
          user_id: effectiveUserId,
          connected_account_id: validConnectedAccountId,
          provider_message_id: msgId,
          normalized_message_fingerprint: fingerprint,
          sender_address: sender,
          subject_redacted: subjectRedacted,
          risk_score: score,
          risk_level: riskLevel,
          detection_method: "rules",
          indicators,
          explanation,
          recommended_actions: recommendations,
          scanned_at: new Date().toISOString()
        }, { onConflict: "user_id,provider_message_id" })
        .select()
        .single();

      scanRecord = savedRecord;

      // Trigger notification if high or critical risk and user is authenticated
      if (riskLevel === "high" || riskLevel === "critical") {
        const { data: prefs } = await supabase
          .from("notification_preferences")
          .select("recipient_email, recipient_verified, critical_risk_alerts, suspicious_email_alerts")
          .eq("user_id", effectiveUserId)
          .maybeSingle();

        const shouldSend = (riskLevel === "critical" && prefs?.critical_risk_alerts) ||
                           (riskLevel === "high" && prefs?.suspicious_email_alerts);

        if (shouldSend && prefs?.recipient_email && prefs?.recipient_verified) {
          const template = EmailTemplates.highRiskAlert({
            sender,
            subject: subjectRedacted,
            riskScore: score,
            riskLevel,
            explanation,
            indicators,
            recommendations,
            detectedAt: new Date().toUTCString()
          });

          await sendTransactionalEmail({
            userId: effectiveUserId,
            to: prefs.recipient_email,
            subject: template.subject,
            html: template.html,
            notificationType: `email_alert_${riskLevel}`,
            deduplicationKey: `scan_alert_${fingerprint}_${riskLevel}`,
            providerMessageId: msgId
          });
        }
      }
    }

    return new Response(JSON.stringify({
      success: true,
      scan: scanRecord || {
        provider_message_id: msgId,
        risk_score: score,
        risk_level: riskLevel,
        explanation,
        indicators,
        recommended_actions: recommendations
      }
    }), {
      status: 200,
      headers: { ...corsHeaders, "Content-Type": "application/json" }
    });
  } catch (err) {
    return new Response(JSON.stringify({ error: err instanceof Error ? err.message : "Email scan failed" }), {
      status: 500,
      headers: { ...corsHeaders, "Content-Type": "application/json" }
    });
  }
});
