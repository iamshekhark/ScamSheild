// Supabase Edge Function: verify-payment-risk
// Production-grade server-side payment fraud assessment for UPI IDs, QR codes, payment URLs, and messages

import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { corsHeaders, handleCors } from "../_shared/cors.ts";
import { getAuthenticatedUser } from "../_shared/authHelper.ts";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL") || "";
const SUPABASE_SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || "";
const AI_API_KEY = Deno.env.get("AI_API_KEY") || Deno.env.get("GEMINI_API_KEY") || "";
const AI_MODEL = Deno.env.get("AI_MODEL") || "gemini-1.5-flash";

interface PaymentEvidenceItem {
  evidence_type: string;
  description: string;
  source: string;
  confidence: number;
  metadata?: Record<string, unknown>;
}

// Payment Heuristics Engine
function evaluatePaymentRules(content: string, inputType: string): {
  evidence: PaymentEvidenceItem[];
  ruleScore: number;
  normalizedPayee?: string;
  paymentDomain?: string;
} {
  const evidence: PaymentEvidenceItem[] = [];
  let ruleScore = 0;
  let normalizedPayee: string | undefined;
  let paymentDomain: string | undefined;

  const text = (content || "").trim();
  const lower = text.toLowerCase();

  const PAYMENT_BRANDS = ["paytm", "phonepe", "gpay", "googlepay", "sbi", "hdfc", "icici", "axis", "amazonpay", "bhim"];

  // 1. UPI VPA Analysis
  if (inputType === "upi_id" || inputType === "qr_code" || inputType === "qr") {
    let vpa = inputType === "upi_id" ? lower : "";
    if ((inputType === "qr_code" || inputType === "qr") && lower.includes("pa=")) {
      const match = text.match(/pa=([^&]+)/i);
      if (match) vpa = decodeURIComponent(match[1]).toLowerCase();
    }

    if (vpa) {
      normalizedPayee = vpa;
      if (!vpa.includes("@") || vpa.split("@").length !== 2) {
        evidence.push({
          evidence_type: "UPI_SYNTAX_ANOMALY",
          description: "Malformed or non-standard UPI address structure",
          source: "rules_engine",
          confidence: 0.95
        });
        ruleScore += 35;
      } else {
        const [handle, psp] = vpa.split("@");
        // Deceptive Brand Impersonation
        for (const b of PAYMENT_BRANDS) {
          if (handle.includes(b)) {
            if (/\b(refund|support|care|help|desk|nodal|kyc|verify|verification|claim|reward|official)\b/i.test(handle) ||
                handle.includes("-refund") || handle.includes("care") || handle.includes("support")) {
              evidence.push({
                evidence_type: "BRAND_IMPERSONATION",
                description: `UPI handle [${vpa}] impersonates an official ${b.toUpperCase()} customer service or refund desk`,
                source: "rules_engine",
                confidence: 0.98
              });
              ruleScore += 85;
              break;
            }
          }
        }

        // Generic financial scam keywords
        if (/\b(cashback|lottery|winner|jackpot|freebonus|electricity-bill|billdesk-support)\b/i.test(handle)) {
          evidence.push({
            evidence_type: "DECEPTIVE_PAYEE_HANDLE",
            description: `UPI handle [${handle}] contains financial lure or utility pretext keywords`,
            source: "rules_engine",
            confidence: 0.90
          });
          ruleScore += 45;
        }

        // Suspicious PSP domain
        if (psp.includes(".") && !psp.startsWith("ok") && !psp.endsWith("bank")) {
          evidence.push({
            evidence_type: "SUSPICIOUS_PSP_DOMAIN",
            description: `UPI PSP handle [@${psp}] contains anomalous domain syntax`,
            source: "rules_engine",
            confidence: 0.85
          });
          ruleScore += 40;
        }
      }
    }
  }

  // 2. QR Code Reverse Collect Fraud Detection
  if (inputType === "qr_code" || inputType === "qr") {
    if (/(?:enter|type|input|share|put|provide)\s+(?:your\s+)?(?:(?:\d+[- ]?digit|secret|4|6)\s+)?(?:upi\s+)?(?:pin|code|password)\s+to\s+(?:receive|claim|accept|credit|get|refund)/i.test(lower) ||
        /(?:enter|type|input|put).*(?:pin|secret\s*code).*(?:receive|claim|get\s*refund|credit|accept)/i.test(lower)) {
      evidence.push({
        evidence_type: "REVERSE_COLLECT_FRAUD",
        description: "CRITICAL ALERT: QR note instructs entering a UPI PIN to receive money. In UPI architecture, entering your PIN ALWAYS debits funds from your bank account!",
        source: "rules_engine",
        confidence: 0.99
      });
      ruleScore += 90;
    }

    if (lower.includes("pn=") && /(?:support|customer\s*care|refund|official|helpdesk|cashback)/i.test(lower)) {
      const paMatch = text.match(/pa=([^&]+)/i);
      if (paMatch && /\d{4,}/.test(paMatch[1])) {
        evidence.push({
          evidence_type: "PAYEE_MISMATCH",
          description: "Payee name claims official entity but underlying UPI VPA belongs to an individual number",
          source: "rules_engine",
          confidence: 0.88
        });
        ruleScore += 45;
      }
    }
  }

  // 3. Payment URL / Domain Analysis
  if (inputType === "payment_url" || /(https?:\/\/[^\s]+)/i.test(text)) {
    let rawUrl = text;
    if (!rawUrl.startsWith("http://") && !rawUrl.startsWith("https://")) {
      rawUrl = "https://" + rawUrl;
    }
    try {
      const u = new URL(rawUrl);
      paymentDomain = u.hostname.toLowerCase();

      if (u.protocol === "http:" && !["localhost", "127.0.0.1"].includes(paymentDomain)) {
        evidence.push({
          evidence_type: "INSECURE_CONNECTION",
          description: "Payment link uses plain unencrypted HTTP",
          source: "rules_engine",
          confidence: 0.9
        });
        ruleScore += 25;
      }

      const riskyTlds = ["xyz", "top", "click", "buzz", "club", "tk", "ml", "ga", "cf", "gq", "icu", "cyou", "site", "online", "shop", "work", "live"];
      const ext = paymentDomain.split(".").pop();
      if (ext && riskyTlds.includes(ext)) {
        evidence.push({
          evidence_type: "RISKY_TLD",
          description: `Uses high-risk throwaway domain extension '.${ext}'`,
          source: "rules_engine",
          confidence: 0.85
        });
        ruleScore += 30;
      }

      for (const b of PAYMENT_BRANDS) {
        if (paymentDomain.includes(b) && !paymentDomain.endsWith(`${b}.com`) && !paymentDomain.endsWith(`${b}.in`)) {
          evidence.push({
            evidence_type: "BRAND_LOOKALIKE_DOMAIN",
            description: `Payment domain mimics legitimate brand ${b.toUpperCase()}`,
            source: "rules_engine",
            confidence: 0.95
          });
          ruleScore += 60;
          break;
        }
      }
    } catch {
      evidence.push({
        evidence_type: "MALFORMED_URL",
        description: "Payment URL format is invalid",
        source: "rules_engine",
        confidence: 0.8
      });
      ruleScore += 20;
    }
  }

  // 4. Message / Extortion / Remote Access Trap Analysis
  if (inputType === "message" || inputType === "screenshot") {
    if (/(?:electricity|power|bijli)\s+(?:bill\s+)?(?:will\s+be\s+)?(?:disconnected|cut|shut\s*off|disconnected\s+tonight)/i.test(lower)) {
      evidence.push({
        evidence_type: "UTILITY_EXTORTION",
        description: "Uses immediate electricity disconnection threat to pressure urgent payment",
        source: "rules_engine",
        confidence: 0.92
      });
      ruleScore += 50;
    }

    if (/\b(anydesk|teamviewer|rustdesk|quicksupport|airdroid|screenshare|screen\s*share)\b/i.test(lower)) {
      evidence.push({
        evidence_type: "REMOTE_ACCESS_TOOL",
        description: "Coerces victim to install remote desktop software (e.g., AnyDesk/TeamViewer) to hijack banking credentials",
        source: "rules_engine",
        confidence: 0.98
      });
      ruleScore += 85;
    }

    if (/(?:enter|type|share|input|put|provide)\s+(?:your\s+)?(?:(?:\d+[- ]?digit|secret|4|6)\s+)?(?:upi\s+)?(?:pin|code|password)\s+to\s+(?:receive|claim|accept|credit|get\s+refund)/i.test(lower) ||
        /(?:enter|type|input|put).*(?:pin|secret\s*code).*(?:receive|claim|get\s*refund|credit|accept)/i.test(lower)) {
      evidence.push({
        evidence_type: "REVERSE_COLLECT_FRAUD",
        description: "Urges entering UPI PIN to receive money. PIN entry only authorizes money leaving your account!",
        source: "rules_engine",
        confidence: 0.99
      });
      ruleScore += 90;
    }
  }

  // Screenshot unverified status disclaimer
  if (inputType === "screenshot") {
    evidence.push({
      evidence_type: "UNVERIFIED_EVIDENCE_SOURCE",
      description: "Payment status not independently verified. Screenshots and UTR numbers alone do not guarantee bank settlement.",
      source: "policy",
      confidence: 1.0
    });
  }

  return { evidence, ruleScore: Math.min(100, ruleScore), normalizedPayee, paymentDomain };
}

// AI contextual scam analysis for payments
async function callAiPaymentAnalysis(content: string, inputType: string): Promise<{
  aiScore: number;
  explanation: string;
  recommendedActions: string[];
} | null> {
  if (!AI_API_KEY) return null;

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 4500);

    const systemPrompt = `You are a financial fraud and cybersecurity expert analyzing a payment identifier, payment URL, QR code, or message for scam indicators (UPI fraud, reverse collect scams, fake payment apps, impersonation, utility bill threats).
Return ONLY valid JSON matching this schema:
{
  "risk_score": <number 0-100>,
  "explanation": "<concise evidence-backed 2-sentence explanation of findings>",
  "recommended_actions": ["<action 1>", "<action 2>"]
}`;

    const res = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${AI_MODEL}:generateContent?key=${AI_API_KEY}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      signal: controller.signal,
      body: JSON.stringify({
        contents: [
          {
            parts: [
              { text: systemPrompt },
              { text: `Analyze this payment input:\nType: ${inputType}\nContent:\n${content.slice(0, 1000)}` }
            ]
          }
        ],
        generationConfig: {
          temperature: 0.1,
          responseMimeType: "application/json"
        }
      })
    });

    clearTimeout(timeout);
    if (!res.ok) return null;

    const data = await res.json();
    const rawText = data?.candidates?.[0]?.content?.parts?.[0]?.text;
    if (!rawText) return null;

    const parsed = JSON.parse(rawText);
    return {
      aiScore: Math.min(100, Math.max(0, parseInt(parsed.risk_score, 10) || 0)),
      explanation: parsed.explanation || "Automated AI fraud assessment completed.",
      recommendedActions: Array.isArray(parsed.recommended_actions) ? parsed.recommended_actions : []
    };
  } catch {
    return null;
  }
}

serve(async (req) => {
  const corsRes = handleCors(req);
  if (corsRes) return corsRes;

  try {
    const body = await req.json();
    const { content, input_type = "upi_id", allow_ai = true } = body;

    if (!content || typeof content !== "string" || content.trim().length === 0) {
      return new Response(JSON.stringify({ error: "Missing or empty content parameter" }), {
        status: 400,
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    // SSRF safety check: reject internal / loopback / metadata IP addresses
    if (input_type === "payment_url") {
      try {
        const u = new URL(content.startsWith("http") ? content : "https://" + content);
        const host = u.hostname.toLowerCase();
        if (
          host === "localhost" ||
          host === "127.0.0.1" ||
          host === "::1" ||
          host.startsWith("192.168.") ||
          host.startsWith("10.") ||
          host.startsWith("172.16.") ||
          host === "169.254.169.254"
        ) {
          return new Response(JSON.stringify({ error: "Access to private or link-local network targets is prohibited" }), {
            status: 400,
            headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }
      } catch {
        // Proceed with syntax check
      }
    }

    const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);
    const authUser = await getAuthenticatedUser(req, supabase);

    // 1. Evaluate deterministic heuristics
    const { evidence, ruleScore, normalizedPayee, paymentDomain } = evaluatePaymentRules(content, input_type);

    // 2. Query threat intelligence if domain is present
    let threatIntelHit = false;
    if (paymentDomain) {
      const { data: threatData } = await supabase
        .from("threat_intelligence")
        .select("threat_type, confidence_score, source")
        .eq("indicator_value", paymentDomain)
        .maybeSingle();

      if (threatData) {
        threatIntelHit = true;
        evidence.push({
          evidence_type: "KNOWN_MALICIOUS_DOMAIN",
          description: `Domain is flagged in threat database as [${threatData.threat_type}]`,
          source: threatData.source || "threat_intelligence",
          confidence: threatData.confidence_score ? threatData.confidence_score / 100 : 0.95
        });
      }
    }

    // 3. Optional contextual AI analysis
    let aiResult: { aiScore: number; explanation: string; recommendedActions: string[] } | null = null;
    let detectionMethod = "rules";

    if (allow_ai && AI_API_KEY) {
      aiResult = await callAiPaymentAnalysis(content, input_type);
      if (aiResult) {
        detectionMethod = "hybrid";
      }
    }

    // 4. Score Blending
    let finalScore = ruleScore;
    if (threatIntelHit) {
      finalScore = Math.max(finalScore, 90);
    }

    if (aiResult) {
      if (ruleScore >= 75) {
        finalScore = ruleScore; // Deterministic evidence takes precedence for known scams
      } else {
        finalScore = Math.round(ruleScore * 0.55 + aiResult.aiScore * 0.45);
      }
    }

    finalScore = Math.min(100, Math.max(0, finalScore));

    let riskLevel = "safe";
    if (finalScore > 80) riskLevel = "critical";
    else if (finalScore > 60) riskLevel = "high";
    else if (finalScore > 40) riskLevel = "medium";
    else if (finalScore > 20) riskLevel = "low";

    // Standard safety recommendations
    const actions: string[] = [];
    if (evidence.some((e) => e.evidence_type === "REVERSE_COLLECT_FRAUD")) {
      actions.push("NEVER enter your UPI PIN. In UPI, receiving money NEVER requires entering your PIN.");
    }
    if (evidence.some((e) => e.evidence_type === "REMOTE_ACCESS_TOOL")) {
      actions.push("Do not install AnyDesk or TeamViewer. Disconnect immediately.");
    }
    if (evidence.some((e) => e.evidence_type === "UTILITY_EXTORTION")) {
      actions.push("Verify bill status directly on your electricity board's official website.");
    }
    if (!actions.length) {
      actions.push("Verify the payee identity with the recipient through a trusted independent channel.");
      actions.push("Check the verified merchant name in your UPI payment app before confirming any payment.");
    }

    const explanation = aiResult?.explanation || (
      finalScore > 60
        ? "High-risk payment fraud indicators detected. Review flagged evidence before proceeding."
        : "Standard payment identifier structure. No critical scam patterns detected."
    );

    // 5. Database Persistence if authenticated
    let scanId = crypto.randomUUID();
    const checkedAt = new Date().toISOString();

    if (authUser?.id) {
      const { data: insertedRecord } = await supabase
        .from("payment_scan_results")
        .insert({
          id: scanId,
          user_id: authUser.id,
          input_type,
          normalized_payee: normalizedPayee || null,
          payment_domain: paymentDomain || null,
          risk_score: finalScore,
          risk_level: riskLevel,
          detection_method: detectionMethod,
          indicators: evidence,
          explanation,
          recommended_actions: actions,
          reputation_source: threatIntelHit ? "threat_intelligence" : null,
          checked_at: checkedAt,
          payment_status: "unverified"
        })
        .select("id")
        .single();

      if (insertedRecord?.id) {
        scanId = insertedRecord.id;
        // Insert evidence items
        if (evidence.length > 0) {
          const evidenceRows = evidence.map((e) => ({
            scan_id: scanId,
            evidence_type: e.evidence_type,
            description: e.description,
            source: e.source,
            confidence: e.confidence,
            metadata: e.metadata || {}
          }));
          await supabase.from("payment_evidence").insert(evidenceRows);
        }
      }
    }

    return new Response(JSON.stringify({
      id: scanId,
      input_type,
      normalized_payee: normalizedPayee || null,
      payment_domain: paymentDomain || null,
      risk_score: finalScore,
      risk_level: riskLevel,
      detection_method: detectionMethod,
      indicators: evidence,
      explanation,
      recommended_actions: actions,
      payment_status: "unverified",
      checked_at: checkedAt
    }), {
      status: 200,
      headers: { ...corsHeaders, "Content-Type": "application/json" }
    });
  } catch (err) {
    return new Response(JSON.stringify({ error: err instanceof Error ? err.message : "Payment verification failed" }), {
      status: 500,
      headers: { ...corsHeaders, "Content-Type": "application/json" }
    });
  }
});
