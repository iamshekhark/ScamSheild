// Supabase Edge Function: process-email-notification
// Dedicated notification worker verifying consent, rate limits, deduplication, and transactional delivery

import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { corsHeaders, handleCors } from "../_shared/cors.ts";
import { EmailTemplates } from "../_shared/emailTemplates.ts";
import { sendTransactionalEmail } from "../_shared/emailSender.ts";
import { getAuthenticatedUser } from "../_shared/authHelper.ts";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL") || "";
const SUPABASE_SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || "";

serve(async (req) => {
  const corsRes = handleCors(req);
  if (corsRes) return corsRes;

  try {
    const { userId, notificationType, payload } = await req.json();

    if (!userId || !notificationType) {
      return new Response(JSON.stringify({ error: "Missing userId or notificationType" }), {
        status: 400,
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);

    // Verify caller authorization: must be either service role or matching authenticated user
    const authHeader = req.headers.get("Authorization");
    const token = authHeader ? authHeader.replace(/^Bearer\s+/i, "").trim() : "";
    const isServiceRole = token && SUPABASE_SERVICE_ROLE_KEY && token === SUPABASE_SERVICE_ROLE_KEY;

    if (!isServiceRole) {
      const authUser = await getAuthenticatedUser(req, supabase);
      if (!authUser?.id || authUser.id !== userId) {
        return new Response(JSON.stringify({ error: "Forbidden: Cannot dispatch notifications for another user" }), {
          status: 403,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
    }

    // 1. Check user notification preferences
    const { data: prefs } = await supabase
      .from("notification_preferences")
      .select("*")
      .eq("user_id", userId)
      .maybeSingle();

    if (!prefs?.recipient_email || !prefs?.recipient_verified) {
      return new Response(JSON.stringify({
        skipped: true,
        reason: "No verified recipient email configured for notifications"
      }), {
        status: 200,
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    let template: { subject: string; html: string } | null = null;
    let dedupKey = `${notificationType}_${userId}_${Date.now()}`;

    if (notificationType === "high_risk_alert") {
      if (!prefs.critical_risk_alerts && !prefs.suspicious_email_alerts) {
        return new Response(JSON.stringify({ skipped: true, reason: "Alerts disabled in user settings" }));
      }
      dedupKey = `high_risk_${payload.fingerprint || Date.now()}`;
      template = EmailTemplates.highRiskAlert(payload);
    } else if (notificationType === "new_login") {
      if (!prefs.account_security_alerts) {
        return new Response(JSON.stringify({ skipped: true, reason: "Account security alerts disabled" }));
      }
      dedupKey = `login_${userId}_${payload.ip}_${Math.floor(Date.now() / 3600000)}`;
      template = EmailTemplates.newLoginAlert(payload.ip, payload.userAgent, payload.time);
    } else if (notificationType === "welcome") {
      dedupKey = `welcome_${userId}`;
      template = EmailTemplates.welcome(payload.displayName);
    }

    if (!template) {
      return new Response(JSON.stringify({ error: "Unsupported notification type" }), {
        status: 400,
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    // 2. Dispatch with deduplication & retry handling
    const result = await sendTransactionalEmail({
      userId,
      to: prefs.recipient_email,
      subject: template.subject,
      html: template.html,
      notificationType,
      deduplicationKey: dedupKey
    });

    return new Response(JSON.stringify({
      success: result.success,
      deliveryStatus: result.deliveryStatus,
      messageId: result.messageId
    }), {
      status: 200,
      headers: { ...corsHeaders, "Content-Type": "application/json" }
    });
  } catch (err) {
    return new Response(JSON.stringify({ error: err instanceof Error ? err.message : "Notification processing failed" }), {
      status: 500,
      headers: { ...corsHeaders, "Content-Type": "application/json" }
    });
  }
});
