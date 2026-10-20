// Supabase Edge Function: update-notification-preferences
// Updates alert preferences and handles recipient change verification

import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { corsHeaders, handleCors } from "../_shared/cors.ts";
import { getAuthenticatedUser } from "../_shared/authHelper.ts";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL") || "";
const SUPABASE_SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || "";

serve(async (req) => {
  const corsRes = handleCors(req);
  if (corsRes) return corsRes;

  try {
    const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);
    const authUser = await getAuthenticatedUser(req, supabase);

    if (!authUser?.id) {
      return new Response(JSON.stringify({ error: "Unauthorized: Active user session required" }), {
        status: 401,
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    const userId = authUser.id;
    const {
      recipientEmail,
      suspiciousEmailAlerts,
      criticalRiskAlerts,
      accountSecurityAlerts,
      connectionStatusAlerts,
      weeklySummary
    } = await req.json();

    // Fetch existing preferences
    const { data: existing } = await supabase
      .from("notification_preferences")
      .select("*")
      .eq("user_id", userId)
      .maybeSingle();

    // If recipient email changed, reset recipient_verified flag until OTP is validated
    let recipientVerified = existing?.recipient_verified ?? false;
    const cleanEmail = (recipientEmail || "").toLowerCase().trim();
    if (cleanEmail && existing?.recipient_email && cleanEmail !== existing.recipient_email) {
      recipientVerified = false;
    }

    const updatePayload: Record<string, unknown> = {
      user_id: userId,
      updated_at: new Date().toISOString()
    };

    if (cleanEmail) updatePayload.recipient_email = cleanEmail;
    updatePayload.recipient_verified = recipientVerified;
    if (suspiciousEmailAlerts !== undefined) updatePayload.suspicious_email_alerts = suspiciousEmailAlerts;
    if (criticalRiskAlerts !== undefined) updatePayload.critical_risk_alerts = criticalRiskAlerts;
    if (accountSecurityAlerts !== undefined) updatePayload.account_security_alerts = accountSecurityAlerts;
    if (connectionStatusAlerts !== undefined) updatePayload.connection_status_alerts = connectionStatusAlerts;
    if (weeklySummary !== undefined) updatePayload.weekly_summary = weeklySummary;

    const { data: updated, error: upsertErr } = await supabase
      .from("notification_preferences")
      .upsert(updatePayload, { onConflict: "user_id" })
      .select()
      .single();

    if (upsertErr) throw upsertErr;

    return new Response(JSON.stringify({
      success: true,
      preferences: updated,
      requiresVerification: !recipientVerified && Boolean(cleanEmail)
    }), {
      status: 200,
      headers: { ...corsHeaders, "Content-Type": "application/json" }
    });
  } catch (err) {
    return new Response(JSON.stringify({ error: err instanceof Error ? err.message : "Failed to update preferences" }), {
      status: 500,
      headers: { ...corsHeaders, "Content-Type": "application/json" }
    });
  }
});
