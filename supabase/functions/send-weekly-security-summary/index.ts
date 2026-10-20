// Supabase Edge Function: send-weekly-security-summary
// Scheduled / cron worker aggregating 7-day risk metrics and delivering security summaries

import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { corsHeaders, handleCors } from "../_shared/cors.ts";
import { EmailTemplates } from "../_shared/emailTemplates.ts";
import { sendTransactionalEmail } from "../_shared/emailSender.ts";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL") || "";
const SUPABASE_SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || "";

serve(async (req) => {
  const corsRes = handleCors(req);
  if (corsRes) return corsRes;

  try {
    const { userId } = await req.json().catch(() => ({ userId: undefined }));
    const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);

    // Fetch users with weekly_summary enabled and a verified recipient
    let query = supabase
      .from("notification_preferences")
      .select("user_id, recipient_email, recipient_verified, weekly_summary")
      .eq("weekly_summary", true)
      .eq("recipient_verified", true);

    if (userId) {
      query = query.eq("user_id", userId);
    }

    const { data: recipients, error: recErr } = await query;
    if (recErr) throw recErr;

    const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 3600 * 1000).toISOString();
    let sentCount = 0;

    for (const rec of recipients || []) {
      // Calculate 7-day stats for this user
      const { data: scans } = await supabase
        .from("scan_history")
        .select("risk_score, risk_level, scan_type")
        .eq("user_id", rec.user_id)
        .gte("created_at", sevenDaysAgo);

      const totalScans = scans?.length || 0;
      const threatsBlocked = scans?.filter((s) => s.risk_score >= 50).length || 0;

      const template = EmailTemplates.weeklyReport({
        totalScans,
        threatsBlocked,
        topCategory: threatsBlocked > 0 ? "Phishing & Spoofing Attacks" : "Standard Web Browsing"
      });

      const yearWeek = Math.floor(Date.now() / (7 * 86400 * 1000));
      const res = await sendTransactionalEmail({
        userId: rec.user_id,
        to: rec.recipient_email,
        subject: template.subject,
        html: template.html,
        notificationType: "weekly_summary",
        deduplicationKey: `weekly_${rec.user_id}_${yearWeek}`
      });

      if (res.success) sentCount++;
    }

    return new Response(JSON.stringify({
      success: true,
      processed: recipients?.length || 0,
      dispatched: sentCount
    }), {
      status: 200,
      headers: { ...corsHeaders, "Content-Type": "application/json" }
    });
  } catch (err) {
    return new Response(JSON.stringify({ error: err instanceof Error ? err.message : "Weekly summary job failed" }), {
      status: 500,
      headers: { ...corsHeaders, "Content-Type": "application/json" }
    });
  }
});
