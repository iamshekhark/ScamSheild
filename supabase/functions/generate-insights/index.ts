// Supabase Edge Function: generate-insights
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { corsHeaders, handleCors } from "../_shared/cors.ts";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL") || "";
const SUPABASE_SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || "";

serve(async (req) => {
  const cors = handleCors(req);
  if (cors) return cors;

  try {
    const authHeader = req.headers.get("Authorization");
    if (!authHeader) {
      return new Response(JSON.stringify({ error: "Missing authorization header" }), {
        status: 401,
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);
    const token = authHeader.replace("Bearer ", "");
    const { data: { user }, error: authErr } = await supabase.auth.getUser(token);

    if (authErr || !user) {
      return new Response(JSON.stringify({ error: "Invalid session token" }), {
        status: 401,
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    // Retrieve user scans from past 30 days
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

    const { data: scans, error: scansErr } = await supabase
      .from("scan_history")
      .select("id, scan_type, risk_score, risk_level, indicators, normalized_domain, created_at")
      .eq("user_id", user.id)
      .gte("created_at", thirtyDaysAgo.toISOString())
      .order("created_at", { ascending: false });

    if (scansErr) throw scansErr;

    const totalScans = scans?.length || 0;
    if (totalScans === 0) {
      return new Response(
        JSON.stringify({
          insights: [],
          metrics: { total: 0, critical: 0, high: 0, medium: 0, low: 0 },
          message: "No scans found in the reporting period. Scan URLs or messages to generate personalized insights."
        }),
        {
          status: 200,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        }
      );
    }

    // Metrics aggregation
    const riskCounts = { low: 0, medium: 0, high: 0, critical: 0 };
    const categoryFrequency: Record<string, number> = {};
    const domainCounts: Record<string, number> = {};

    scans?.forEach((s) => {
      const lvl = (s.risk_level || "low").toLowerCase() as keyof typeof riskCounts;
      if (riskCounts[lvl] !== undefined) riskCounts[lvl]++;

      if (Array.isArray(s.indicators)) {
        s.indicators.forEach((ind: { indicator_type?: string }) => {
          if (ind.indicator_type) {
            categoryFrequency[ind.indicator_type] = (categoryFrequency[ind.indicator_type] || 0) + 1;
          }
        });
      }

      if (s.normalized_domain) {
        domainCounts[s.normalized_domain] = (domainCounts[s.normalized_domain] || 0) + 1;
      }
    });

    const topCategories = Object.entries(categoryFrequency)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 3)
      .map(([cat, count]) => ({ category: cat, count }));

    // Generate evidence-based recommendations
    const recommendations: string[] = [];
    if (categoryFrequency["OTP_REQUEST"]) {
      recommendations.push("High frequency of OTP scams detected: never share verification codes with callers.");
    }
    if (categoryFrequency["BRAND_IMPERSONATION"]) {
      recommendations.push("Brand look-alike attacks observed: bookmark your primary banking and shopping sites.");
    }
    if (riskCounts.critical + riskCounts.high > 0) {
      recommendations.push(`You encountered ${riskCounts.critical + riskCounts.high} high/critical risk links. Enable browser warnings.`);
    }

    const title = `Security Summary: ${totalScans} Scans Audited`;
    const description = `In the last 30 days, ${riskCounts.critical} critical and ${riskCounts.high} high risk items were intercepted. Dominant vector: ${topCategories[0]?.category || "None"}.`;

    // Save insight record
    await supabase.from("ai_insights").insert({
      user_id: user.id,
      insight_type: "weekly_summary",
      title,
      description,
      supporting_metrics: {
        total_scans: totalScans,
        risk_breakdown: riskCounts,
        top_categories: topCategories
      },
      recommendations,
      period_start: thirtyDaysAgo.toISOString(),
      period_end: new Date().toISOString()
    });

    return new Response(
      JSON.stringify({
        summary: {
          title,
          description,
          metrics: {
            total: totalScans,
            ...riskCounts
          },
          top_categories: topCategories,
          recommendations
        }
      }),
      {
        status: 200,
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      }
    );
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : "Internal error";
    return new Response(JSON.stringify({ error: message }), {
      status: 500,
      headers: { ...corsHeaders, "Content-Type": "application/json" }
    });
  }
});
