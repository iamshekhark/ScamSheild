// Supabase Edge Function: get-payment-scan-history
// Returns paginated payment fraud scans for the authenticated user

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

    const url = new URL(req.url);
    const limit = Math.min(50, Math.max(1, parseInt(url.searchParams.get("limit") || "20", 10)));
    const offset = Math.max(0, parseInt(url.searchParams.get("offset") || "0", 10));
    const inputType = url.searchParams.get("input_type");

    let query = supabase
      .from("payment_scan_results")
      .select("id, input_type, normalized_payee, payment_domain, risk_score, risk_level, detection_method, indicators, explanation, recommended_actions, payment_status, created_at", { count: "exact" })
      .eq("user_id", authUser.id)
      .order("created_at", { ascending: false })
      .range(offset, offset + limit - 1);

    if (inputType && inputType !== "all") {
      query = query.eq("input_type", inputType);
    }

    const { data, count, error } = await query;
    if (error) throw error;

    return new Response(JSON.stringify({
      scans: data || [],
      total: count || 0,
      limit,
      offset
    }), {
      status: 200,
      headers: { ...corsHeaders, "Content-Type": "application/json" }
    });
  } catch (err) {
    return new Response(JSON.stringify({ error: err instanceof Error ? err.message : "Failed to load payment history" }), {
      status: 500,
      headers: { ...corsHeaders, "Content-Type": "application/json" }
    });
  }
});
