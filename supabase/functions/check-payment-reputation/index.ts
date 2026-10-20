// Supabase Edge Function: check-payment-reputation
// Queries threat intelligence database for payment domains, VPAs, or merchant identifiers

import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { corsHeaders, handleCors } from "../_shared/cors.ts";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL") || "";
const SUPABASE_SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || "";

serve(async (req) => {
  const corsRes = handleCors(req);
  if (corsRes) return corsRes;

  try {
    const { identifier, indicator_type = "domain" } = await req.json();

    if (!identifier) {
      return new Response(JSON.stringify({ error: "Missing identifier parameter" }), {
        status: 400,
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    const clean = identifier.trim().toLowerCase();
    const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);

    const { data: record, error } = await supabase
      .from("threat_intelligence")
      .select("indicator_value, threat_type, confidence_score, source, description, created_at")
      .eq("indicator_value", clean)
      .maybeSingle();

    if (error) throw error;

    if (!record) {
      return new Response(JSON.stringify({
        found: false,
        identifier: clean,
        reputation: "unknown",
        message: "No known threat intelligence reports on record for this identifier."
      }), {
        status: 200,
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    return new Response(JSON.stringify({
      found: true,
      identifier: clean,
      reputation: "malicious",
      threat_type: record.threat_type,
      confidence_score: record.confidence_score,
      source: record.source,
      description: record.description,
      reported_at: record.created_at
    }), {
      status: 200,
      headers: { ...corsHeaders, "Content-Type": "application/json" }
    });
  } catch (err) {
    return new Response(JSON.stringify({ error: err instanceof Error ? err.message : "Reputation lookup failed" }), {
      status: 500,
      headers: { ...corsHeaders, "Content-Type": "application/json" }
    });
  }
});
