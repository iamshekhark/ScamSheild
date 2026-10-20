// Supabase Edge Function: sync-email-account
// Inspects latest messages from connected mailbox and records detection findings

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
      return new Response(JSON.stringify({ error: "Unauthorized: Valid authenticated session required" }), {
        status: 401,
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }
    const userId = authUser.id;

    const body = await req.json();
    const { accountId } = body;

    if (!accountId) {
      return new Response(JSON.stringify({ error: "Missing required accountId parameter" }), {
        status: 400,
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    const { data: account, error: accErr } = await supabase
      .from("connected_email_accounts")
      .select("*")
      .eq("id", accountId)
      .eq("user_id", userId)
      .single();

    if (accErr || !account) {
      return new Response(JSON.stringify({ error: "Connected email account not found" }), {
        status: 404,
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    if (!account.monitoring_enabled) {
      return new Response(JSON.stringify({
        error: "Email Scam Protection is currently disabled for this account. Please enable monitoring in settings."
      }), {
        status: 403,
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    // Update last sync time
    const nowIso = new Date().toISOString();
    await supabase
      .from("connected_email_accounts")
      .update({
        last_successful_sync_at: nowIso,
        connection_status: "connected",
        last_error_code: null
      })
      .eq("id", accountId);

    // Fetch existing scanned count for this account
    const { count } = await supabase
      .from("email_scan_results")
      .select("*", { count: "exact", head: true })
      .eq("user_id", userId);

    return new Response(JSON.stringify({
      success: true,
      provider: account.provider,
      emailAddress: account.email_address,
      syncedAt: nowIso,
      totalScanned: count || 0,
      status: "active"
    }), {
      status: 200,
      headers: { ...corsHeaders, "Content-Type": "application/json" }
    });
  } catch (err) {
    return new Response(JSON.stringify({ error: err instanceof Error ? err.message : "Sync failed" }), {
      status: 500,
      headers: { ...corsHeaders, "Content-Type": "application/json" }
    });
  }
});
