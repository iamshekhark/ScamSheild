// Supabase Edge Function: submit-feedback
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

    const { scan_id, feedback_type, comment } = await req.json();

    if (!scan_id || !["correct", "false_positive", "false_negative"].includes(feedback_type)) {
      return new Response(JSON.stringify({ error: "Invalid scan_id or feedback_type" }), {
        status: 400,
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    // Verify scan ownership
    const { data: scan, error: scanErr } = await supabase
      .from("scan_history")
      .select("id")
      .eq("id", scan_id)
      .eq("user_id", user.id)
      .maybeSingle();

    if (scanErr || !scan) {
      return new Response(JSON.stringify({ error: "Scan record not found or access denied" }), {
        status: 404,
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    const { data: feedback, error: fbErr } = await supabase
      .from("user_feedback")
      .upsert({
        user_id: user.id,
        scan_id: scan_id,
        feedback_type,
        comment: comment ? String(comment).slice(0, 1000) : null
      })
      .select()
      .single();

    if (fbErr) throw fbErr;

    return new Response(
      JSON.stringify({ success: true, feedback }),
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
