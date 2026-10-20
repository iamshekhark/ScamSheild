// Supabase Edge Function: delete-account-data
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

    const { action, scan_id } = await req.json();

    if (action === "delete_single_scan" && scan_id) {
      const { error: delErr } = await supabase
        .from("scan_history")
        .delete()
        .eq("id", scan_id)
        .eq("user_id", user.id);

      if (delErr) throw delErr;
      return new Response(JSON.stringify({ success: true, message: "Scan deleted successfully" }), {
        status: 200,
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    if (action === "clear_history") {
      const { error: delErr } = await supabase
        .from("scan_history")
        .delete()
        .eq("user_id", user.id);

      if (delErr) throw delErr;
      return new Response(JSON.stringify({ success: true, message: "All scan history cleared" }), {
        status: 200,
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    if (action === "delete_account") {
      // Delete user profile and data (cascading deletes handle tables)
      await supabase.from("profiles").delete().eq("id", user.id);
      await supabase.auth.admin.deleteUser(user.id);

      return new Response(JSON.stringify({ success: true, message: "Account and associated data deleted permanently" }), {
        status: 200,
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    return new Response(JSON.stringify({ error: "Invalid action. Supported: delete_single_scan, clear_history, delete_account" }), {
      status: 400,
      headers: { ...corsHeaders, "Content-Type": "application/json" }
    });
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : "Internal error";
    return new Response(JSON.stringify({ error: message }), {
      status: 500,
      headers: { ...corsHeaders, "Content-Type": "application/json" }
    });
  }
});
