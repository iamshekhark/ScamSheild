// Supabase Edge Function: disconnect-email-account
// Safely revokes provider access, purges stored tokens, and notifies user

import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { corsHeaders, handleCors } from "../_shared/cors.ts";
import { EmailTemplates } from "../_shared/emailTemplates.ts";
import { sendTransactionalEmail } from "../_shared/emailSender.ts";
import { getAuthenticatedUser } from "../_shared/authHelper.ts";
import { decryptToken } from "../_shared/crypto.ts";

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

    // 1. Fetch account to disconnect (enforcing ownership)
    const { data: account, error: fetchErr } = await supabase
      .from("connected_email_accounts")
      .select("*")
      .eq("id", accountId)
      .eq("user_id", userId)
      .single();

    if (fetchErr || !account) {
      return new Response(JSON.stringify({ error: "Connected email account not found" }), {
        status: 404,
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    // 2. Fetch encrypted token from isolated table or legacy column
    let encryptedToken = account.encrypted_refresh_token || "";
    const { data: tokenRecord } = await supabase
      .from("connected_mailbox_tokens")
      .select("encrypted_refresh_token")
      .eq("account_id", accountId)
      .maybeSingle();

    if (tokenRecord?.encrypted_refresh_token) {
      encryptedToken = tokenRecord.encrypted_refresh_token;
    }

    // 3. Revoke token with upstream provider (best effort)
    if (account.provider === "gmail" && encryptedToken) {
      try {
        const decrypted = await decryptToken(encryptedToken);
        if (decrypted) {
          await fetch(`https://oauth2.googleapis.com/revoke?token=${encodeURIComponent(decrypted)}`, {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" }
          });
        }
      } catch (revokeErr) {
        console.warn("[disconnect-email-account] Upstream revocation call:", revokeErr);
      }
    }

    // 4. Delete tokens and account records
    await supabase
      .from("connected_mailbox_tokens")
      .delete()
      .eq("account_id", accountId);

    await supabase
      .from("connected_email_accounts")
      .delete()
      .eq("id", accountId)
      .eq("user_id", userId);

    // 5. Send notification email to user if recipient is configured
    const { data: prefs } = await supabase
      .from("notification_preferences")
      .select("recipient_email, connection_status_alerts, recipient_verified")
      .eq("user_id", userId)
      .maybeSingle();

    if (prefs?.connection_status_alerts && prefs?.recipient_email && prefs?.recipient_verified) {
      const template = EmailTemplates.mailboxRevoked(account.provider, account.email_address);
      await sendTransactionalEmail({
        userId,
        to: prefs.recipient_email,
        subject: template.subject,
        html: template.html,
        notificationType: "mailbox_revoked",
        deduplicationKey: `revoked_${accountId}_${Date.now()}`
      });
    }

    return new Response(JSON.stringify({
      success: true,
      message: `Disconnected ${account.provider.toUpperCase()} account (${account.email_address})`
    }), {
      status: 200,
      headers: { ...corsHeaders, "Content-Type": "application/json" }
    });
  } catch (err) {
    return new Response(JSON.stringify({ error: err instanceof Error ? err.message : "Disconnection failed" }), {
      status: 500,
      headers: { ...corsHeaders, "Content-Type": "application/json" }
    });
  }
});
