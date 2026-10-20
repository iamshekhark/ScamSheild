// Supabase Edge Function: complete-email-oauth
// Server-side OAuth 2.0 authorization code exchange and secure mailbox identity binding
// Supports BOTH:
// 1. Direct GET callback from provider (Backend Callback Architecture)
// 2. Authenticated POST invocation from frontend (Client Handshake Architecture)
// Enforces single-use transaction consumption, PKCE verification, AES-256-GCM token encryption, and token isolation

import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { corsHeaders, handleCors } from "../_shared/cors.ts";
import { getAuthenticatedUser } from "../_shared/authHelper.ts";
import { encryptToken } from "../_shared/crypto.ts";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL") || "";
const SUPABASE_SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || "";

const GOOGLE_CLIENT_ID = Deno.env.get("GOOGLE_CLIENT_ID") || "";
const GOOGLE_CLIENT_SECRET = Deno.env.get("GOOGLE_CLIENT_SECRET") || "";

const MICROSOFT_CLIENT_ID = Deno.env.get("MICROSOFT_CLIENT_ID") || Deno.env.get("AZURE_CLIENT_ID") || "";
const MICROSOFT_CLIENT_SECRET = Deno.env.get("MICROSOFT_CLIENT_SECRET") || Deno.env.get("AZURE_CLIENT_SECRET") || "";
const MICROSOFT_TENANT_ID = Deno.env.get("MICROSOFT_TENANT_ID") || "common";

const DASHBOARD_ORIGIN = Deno.env.get("DASHBOARD_ORIGIN") || "http://localhost:5173";

const ALLOWED_REDIRECT_ORIGINS = [
  "http://localhost:5173",
  "http://localhost:5174",
  "http://localhost:3000",
  "http://127.0.0.1:5173",
  "http://127.0.0.1:5174",
  "chrome-extension://",
  "https://scamshield.local",
  DASHBOARD_ORIGIN,
  SUPABASE_URL
].filter(Boolean);

serve(async (req) => {
  const corsRes = handleCors(req);
  if (corsRes) return corsRes;

  const isGetCallback = req.method === "GET";
  const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);

  try {
    let provider = "";
    let code = "";
    let state = "";
    let clientRedirectUri = "";
    let userId = "";

    if (isGetCallback) {
      // Flow A: Provider redirected browser directly to this backend endpoint
      const url = new URL(req.url);
      code = url.searchParams.get("code") || "";
      state = url.searchParams.get("state") || "";
      const errorParam = url.searchParams.get("error");
      const errorDesc = url.searchParams.get("error_description");

      if (errorParam) {
        return Response.redirect(
          `${DASHBOARD_ORIGIN}/?error=${encodeURIComponent(errorParam)}&error_description=${encodeURIComponent(errorDesc || "")}`,
          302
        );
      }

      if (!code || !state) {
        return Response.redirect(`${DASHBOARD_ORIGIN}/?error=missing_code_or_state`, 302);
      }
    } else {
      // Flow B: Frontend authenticated POST request
      const authUser = await getAuthenticatedUser(req, supabase);
      if (!authUser?.id) {
        return new Response(JSON.stringify({ error: "Unauthorized: Valid authenticated user session required" }), {
          status: 401,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
      userId = authUser.id;

      const body = await req.json();
      provider = body.provider || "";
      code = body.code || "";
      state = body.state || "";
      clientRedirectUri = body.redirectUri || "";
    }

    if (!code || !state) {
      return new Response(JSON.stringify({ error: "Missing required parameters (code, state)" }), {
        status: 400,
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    // 1. Atomically consume the pending transaction to prevent race conditions or replay attacks
    const nowIso = new Date().toISOString();
    const { data: tx, error: txUpdateErr } = await supabase
      .from("oauth_pending_transactions")
      .update({ consumed_at: nowIso })
      .eq("state", state)
      .is("consumed_at", null)
      .select("*")
      .maybeSingle();

    if (txUpdateErr) {
      console.error("[complete-email-oauth] Error atomically consuming oauth transaction:", txUpdateErr);
    }

    if (!tx) {
      if (isGetCallback) {
        return Response.redirect(`${DASHBOARD_ORIGIN}/?error=state_already_consumed_or_invalid`, 302);
      }
      return new Response(JSON.stringify({ error: "OAuth authorization transaction already consumed or invalid (replay attack rejected)" }), {
        status: 400,
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    if (new Date(tx.expires_at).getTime() < Date.now()) {
      if (isGetCallback) {
        return Response.redirect(`${DASHBOARD_ORIGIN}/?error=transaction_expired`, 302);
      }
      return new Response(JSON.stringify({ error: "OAuth authorization transaction has expired. Please initiate connection again." }), {
        status: 400,
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    // User binding verification
    if (isGetCallback) {
      userId = tx.user_id; // Securely extracted from server-side record bound at start time
      provider = tx.provider;
    } else {
      if (tx.user_id !== userId) {
        return new Response(JSON.stringify({ error: "OAuth session state belongs to a different authenticated user" }), {
          status: 403,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
      if (provider && tx.provider !== provider) {
        return new Response(JSON.stringify({ error: "OAuth provider mismatch between session and callback" }), {
          status: 400,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
      provider = tx.provider;
    }

    const codeVerifier = tx.code_verifier || "";
    const effectiveRedirectUri = tx.redirect_uri || clientRedirectUri || `${DASHBOARD_ORIGIN}/`;

    let accountEmail = "";
    let providerAccountId = "";
    let encryptedRefreshToken = "";
    let grantedScopes: string[] = [];
    let expiresInSeconds = 3600;

    // 2. Exchange authorization code with upstream provider
    if (provider === "gmail") {
      if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET) {
        const errDesc = "Google OAuth credentials (GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET) are not configured in backend environment.";
        if (isGetCallback) {
          return Response.redirect(`${DASHBOARD_ORIGIN}/?error=${encodeURIComponent(errDesc)}`, 302);
        }
        return new Response(JSON.stringify({ error: errDesc }), {
          status: 503,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }

      const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          code,
          client_id: GOOGLE_CLIENT_ID,
          client_secret: GOOGLE_CLIENT_SECRET,
          redirect_uri: effectiveRedirectUri,
          grant_type: "authorization_code",
          code_verifier: codeVerifier
        })
      });

      const tokenData = await tokenRes.json();
      if (!tokenRes.ok) {
        console.error("[complete-email-oauth] Google token exchange failed:", tokenData);
        throw new Error(tokenData.error_description || tokenData.error || "Google token exchange failed");
      }

      // Fetch authentic mailbox identity from Google (never trust frontend-supplied email)
      const userRes = await fetch("https://www.googleapis.com/oauth2/v2/userinfo", {
        headers: { Authorization: `Bearer ${tokenData.access_token}` }
      });
      const userData = await userRes.json();
      if (!userData?.email) {
        throw new Error("Unable to retrieve verified email address from Google profile");
      }

      accountEmail = userData.email.toLowerCase().trim();
      providerAccountId = userData.id || userData.email;
      expiresInSeconds = tokenData.expires_in || 3600;
      grantedScopes = (tokenData.scope || "").split(" ");

      if (tokenData.refresh_token) {
        encryptedRefreshToken = await encryptToken(tokenData.refresh_token);
      }
    } else {
      // provider === "outlook"
      if (!MICROSOFT_CLIENT_ID || !MICROSOFT_CLIENT_SECRET) {
        const errDesc = "Microsoft OAuth credentials (MICROSOFT_CLIENT_ID, MICROSOFT_CLIENT_SECRET) are not configured in backend environment.";
        if (isGetCallback) {
          return Response.redirect(`${DASHBOARD_ORIGIN}/?error=${encodeURIComponent(errDesc)}`, 302);
        }
        return new Response(JSON.stringify({ error: errDesc }), {
          status: 503,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }

      const tokenRes = await fetch(`https://login.microsoftonline.com/${MICROSOFT_TENANT_ID}/oauth2/v2.0/token`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          client_id: MICROSOFT_CLIENT_ID,
          client_secret: MICROSOFT_CLIENT_SECRET,
          code,
          redirect_uri: effectiveRedirectUri,
          grant_type: "authorization_code",
          code_verifier: codeVerifier
        })
      });

      const tokenData = await tokenRes.json();
      if (!tokenRes.ok) {
        console.error("[complete-email-oauth] Microsoft token exchange failed:", tokenData);
        throw new Error(tokenData.error_description || tokenData.error || "Microsoft token exchange failed");
      }

      // Fetch authentic mailbox identity from Microsoft Graph API
      const userRes = await fetch("https://graph.microsoft.com/v1.0/me", {
        headers: { Authorization: `Bearer ${tokenData.access_token}` }
      });
      const userData = await userRes.json();
      const rawEmail = userData?.mail || userData?.userPrincipalName;
      if (!rawEmail) {
        throw new Error("Unable to retrieve verified email address from Microsoft Graph");
      }

      accountEmail = rawEmail.toLowerCase().trim();
      providerAccountId = userData.id || rawEmail;
      expiresInSeconds = tokenData.expires_in || 3600;
      grantedScopes = (tokenData.scope || "").split(" ");

      if (tokenData.refresh_token) {
        encryptedRefreshToken = await encryptToken(tokenData.refresh_token);
      }
    }

    if (!accountEmail || !providerAccountId) {
      throw new Error("Failed to extract authentic account identity from provider");
    }

    // 3. Upsert mailbox account record (tokens excluded from this table)
    const { data: record, error: dbErr } = await supabase
      .from("connected_email_accounts")
      .upsert({
        user_id: userId,
        provider,
        provider_account_id: providerAccountId,
        email_address: accountEmail,
        connection_status: "connected",
        granted_scopes: grantedScopes,
        access_token_expiry: new Date(Date.now() + expiresInSeconds * 1000).toISOString(),
        monitoring_enabled: false, // Requires explicit user toggle
        last_successful_sync_at: new Date().toISOString(),
        last_error_code: null,
        updated_at: new Date().toISOString()
      }, { onConflict: "user_id,provider,provider_account_id" })
      .select("id, user_id, provider, provider_account_id, email_address, connection_status, granted_scopes, monitoring_enabled, last_successful_sync_at, created_at, updated_at")
      .single();

    if (dbErr) throw dbErr;

    // 4. Persist encrypted refresh token in isolated token table (fail-closed if secure write fails)
    if (encryptedRefreshToken && record?.id) {
      const { error: tokenErr } = await supabase
        .from("connected_mailbox_tokens")
        .upsert({
          account_id: record.id,
          user_id: userId,
          encrypted_refresh_token: encryptedRefreshToken,
          token_encryption_version: "v1",
          updated_at: new Date().toISOString()
        }, { onConflict: "account_id" });

      if (tokenErr) {
        console.error("[complete-email-oauth] Security error writing to connected_mailbox_tokens:", tokenErr.message);
        // Fail-closed: revert or mark connection error so an insecure connection is never presented as healthy
        await supabase
          .from("connected_email_accounts")
          .update({
            connection_status: "error",
            last_error_code: "TOKEN_STORAGE_FAILED",
            updated_at: new Date().toISOString()
          })
          .eq("id", record.id);

        throw new Error("CRITICAL_SECURITY_ERROR: Failed to securely store encrypted authorization token");
      }
    }

    // 5. Return response
    if (isGetCallback) {
      // Redirect browser back to dashboard with success query parameters
      return Response.redirect(
        `${DASHBOARD_ORIGIN}/?oauth_status=success&provider=${provider}&email=${encodeURIComponent(accountEmail)}`,
        302
      );
    }

    return new Response(JSON.stringify({
      success: true,
      account: {
        id: record.id,
        user_id: record.user_id,
        provider: record.provider,
        provider_account_id: record.provider_account_id,
        email_address: record.email_address,
        connection_status: record.connection_status,
        granted_scopes: record.granted_scopes,
        monitoring_enabled: record.monitoring_enabled,
        last_successful_sync_at: record.last_successful_sync_at,
        created_at: record.created_at,
        updated_at: record.updated_at
      }
    }), {
      status: 200,
      headers: { ...corsHeaders, "Content-Type": "application/json" }
    });
  } catch (err) {
    console.error("[complete-email-oauth] Error:", err);
    if (isGetCallback) {
      const msg = err instanceof Error ? err.message : "OAuth completion failed";
      return Response.redirect(`${DASHBOARD_ORIGIN}/?error=${encodeURIComponent(msg)}`, 302);
    }
    return new Response(JSON.stringify({ error: err instanceof Error ? err.message : "OAuth completion failed" }), {
      status: 500,
      headers: { ...corsHeaders, "Content-Type": "application/json" }
    });
  }
});
