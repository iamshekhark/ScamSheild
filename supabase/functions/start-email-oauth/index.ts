// Supabase Edge Function: start-email-oauth
// Initiates secure OAuth 2.0 PKCE Authorization Code flow for Gmail or Microsoft Outlook
// Strictly requests minimum read-only permissions and enforces server-side user-bound state persistence

import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { corsHeaders, handleCors } from "../_shared/cors.ts";
import { getAuthenticatedUser } from "../_shared/authHelper.ts";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL") || "";
const SUPABASE_SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || "";

const GOOGLE_CLIENT_ID = Deno.env.get("GOOGLE_CLIENT_ID") || "";
const MICROSOFT_CLIENT_ID = Deno.env.get("MICROSOFT_CLIENT_ID") || Deno.env.get("AZURE_CLIENT_ID") || "";
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

  try {
    const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);

    // 1. Authenticate user: Only authenticated users can initiate an OAuth handshake
    const authUser = await getAuthenticatedUser(req, supabase);
    if (!authUser?.id) {
      return new Response(JSON.stringify({ error: "Unauthorized: Active user session required to connect email account" }), {
        status: 401,
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    const { provider, redirectUri } = await req.json();

    if (!provider || !["gmail", "outlook"].includes(provider)) {
      return new Response(JSON.stringify({ error: "Unsupported provider. Must be 'gmail' or 'outlook'" }), {
        status: 400,
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    const callbackRedirect = redirectUri || `${DASHBOARD_ORIGIN}/`;

    // 2. Validate redirect URI origin against allowed list
    try {
      const parsedRedirect = new URL(callbackRedirect);
      const isAllowed = ALLOWED_REDIRECT_ORIGINS.some((allowed) => {
        try {
          if (allowed.startsWith("chrome-extension://")) {
            return callbackRedirect.startsWith(allowed);
          }
          return new URL(allowed).origin === parsedRedirect.origin;
        } catch {
          return false;
        }
      });

      if (!isAllowed) {
        return new Response(JSON.stringify({ error: "Invalid redirect URI: Origin is not in the allowlist" }), {
          status: 400,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
    } catch {
      return new Response(JSON.stringify({ error: "Malformed redirectUri parameter" }), {
        status: 400,
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    // 3. Check provider client credentials
    const clientId = provider === "gmail" ? GOOGLE_CLIENT_ID : MICROSOFT_CLIENT_ID;
    if (!clientId) {
      const missingKeys = provider === "gmail"
        ? "GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET"
        : "MICROSOFT_CLIENT_ID (or AZURE_CLIENT_ID) and MICROSOFT_CLIENT_SECRET";

      return new Response(JSON.stringify({
        configured: false,
        error: `OAuth credentials for ${provider.toUpperCase()} are not yet configured on the server. Please configure ${missingKeys} in Supabase project secrets or environment.`
      }), {
        status: 503,
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    // 4. Generate high-entropy cryptographic state token (bound to provider and user session)
    const stateEntropy = Array.from(crypto.getRandomValues(new Uint8Array(24)))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
    const state = `${provider}:${Date.now()}:${stateEntropy}`;

    // 5. PKCE code verifier and challenge (RFC 7636)
    // 32 cryptographic random bytes -> Base64URL-safe string
    const verifierBytes = new Uint8Array(32);
    crypto.getRandomValues(verifierBytes);
    const codeVerifier = Array.from(verifierBytes)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");

    const verifierHash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(codeVerifier));
    const codeChallenge = btoa(String.fromCharCode(...new Uint8Array(verifierHash)))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");

    // 6. Record transaction in oauth_pending_transactions table
    // Bound to authUser.id with 10-minute validity and single-use consumption guarantee
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000).toISOString();
    const { error: txErr } = await supabase.from("oauth_pending_transactions").insert({
      user_id: authUser.id,
      provider,
      state,
      code_challenge: codeChallenge,
      code_verifier: codeVerifier,
      redirect_uri: callbackRedirect,
      expires_at: expiresAt
    });

    if (txErr) {
      console.error("[start-email-oauth] Failed to record pending transaction:", txErr);
      return new Response(JSON.stringify({ error: "Failed to initialize secure OAuth transaction record" }), {
        status: 500,
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    // 7. Construct Provider Authorization URLs with minimum read-only scopes
    let authUrl = "";

    if (provider === "gmail") {
      // Minimum read-only Gmail scope + userinfo to identify mailbox
      const scopes = [
        "https://www.googleapis.com/auth/gmail.readonly",
        "https://www.googleapis.com/auth/userinfo.email",
        "openid"
      ].join(" ");

      const params = new URLSearchParams({
        client_id: clientId,
        redirect_uri: callbackRedirect,
        response_type: "code",
        scope: scopes,
        access_type: "offline",
        prompt: "consent",
        state,
        code_challenge: codeChallenge,
        code_challenge_method: "S256",
        include_granted_scopes: "true"
      });
      authUrl = `https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`;
    } else {
      // Minimum read-only Outlook Graph scope + user profile
      const scopes = [
        "https://graph.microsoft.com/Mail.Read",
        "offline_access",
        "User.Read",
        "openid",
        "email"
      ].join(" ");

      const params = new URLSearchParams({
        client_id: clientId,
        redirect_uri: callbackRedirect,
        response_type: "code",
        scope: scopes,
        response_mode: "query",
        state,
        code_challenge: codeChallenge,
        code_challenge_method: "S256",
        prompt: "consent"
      });
      authUrl = `https://login.microsoftonline.com/${MICROSOFT_TENANT_ID}/oauth2/v2.0/authorize?${params.toString()}`;
    }

    return new Response(JSON.stringify({
      configured: true,
      authUrl,
      provider,
      state,
      scopesExplanation: provider === "gmail"
        ? "ScamShield requests 'gmail.readonly' to inspect email headers, text, and links for phishing with zero write or delete privileges."
        : "ScamShield requests 'Mail.Read' to inspect incoming Outlook messages for scam patterns with zero write privileges."
    }), {
      status: 200,
      headers: { ...corsHeaders, "Content-Type": "application/json" }
    });
  } catch (err) {
    return new Response(JSON.stringify({ error: err instanceof Error ? err.message : "Failed to generate OAuth URL" }), {
      status: 500,
      headers: { ...corsHeaders, "Content-Type": "application/json" }
    });
  }
});
