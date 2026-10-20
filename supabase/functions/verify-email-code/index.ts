// Supabase Edge Function: verify-email-code
// Validates 6-digit OTP code against salted hash, checks expiry and attempt limit

import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { corsHeaders, handleCors } from "../_shared/cors.ts";
import { verifyOtpHash, OTP_MAX_ATTEMPTS } from "../_shared/otpService.ts";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL") || "";
const SUPABASE_SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || "";

serve(async (req) => {
  const corsRes = handleCors(req);
  if (corsRes) return corsRes;

  try {
    const { email, code, purpose = "registration", userId } = await req.json();
    const cleanEmail = (email || "").toLowerCase().trim();
    const cleanCode = (code || "").trim();

    if (!cleanEmail || !cleanCode || cleanCode.length !== 6) {
      return new Response(JSON.stringify({ error: "Please enter a valid 6-digit verification code" }), {
        status: 400,
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);
    const now = new Date();

    // 1. Fetch the latest active challenge for this email and purpose
    const { data: challenge } = await supabase
      .from("email_verification_challenges")
      .select("*")
      .eq("email_address", cleanEmail)
      .eq("purpose", purpose)
      .is("consumed_at", null)
      .gt("expires_at", now.toISOString())
      .order("created_at", { ascending: false })
      .limit(1)
      .maybeSingle();

    if (!challenge) {
      return new Response(JSON.stringify({
        error: "Verification code has expired or was not found. Please request a new code."
      }), {
        status: 400,
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    // 2. Check maximum attempts limit
    if (challenge.attempt_count >= OTP_MAX_ATTEMPTS) {
      await supabase
        .from("email_verification_challenges")
        .update({ consumed_at: now.toISOString() })
        .eq("id", challenge.id);

      return new Response(JSON.stringify({
        error: "Maximum verification attempts exceeded. This code has been invalidated for security."
      }), {
        status: 429,
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    // 3. Increment attempt counter
    const newAttemptCount = challenge.attempt_count + 1;
    await supabase
      .from("email_verification_challenges")
      .update({ attempt_count: newAttemptCount })
      .eq("id", challenge.id);

    // 4. Verify code against salted hash
    const [salt, expectedHash] = challenge.code_hash.split(":");
    const isMatch = await verifyOtpHash(cleanCode, salt, expectedHash);

    if (!isMatch) {
      const remaining = Math.max(0, OTP_MAX_ATTEMPTS - newAttemptCount);
      return new Response(JSON.stringify({
        error: `Incorrect verification code. ${remaining} attempts remaining.`,
        remainingAttempts: remaining
      }), {
        status: 400,
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    // 5. Code is valid: Mark as consumed (atomic single-use semantics to prevent concurrent replay)
    const { data: consumedChallenge, error: consumeErr } = await supabase
      .from("email_verification_challenges")
      .update({ consumed_at: now.toISOString() })
      .eq("id", challenge.id)
      .is("consumed_at", null)
      .select("id")
      .maybeSingle();

    if (consumeErr || !consumedChallenge) {
      return new Response(JSON.stringify({
        error: "Verification code has already been used or is no longer valid."
      }), {
        status: 400,
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    // 6. Fulfill verification purpose
    if (purpose === "recipient_verification" && userId) {
      await supabase
        .from("notification_preferences")
        .upsert({
          user_id: userId,
          recipient_email: cleanEmail,
          recipient_verified: true,
          updated_at: now.toISOString()
        }, { onConflict: "user_id" });
    }

    return new Response(JSON.stringify({
      success: true,
      verified: true,
      email: cleanEmail,
      purpose,
      message: "Email address successfully verified."
    }), {
      status: 200,
      headers: { ...corsHeaders, "Content-Type": "application/json" }
    });
  } catch (err) {
    return new Response(JSON.stringify({ error: err instanceof Error ? err.message : "Verification failed" }), {
      status: 500,
      headers: { ...corsHeaders, "Content-Type": "application/json" }
    });
  }
});
