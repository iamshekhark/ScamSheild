// Supabase Edge Function: request-email-verification
// Issues cryptographically secure, salted 6-digit OTP with 5-minute expiry and 60s cooldown

import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { corsHeaders, handleCors } from "../_shared/cors.ts";
import { generateSecureOtp, generateSalt, hashOtp, OTP_EXPIRY_MS, OTP_COOLDOWN_MS } from "../_shared/otpService.ts";
import { EmailTemplates } from "../_shared/emailTemplates.ts";
import { sendTransactionalEmail } from "../_shared/emailSender.ts";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL") || "";
const SUPABASE_SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || "";

serve(async (req) => {
  const corsRes = handleCors(req);
  if (corsRes) return corsRes;

  try {
    const { email, purpose = "registration", userId } = await req.json();
    const cleanEmail = (email || "").toLowerCase().trim();

    if (!cleanEmail || !cleanEmail.includes("@")) {
      return new Response(JSON.stringify({ error: "A valid email address is required" }), {
        status: 400,
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);
    const now = new Date();

    // 1. Check for active cooldown (prevent spamming requests)
    const { data: recentChallenge } = await supabase
      .from("email_verification_challenges")
      .select("id, resend_after, created_at")
      .eq("email_address", cleanEmail)
      .eq("purpose", purpose)
      .is("consumed_at", null)
      .gt("resend_after", now.toISOString())
      .order("created_at", { ascending: false })
      .limit(1)
      .maybeSingle();

    if (recentChallenge) {
      const waitSeconds = Math.max(1, Math.ceil((new Date(recentChallenge.resend_after).getTime() - now.getTime()) / 1000));
      return new Response(JSON.stringify({
        error: `Please wait ${waitSeconds} seconds before requesting a new verification code.`,
        retryAfter: waitSeconds
      }), {
        status: 429,
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    // 2. Invalidate previous unconsumed challenges for this email and purpose
    await supabase
      .from("email_verification_challenges")
      .update({ consumed_at: now.toISOString() })
      .eq("email_address", cleanEmail)
      .eq("purpose", purpose)
      .is("consumed_at", null);

    // 3. Generate cryptographically secure OTP & Salt
    const code = generateSecureOtp();
    const salt = generateSalt();
    const codeHash = `${salt}:${await hashOtp(code, salt)}`;

    const expiresAt = new Date(now.getTime() + OTP_EXPIRY_MS);
    const resendAfter = new Date(now.getTime() + OTP_COOLDOWN_MS);

    // 4. Store challenge in database
    const { error: insertErr } = await supabase
      .from("email_verification_challenges")
      .insert({
        user_id: userId || null,
        email_address: cleanEmail,
        purpose,
        code_hash: codeHash,
        expires_at: expiresAt.toISOString(),
        resend_after: resendAfter.toISOString(),
        attempt_count: 0,
        max_attempts: 5
      });

    if (insertErr) throw insertErr;

    // 5. Render email template & dispatch via transactional sender
    const template = EmailTemplates.verificationCode(code, purpose, 5);
    const sendResult = await sendTransactionalEmail({
      userId: userId || "guest_verify",
      to: cleanEmail,
      subject: template.subject,
      html: template.html,
      notificationType: "verification_code",
      deduplicationKey: `verify_${cleanEmail}_${now.getTime()}`
    });

    if (!sendResult.success) {
      // Invalidate the newly created challenge so it cannot be claimed if dispatch failed
      await supabase
        .from("email_verification_challenges")
        .update({ consumed_at: now.toISOString() })
        .eq("email_address", cleanEmail)
        .eq("purpose", purpose)
        .is("consumed_at", null);

      return new Response(JSON.stringify({
        error: "Unable to dispatch verification email. Please verify mail configuration or try again shortly.",
        code: "EMAIL_DISPATCH_FAILED"
      }), {
        status: 502,
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    // 6. Generic response: never leak plaintext OTP or reveal user status
    return new Response(JSON.stringify({
      success: true,
      message: "A verification code has been dispatched to your email address.",
      resendAfterSeconds: 60,
      expiresInMinutes: 5
    }), {
      status: 200,
      headers: { ...corsHeaders, "Content-Type": "application/json" }
    });
  } catch (err) {
    return new Response(JSON.stringify({ error: err instanceof Error ? err.message : "Verification request failed" }), {
      status: 500,
      headers: { ...corsHeaders, "Content-Type": "application/json" }
    });
  }
});
