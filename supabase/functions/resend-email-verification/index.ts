// Supabase Edge Function: resend-email-verification
// Enforces 60-second cooldown, invalidates older challenges, and dispatches a fresh code

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

    // Check cooldown
    const { data: recent } = await supabase
      .from("email_verification_challenges")
      .select("resend_after")
      .eq("email_address", cleanEmail)
      .eq("purpose", purpose)
      .is("consumed_at", null)
      .gt("resend_after", now.toISOString())
      .order("created_at", { ascending: false })
      .limit(1)
      .maybeSingle();

    if (recent) {
      const wait = Math.max(1, Math.ceil((new Date(recent.resend_after).getTime() - now.getTime()) / 1000));
      return new Response(JSON.stringify({
        error: `Please wait ${wait} seconds before resending verification code.`,
        retryAfter: wait
      }), {
        status: 429,
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    // Invalidate earlier active challenges
    await supabase
      .from("email_verification_challenges")
      .update({ consumed_at: now.toISOString() })
      .eq("email_address", cleanEmail)
      .eq("purpose", purpose)
      .is("consumed_at", null);

    // Generate new OTP & Salt
    const code = generateSecureOtp();
    const salt = generateSalt();
    const codeHash = `${salt}:${await hashOtp(code, salt)}`;

    const expiresAt = new Date(now.getTime() + OTP_EXPIRY_MS);
    const resendAfter = new Date(now.getTime() + OTP_COOLDOWN_MS);

    await supabase
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

    // Send email
    const template = EmailTemplates.verificationCode(code, purpose, 5);
    await sendTransactionalEmail({
      userId: userId || "guest_verify",
      to: cleanEmail,
      subject: template.subject,
      html: template.html,
      notificationType: "verification_code_resend",
      deduplicationKey: `resend_${cleanEmail}_${now.getTime()}`
    });

    return new Response(JSON.stringify({
      success: true,
      message: "A fresh verification code has been dispatched.",
      resendAfterSeconds: 60
    }), {
      status: 200,
      headers: { ...corsHeaders, "Content-Type": "application/json" }
    });
  } catch (err) {
    return new Response(JSON.stringify({ error: err instanceof Error ? err.message : "Failed to resend code" }), {
      status: 500,
      headers: { ...corsHeaders, "Content-Type": "application/json" }
    });
  }
});
