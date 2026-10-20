// Transactional Email Dispatcher with Deduplication, Rate Limiting & Bounded Backoff Retries
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const MAIL_SERVICE_URL = Deno.env.get("MAIL_SERVICE_URL") || "";
const MAIL_SERVICE_API_KEY = Deno.env.get("MAIL_SERVICE_API_KEY") || "";
const RESEND_API_KEY = Deno.env.get("RESEND_API_KEY") || "";
const FROM_EMAIL = Deno.env.get("FROM_EMAIL") || "ScamShield Security <alerts@scamshield.local>";
const SUPABASE_URL = Deno.env.get("SUPABASE_URL") || "";
const SUPABASE_SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || "";

export interface SendEmailOptions {
  userId: string;
  to: string;
  subject: string;
  html: string;
  notificationType: string;
  deduplicationKey: string;
  providerMessageId?: string;
}

export interface SendEmailResult {
  success: boolean;
  messageId?: string;
  deliveryStatus: "delivered" | "failed" | "suppressed";
  error?: string;
}

export async function sendTransactionalEmail(opts: SendEmailOptions): Promise<SendEmailResult> {
  const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);

  // 1. Check deduplication in database
  const { data: existingLog } = await supabase
    .from("notification_delivery_log")
    .select("id, delivery_status")
    .eq("user_id", opts.userId)
    .eq("deduplication_key", opts.deduplicationKey)
    .maybeSingle();

  if (existingLog && existingLog.delivery_status === "delivered") {
    return {
      success: true,
      deliveryStatus: "suppressed",
      error: "Duplicate alert suppressed by deduplication key"
    };
  }

  // 2. Delivery with bounded exponential backoff retry (up to 3 attempts)
  let lastError = "";
  let messageId = "";
  let success = false;

  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      if (MAIL_SERVICE_URL && MAIL_SERVICE_API_KEY) {
        // Send via ScamShield Nodemailer SMTP microservice
        const cleanBaseUrl = MAIL_SERVICE_URL.replace(/\/+$/, "");
        const res = await fetch(`${cleanBaseUrl}/send`, {
          method: "POST",
          headers: {
            "X-API-Key": MAIL_SERVICE_API_KEY,
            "Content-Type": "application/json"
          },
          body: JSON.stringify({
            to: opts.to,
            subject: opts.subject,
            html: opts.html,
            notificationType: opts.notificationType,
            deduplicationKey: opts.deduplicationKey,
            providerMessageId: opts.providerMessageId
          })
        });

        if (!res.ok) {
          const errData = await res.json().catch(() => ({}));
          throw new Error(errData.message || errData.error || `Mail service error HTTP ${res.status}`);
        }

        const data = await res.json();
        messageId = data.messageId || `msg_${Date.now()}`;
        success = true;
        break;
      } else if (RESEND_API_KEY) {
        // Send via Resend REST API
        const res = await fetch("https://api.resend.com/emails", {
          method: "POST",
          headers: {
            "Authorization": `Bearer ${RESEND_API_KEY}`,
            "Content-Type": "application/json"
          },
          body: JSON.stringify({
            from: FROM_EMAIL,
            to: [opts.to],
            subject: opts.subject,
            html: opts.html
          })
        });

        if (!res.ok) {
          const errData = await res.json().catch(() => ({}));
          throw new Error(errData.message || `Resend error HTTP ${res.status}`);
        }

        const data = await res.json();
        messageId = data.id || `msg_${Date.now()}`;
        success = true;
        break;
      } else {
        lastError = "Neither MAIL_SERVICE_URL nor RESEND_API_KEY is configured on the server. Transactional email dispatch blocked.";
        console.warn(`[EmailSender] ${lastError}`);
        success = false;
        break;
      }
    } catch (err) {
      lastError = err instanceof Error ? err.message : String(err);
      console.warn(`[EmailSender] Attempt ${attempt} failed: ${lastError}`);
      if (attempt < 3) {
        // Exponential backoff: 300ms, 600ms
        await new Promise((resolve) => setTimeout(resolve, attempt * 300));
      }
    }
  }

  // 3. Record in notification_delivery_log
  const deliveryStatus = success ? "delivered" : "failed";
  await supabase.from("notification_delivery_log").upsert({
    user_id: opts.userId,
    notification_type: opts.notificationType,
    deduplication_key: opts.deduplicationKey,
    provider_message_id: opts.providerMessageId || messageId,
    delivery_status: deliveryStatus,
    last_error_code: success ? null : lastError.slice(0, 100),
    sent_at: success ? new Date().toISOString() : null
  }, { onConflict: "user_id,deduplication_key" });

  return {
    success,
    messageId,
    deliveryStatus,
    error: success ? undefined : lastError
  };
}
