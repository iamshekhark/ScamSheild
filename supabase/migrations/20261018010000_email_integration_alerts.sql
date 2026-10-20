-- SCAMSHIELD DATABASE MIGRATION: EMAIL INTEGRATION, OTP VERIFICATION & ALERTS
-- Adds connected_email_accounts, email_scan_results, email_verification_challenges,
-- notification_preferences, and notification_delivery_log

-- ============================================================================
-- 1. CONNECTED EMAIL ACCOUNTS (Gmail & Outlook OAuth)
-- ============================================================================
CREATE TABLE IF NOT EXISTS public.connected_email_accounts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    provider TEXT NOT NULL CHECK (provider IN ('gmail', 'outlook')),
    provider_account_id TEXT NOT NULL,
    email_address TEXT NOT NULL,
    connection_status TEXT NOT NULL DEFAULT 'connected' CHECK (connection_status IN ('connected', 'expired', 'revoked', 'error')),
    granted_scopes TEXT[] NOT NULL DEFAULT '{}',
    encrypted_refresh_token TEXT,
    access_token_expiry TIMESTAMPTZ,
    monitoring_enabled BOOLEAN NOT NULL DEFAULT false,
    last_successful_sync_at TIMESTAMPTZ,
    last_error_code TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc', now()),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc', now()),
    CONSTRAINT uq_user_provider_account UNIQUE(user_id, provider, provider_account_id)
);

CREATE INDEX IF NOT EXISTS idx_connected_email_user_id ON public.connected_email_accounts(user_id);
CREATE INDEX IF NOT EXISTS idx_connected_email_monitoring ON public.connected_email_accounts(monitoring_enabled) WHERE monitoring_enabled = true;

-- ============================================================================
-- 2. EMAIL SCAN RESULTS
-- ============================================================================
CREATE TABLE IF NOT EXISTS public.email_scan_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    connected_account_id UUID REFERENCES public.connected_email_accounts(id) ON DELETE SET NULL,
    provider_message_id TEXT NOT NULL,
    normalized_message_fingerprint TEXT NOT NULL,
    sender_address TEXT NOT NULL,
    subject_redacted TEXT NOT NULL,
    risk_score INTEGER NOT NULL CHECK (risk_score >= 0 AND risk_score <= 100),
    risk_level TEXT NOT NULL CHECK (risk_level IN ('low', 'medium', 'high', 'critical')),
    detection_method TEXT NOT NULL CHECK (detection_method IN ('rules', 'ai', 'hybrid')),
    indicators JSONB NOT NULL DEFAULT '[]'::jsonb,
    explanation TEXT,
    recommended_actions JSONB NOT NULL DEFAULT '[]'::jsonb,
    scanned_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc', now()),
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc', now()),
    CONSTRAINT uq_user_provider_message UNIQUE(user_id, provider_message_id)
);

CREATE INDEX IF NOT EXISTS idx_email_scan_user_id ON public.email_scan_results(user_id);
CREATE INDEX IF NOT EXISTS idx_email_scan_created_at ON public.email_scan_results(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_email_scan_risk_level ON public.email_scan_results(risk_level);

-- ============================================================================
-- 3. EMAIL VERIFICATION CHALLENGES (Hashed OTPs, Expiry, Rate Limits)
-- ============================================================================
CREATE TABLE IF NOT EXISTS public.email_verification_challenges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
    email_address TEXT NOT NULL,
    purpose TEXT NOT NULL CHECK (purpose IN ('registration', 'email_change', 'recipient_verification', 'sensitive_action')),
    code_hash TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 5,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc', now()),
    resend_after TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_verification_email ON public.email_verification_challenges(email_address, purpose);
CREATE INDEX IF NOT EXISTS idx_verification_expires ON public.email_verification_challenges(expires_at);

-- ============================================================================
-- 4. NOTIFICATION PREFERENCES TABLE
-- ============================================================================
CREATE TABLE IF NOT EXISTS public.notification_preferences (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE UNIQUE,
    recipient_email TEXT,
    recipient_verified BOOLEAN NOT NULL DEFAULT false,
    suspicious_email_alerts BOOLEAN NOT NULL DEFAULT true,
    critical_risk_alerts BOOLEAN NOT NULL DEFAULT true,
    account_security_alerts BOOLEAN NOT NULL DEFAULT true,
    connection_status_alerts BOOLEAN NOT NULL DEFAULT true,
    weekly_summary BOOLEAN NOT NULL DEFAULT true,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc', now())
);

CREATE INDEX IF NOT EXISTS idx_notif_prefs_user ON public.notification_preferences(user_id);

-- ============================================================================
-- 5. NOTIFICATION DELIVERY LOG (Deduplication & Delivery Tracking)
-- ============================================================================
CREATE TABLE IF NOT EXISTS public.notification_delivery_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    notification_type TEXT NOT NULL,
    deduplication_key TEXT NOT NULL,
    provider_message_id TEXT,
    delivery_status TEXT NOT NULL DEFAULT 'pending' CHECK (delivery_status IN ('pending', 'delivered', 'failed', 'suppressed')),
    attempt_count INTEGER NOT NULL DEFAULT 0,
    last_error_code TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc', now()),
    sent_at TIMESTAMPTZ,
    CONSTRAINT uq_user_dedup UNIQUE(user_id, deduplication_key)
);

CREATE INDEX IF NOT EXISTS idx_notif_log_user_id ON public.notification_delivery_log(user_id);
CREATE INDEX IF NOT EXISTS idx_notif_log_created_at ON public.notification_delivery_log(created_at DESC);

-- ============================================================================
-- 6. ROW LEVEL SECURITY (RLS) POLICIES
-- ============================================================================
ALTER TABLE public.connected_email_accounts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.email_scan_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.email_verification_challenges ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.notification_preferences ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.notification_delivery_log ENABLE ROW LEVEL SECURITY;

-- connected_email_accounts: Users can read and manage only their own accounts
CREATE POLICY "Users can manage own connected accounts"
    ON public.connected_email_accounts FOR ALL
    TO authenticated
    USING (auth.uid() = user_id)
    WITH CHECK (auth.uid() = user_id);

-- email_scan_results: Users can view their own scan records
CREATE POLICY "Users can manage own email scans"
    ON public.email_scan_results FOR ALL
    TO authenticated
    USING (auth.uid() = user_id)
    WITH CHECK (auth.uid() = user_id);

-- notification_preferences: Users can view and update their own preferences
CREATE POLICY "Users can manage own notification preferences"
    ON public.notification_preferences FOR ALL
    TO authenticated
    USING (auth.uid() = user_id)
    WITH CHECK (auth.uid() = user_id);

-- notification_delivery_log: Users can view their notification delivery log
CREATE POLICY "Users can view own notification delivery logs"
    ON public.notification_delivery_log FOR SELECT
    TO authenticated
    USING (auth.uid() = user_id);

-- email_verification_challenges: Strictly denied to direct client queries;
-- Only service_role can interact with challenge hashes directly.
CREATE POLICY "Deny direct public client access to verification hashes"
    ON public.email_verification_challenges FOR ALL
    TO authenticated
    USING (false);
