-- SCAMSHIELD FULL-STACK DATABASE SCHEMA (PostgreSQL / Supabase)
-- Initial migration: Profiles, Scan History, Indicators, Feedback, Preferences, Threat Intel, AI Insights

-- Enable UUID extension if not already available
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ============================================================================
-- 1. PROFILES TABLE
-- ============================================================================
CREATE TABLE IF NOT EXISTS public.profiles (
    id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    display_name TEXT,
    preferred_theme TEXT DEFAULT 'system' CHECK (preferred_theme IN ('light', 'dark', 'system')),
    notification_preferences JSONB DEFAULT '{"email_alerts": true, "browser_notifications": true, "weekly_digest": false}'::jsonb,
    account_status TEXT DEFAULT 'active' CHECK (account_status IN ('active', 'suspended', 'pending_deletion')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc', now()),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc', now())
);

-- ============================================================================
-- 2. USER PREFERENCES TABLE
-- ============================================================================
CREATE TABLE IF NOT EXISTS public.user_preferences (
    user_id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    save_scan_history BOOLEAN NOT NULL DEFAULT true,
    allow_ai_analysis BOOLEAN NOT NULL DEFAULT true,
    allow_anonymous_telemetry BOOLEAN NOT NULL DEFAULT false,
    notification_settings JSONB NOT NULL DEFAULT '{"high_risk_alert": true, "monthly_report": true}'::jsonb,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc', now())
);

-- ============================================================================
-- 3. SCAN HISTORY TABLE
-- ============================================================================
CREATE TABLE IF NOT EXISTS public.scan_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES auth.users(id) ON DELETE SET NULL,
    scan_type TEXT NOT NULL CHECK (scan_type IN ('url', 'text', 'email', 'message', 'screenshot')),
    submitted_content TEXT NOT NULL,
    normalized_domain TEXT,
    risk_score INTEGER NOT NULL CHECK (risk_score >= 0 AND risk_score <= 100),
    risk_level TEXT NOT NULL CHECK (risk_level IN ('low', 'medium', 'high', 'critical')),
    detection_method TEXT NOT NULL CHECK (detection_method IN ('rules', 'ai', 'hybrid')),
    explanation TEXT,
    indicators JSONB NOT NULL DEFAULT '[]'::jsonb,
    recommended_actions JSONB NOT NULL DEFAULT '[]'::jsonb,
    model_version TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc', now())
);

-- Indexes for performant user queries and metrics
CREATE INDEX IF NOT EXISTS idx_scan_history_user_id ON public.scan_history(user_id);
CREATE INDEX IF NOT EXISTS idx_scan_history_created_at ON public.scan_history(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scan_history_risk_level ON public.scan_history(risk_level);
CREATE INDEX IF NOT EXISTS idx_scan_history_domain ON public.scan_history(normalized_domain);

-- ============================================================================
-- 4. SCAM INDICATORS TABLE
-- ============================================================================
CREATE TABLE IF NOT EXISTS public.scam_indicators (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL REFERENCES public.scan_history(id) ON DELETE CASCADE,
    indicator_type TEXT NOT NULL,
    description TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    evidence JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc', now())
);

CREATE INDEX IF NOT EXISTS idx_scam_indicators_scan_id ON public.scam_indicators(scan_id);
CREATE INDEX IF NOT EXISTS idx_scam_indicators_type ON public.scam_indicators(indicator_type);

-- ============================================================================
-- 5. USER FEEDBACK TABLE
-- ============================================================================
CREATE TABLE IF NOT EXISTS public.user_feedback (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    scan_id UUID NOT NULL REFERENCES public.scan_history(id) ON DELETE CASCADE,
    feedback_type TEXT NOT NULL CHECK (feedback_type IN ('correct', 'false_positive', 'false_negative')),
    comment TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc', now()),
    CONSTRAINT unique_user_scan_feedback UNIQUE(user_id, scan_id)
);

CREATE INDEX IF NOT EXISTS idx_user_feedback_user ON public.user_feedback(user_id);

-- ============================================================================
-- 6. THREAT INTELLIGENCE TABLE (Managed via backend processes)
-- ============================================================================
CREATE TABLE IF NOT EXISTS public.threat_intelligence (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    indicator_type TEXT NOT NULL CHECK (indicator_type IN ('domain', 'ip', 'url_keyword', 'sender', 'hash')),
    indicator_value TEXT NOT NULL UNIQUE,
    source TEXT NOT NULL,
    confidence_score INTEGER NOT NULL CHECK (confidence_score >= 0 AND confidence_score <= 100),
    first_seen TIMESTAMPTZ NOT NULL DEFAULT timezone('utc', now()),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT timezone('utc', now()),
    expires_at TIMESTAMPTZ,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_threat_intel_val ON public.threat_intelligence(indicator_value);
CREATE INDEX IF NOT EXISTS idx_threat_intel_type ON public.threat_intelligence(indicator_type);

-- Seed initial known malicious indicator examples
INSERT INTO public.threat_intelligence (indicator_type, indicator_value, source, confidence_score, metadata)
VALUES
    ('domain', 'paytrn-security.xyz', 'ScamShield Threat Intel', 95, '{"threat": "Paytm Brand Phishing"}'::jsonb),
    ('domain', 'amaz0n-security.com', 'ScamShield Threat Intel', 98, '{"threat": "Amazon Credential Harvesting"}'::jsonb),
    ('ip', '192.168.1.50', 'Internal Test Intel', 90, '{"threat": "Raw IP Phishing Endpoint"}'::jsonb)
ON CONFLICT (indicator_value) DO NOTHING;

-- ============================================================================
-- 7. AI INSIGHTS TABLE
-- ============================================================================
CREATE TABLE IF NOT EXISTS public.ai_insights (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    insight_type TEXT NOT NULL CHECK (insight_type IN ('weekly_summary', 'category_trend', 'targeted_warning', 'recommendation')),
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    supporting_metrics JSONB NOT NULL DEFAULT '{}'::jsonb,
    recommendations JSONB NOT NULL DEFAULT '[]'::jsonb,
    period_start TIMESTAMPTZ,
    period_end TIMESTAMPTZ,
    generated_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc', now())
);

CREATE INDEX IF NOT EXISTS idx_ai_insights_user ON public.ai_insights(user_id);
CREATE INDEX IF NOT EXISTS idx_ai_insights_generated ON public.ai_insights(generated_at DESC);

-- ============================================================================
-- 8. AUTOMATIC PROFILE AND PREFERENCES PROVISIONING TRIGGER
-- ============================================================================
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO public.profiles (id, display_name)
    VALUES (NEW.id, COALESCE(NEW.raw_user_meta_data->>'full_name', split_part(NEW.email, '@', 1)))
    ON CONFLICT (id) DO NOTHING;

    INSERT INTO public.user_preferences (user_id)
    VALUES (NEW.id)
    ON CONFLICT (user_id) DO NOTHING;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Trigger execution after auth.users signup
DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
    AFTER INSERT ON auth.users
    FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

-- ============================================================================
-- 9. ROW LEVEL SECURITY (RLS) POLICIES
-- ============================================================================
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.user_preferences ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scan_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scam_indicators ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.user_feedback ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.threat_intelligence ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.ai_insights ENABLE ROW LEVEL SECURITY;

-- Profiles: Users can only read and update their own profile
CREATE POLICY "Users can read own profile"
    ON public.profiles FOR SELECT
    USING (auth.uid() = id);

CREATE POLICY "Users can update own profile"
    ON public.profiles FOR UPDATE
    USING (auth.uid() = id)
    WITH CHECK (auth.uid() = id);

-- User Preferences: Users can read and update their own preferences
CREATE POLICY "Users can read own preferences"
    ON public.user_preferences FOR SELECT
    USING (auth.uid() = user_id);

CREATE POLICY "Users can update own preferences"
    ON public.user_preferences FOR UPDATE
    USING (auth.uid() = user_id)
    WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can insert own preferences"
    ON public.user_preferences FOR INSERT
    WITH CHECK (auth.uid() = user_id);

-- Scan History: Users can view, insert, and delete only their own scans
CREATE POLICY "Users can read own scan history"
    ON public.scan_history FOR SELECT
    USING (auth.uid() = user_id);

CREATE POLICY "Users can insert own scans"
    ON public.scan_history FOR INSERT
    WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can delete own scan history"
    ON public.scan_history FOR DELETE
    USING (auth.uid() = user_id);

-- Scam Indicators: Access strictly tied to the authenticated parent scan_history ownership
CREATE POLICY "Users can read indicators of own scans"
    ON public.scam_indicators FOR SELECT
    USING (
        EXISTS (
            SELECT 1 FROM public.scan_history
            WHERE public.scan_history.id = public.scam_indicators.scan_id
            AND public.scan_history.user_id = auth.uid()
        )
    );

CREATE POLICY "Service and owners can insert indicators"
    ON public.scam_indicators FOR INSERT
    WITH CHECK (
        EXISTS (
            SELECT 1 FROM public.scan_history
            WHERE public.scan_history.id = public.scam_indicators.scan_id
            AND public.scan_history.user_id = auth.uid()
        )
    );

-- User Feedback: Users can manage only their own feedback
CREATE POLICY "Users can manage own feedback"
    ON public.user_feedback FOR ALL
    USING (auth.uid() = user_id)
    WITH CHECK (auth.uid() = user_id);

-- Threat Intelligence: Read-only for authenticated & anon clients, write restricted to service role
CREATE POLICY "Anyone can read threat intelligence"
    ON public.threat_intelligence FOR SELECT
    USING (true);

-- AI Insights: Users can read and delete their own insights
CREATE POLICY "Users can read own AI insights"
    ON public.ai_insights FOR SELECT
    USING (auth.uid() = user_id);

CREATE POLICY "Users can delete own AI insights"
    ON public.ai_insights FOR DELETE
    USING (auth.uid() = user_id);

CREATE POLICY "Service role can insert AI insights"
    ON public.ai_insights FOR INSERT
    WITH CHECK (auth.uid() = user_id OR auth.role() = 'service_role');

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

-- SCAMSHIELD DATABASE MIGRATION: PAYMENT SCAM VERIFICATION
-- Adds payment_scan_results, payment_evidence, and payment_provider_events with strict RLS

-- ============================================================================
-- 1. PAYMENT SCAN RESULTS
-- ============================================================================
CREATE TABLE IF NOT EXISTS public.payment_scan_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    input_type TEXT NOT NULL CHECK (input_type IN ('upi_id', 'payment_url', 'qr_code', 'message', 'screenshot', 'utr')),
    normalized_payee TEXT,
    payment_domain TEXT,
    risk_score INTEGER NOT NULL CHECK (risk_score >= 0 AND risk_score <= 100),
    risk_level TEXT NOT NULL CHECK (risk_level IN ('safe', 'low', 'medium', 'high', 'critical')),
    detection_method TEXT NOT NULL CHECK (detection_method IN ('rules', 'ai', 'hybrid')),
    indicators JSONB NOT NULL DEFAULT '[]'::jsonb,
    explanation TEXT,
    recommended_actions JSONB NOT NULL DEFAULT '[]'::jsonb,
    reputation_source TEXT,
    checked_at TIMESTAMPTZ,
    payment_status TEXT NOT NULL DEFAULT 'unverified' CHECK (payment_status IN ('unverified', 'pending', 'successful', 'failed', 'cancelled', 'refunded', 'unknown')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc', now())
);

CREATE INDEX IF NOT EXISTS idx_payment_scan_user_id ON public.payment_scan_results(user_id);
CREATE INDEX IF NOT EXISTS idx_payment_scan_created_at ON public.payment_scan_results(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_payment_scan_risk_level ON public.payment_scan_results(risk_level);
CREATE INDEX IF NOT EXISTS idx_payment_scan_input_type ON public.payment_scan_results(input_type);

-- ============================================================================
-- 2. PAYMENT EVIDENCE
-- ============================================================================
CREATE TABLE IF NOT EXISTS public.payment_evidence (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL REFERENCES public.payment_scan_results(id) ON DELETE CASCADE,
    evidence_type TEXT NOT NULL,
    description TEXT NOT NULL,
    source TEXT NOT NULL,
    confidence REAL NOT NULL DEFAULT 1.0,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc', now())
);

CREATE INDEX IF NOT EXISTS idx_payment_evidence_scan_id ON public.payment_evidence(scan_id);

-- ============================================================================
-- 3. PAYMENT PROVIDER EVENTS (Authoritative Merchant Webhooks If Configured)
-- ============================================================================
CREATE TABLE IF NOT EXISTS public.payment_provider_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    provider TEXT NOT NULL,
    provider_event_id TEXT NOT NULL,
    transaction_ref TEXT,
    verified_event_status TEXT NOT NULL,
    event_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    event_timestamp TIMESTAMPTZ NOT NULL,
    processed_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc', now()),
    CONSTRAINT uq_payment_event UNIQUE (provider, provider_event_id)
);

CREATE INDEX IF NOT EXISTS idx_provider_events_tx ON public.payment_provider_events(transaction_ref);

-- ============================================================================
-- 4. ROW LEVEL SECURITY (RLS) POLICIES
-- ============================================================================
ALTER TABLE public.payment_scan_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.payment_evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.payment_provider_events ENABLE ROW LEVEL SECURITY;

-- payment_scan_results: Users can view and delete only their own scan results
CREATE POLICY "Users can manage own payment scan results"
    ON public.payment_scan_results FOR ALL
    TO authenticated
    USING (auth.uid() = user_id)
    WITH CHECK (auth.uid() = user_id);

-- payment_evidence: Users can view evidence for their own scans
CREATE POLICY "Users can view evidence for own scans"
    ON public.payment_evidence FOR SELECT
    TO authenticated
    USING (
        EXISTS (
            SELECT 1 FROM public.payment_scan_results psr
            WHERE psr.id = payment_evidence.scan_id
            AND psr.user_id = auth.uid()
        )
    );

-- payment_provider_events: Public clients have zero read/write access.
-- Writes are performed exclusively by server-side webhook handlers with service_role.
CREATE POLICY "Deny client direct access to provider events"
    ON public.payment_provider_events FOR ALL
    TO authenticated
    USING (false);

-- ============================================================================
-- SCAMSHIELD DATABASE MIGRATION: SECURE OAUTH 2.0 FLOW & TOKEN ISOLATION
-- ============================================================================
-- 1. Creates public.oauth_pending_transactions for user-bound, single-use, expiring state.
-- 2. Creates public.connected_mailbox_tokens to isolate encrypted tokens from client queries.
-- 3. Enforces strict Row Level Security (RLS) denying all direct client access to tokens and state.
-- ============================================================================

-- 1. OAuth Pending Transactions Table
CREATE TABLE IF NOT EXISTS public.oauth_pending_transactions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    provider TEXT NOT NULL CHECK (provider IN ('gmail', 'outlook')),
    state TEXT NOT NULL UNIQUE,
    code_challenge TEXT NOT NULL,
    code_verifier TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc', now()),
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_oauth_pending_state ON public.oauth_pending_transactions(state);
CREATE INDEX IF NOT EXISTS idx_oauth_pending_user ON public.oauth_pending_transactions(user_id);
CREATE INDEX IF NOT EXISTS idx_oauth_pending_expires ON public.oauth_pending_transactions(expires_at);

-- 2. Connected Mailbox Tokens (Isolated token storage)
CREATE TABLE IF NOT EXISTS public.connected_mailbox_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id UUID NOT NULL REFERENCES public.connected_email_accounts(id) ON DELETE CASCADE UNIQUE,
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    encrypted_refresh_token TEXT NOT NULL,
    token_encryption_version TEXT NOT NULL DEFAULT 'v1',
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc', now()),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc', now())
);

CREATE INDEX IF NOT EXISTS idx_mailbox_tokens_account ON public.connected_mailbox_tokens(account_id);
CREATE INDEX IF NOT EXISTS idx_mailbox_tokens_user ON public.connected_mailbox_tokens(user_id);

-- 3. Data Migration: Move any existing tokens from connected_email_accounts to connected_mailbox_tokens
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_schema = 'public' 
          AND table_name = 'connected_email_accounts' 
          AND column_name = 'encrypted_refresh_token'
    ) THEN
        INSERT INTO public.connected_mailbox_tokens (account_id, user_id, encrypted_refresh_token, token_encryption_version)
        SELECT id, user_id, encrypted_refresh_token, 'v1'
        FROM public.connected_email_accounts
        WHERE encrypted_refresh_token IS NOT NULL AND encrypted_refresh_token != ''
        ON CONFLICT (account_id) DO UPDATE 
        SET encrypted_refresh_token = EXCLUDED.encrypted_refresh_token,
            updated_at = timezone('utc', now());

        -- Null out token in connected_email_accounts so client queries never expose tokens
        UPDATE public.connected_email_accounts SET encrypted_refresh_token = NULL;
    END IF;
END $$;

-- 4. Row Level Security Policies
ALTER TABLE public.oauth_pending_transactions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.connected_mailbox_tokens ENABLE ROW LEVEL SECURITY;

-- Deny all direct client access (both anonymous and authenticated).
-- Only backend functions with service_role can interact with pending transactions and tokens.
CREATE POLICY "Deny direct public client access to oauth transactions"
    ON public.oauth_pending_transactions FOR ALL
    TO authenticated
    USING (false);

CREATE POLICY "Deny direct public client access to mailbox tokens"
    ON public.connected_mailbox_tokens FOR ALL
    TO authenticated
    USING (false);

