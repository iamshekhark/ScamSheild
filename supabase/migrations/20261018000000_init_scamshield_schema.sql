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
