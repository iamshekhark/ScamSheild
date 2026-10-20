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
