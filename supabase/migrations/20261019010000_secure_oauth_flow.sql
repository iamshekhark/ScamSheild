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
