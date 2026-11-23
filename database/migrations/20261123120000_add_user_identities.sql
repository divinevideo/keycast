-- Sign-in providers (Google, Apple) linked to a Keycast account.
--
-- A provider only proves who is signing in. The account, its email and its Nostr key stay in
-- `users` and `personal_keys`; a row here says "this provider subject signs in as that account".
-- `subject` is the provider's stable user id (`sub`), never the email, because provider emails
-- can change while the subject cannot.
CREATE TABLE user_identities (
    id BIGSERIAL PRIMARY KEY,
    tenant_id BIGINT NOT NULL REFERENCES tenants (id),
    user_pubkey CHAR(64) NOT NULL,
    provider TEXT NOT NULL,
    subject TEXT NOT NULL,
    -- Last email the provider reported for this subject, lowercased. Informational only: account
    -- resolution uses `subject`, and the account's own address stays in `users.email`.
    email TEXT,
    -- Apple refresh token encrypted with the configured key manager. Kept so the grant can be
    -- revoked when the account is deleted.
    apple_refresh_token_encrypted BYTEA,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT user_identities_provider_check CHECK (provider IN ('google', 'apple')),
    CONSTRAINT user_identities_apple_token_check
        CHECK (provider = 'apple' OR apple_refresh_token_encrypted IS NULL),
    CONSTRAINT user_identities_provider_subject_unique UNIQUE (tenant_id, provider, subject),
    -- Deleting the account removes its sign-in providers with it.
    CONSTRAINT user_identities_user_fkey FOREIGN KEY (user_pubkey, tenant_id)
        REFERENCES users (pubkey, tenant_id) ON DELETE CASCADE
);

CREATE INDEX idx_user_identities_user ON user_identities (user_pubkey, tenant_id);

-- Support may see which providers an account uses, never the stored token.
GRANT SELECT (id, tenant_id, user_pubkey, provider, subject, email, created_at, last_login_at)
    ON public.user_identities TO support_reader;
