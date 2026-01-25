-- OAuth refresh tokens for silent token renewal (RFC 6749 §6)
-- Uses SHA256 hash for storage (not bcrypt - needs lookup by hash)
-- Token rotation: each refresh consumes old token and issues new one (RFC 9700)

CREATE TABLE IF NOT EXISTS oauth_refresh_tokens (
    id SERIAL PRIMARY KEY,
    token_hash VARCHAR(64) NOT NULL,  -- SHA256 hash (hex encoded)
    authorization_id INTEGER NOT NULL REFERENCES oauth_authorizations(id) ON DELETE CASCADE,
    tenant_id BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,  -- 30 days from creation
    consumed_at TIMESTAMPTZ,          -- NULL = valid, set = one-time use consumed

    CONSTRAINT uq_refresh_token_hash UNIQUE (token_hash)
);

-- Index for token lookup (only unconsumed tokens)
CREATE INDEX IF NOT EXISTS idx_refresh_token_hash ON oauth_refresh_tokens(token_hash)
    WHERE consumed_at IS NULL;

-- Index for finding all tokens for an authorization (for revocation cascade)
CREATE INDEX IF NOT EXISTS idx_refresh_token_auth_id ON oauth_refresh_tokens(authorization_id);

-- Index for cleanup of expired/consumed tokens
CREATE INDEX IF NOT EXISTS idx_refresh_token_expires ON oauth_refresh_tokens(expires_at)
    WHERE consumed_at IS NULL;
