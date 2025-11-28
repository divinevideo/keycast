-- NIP-46 Client Pubkey Tracking
-- Tracks connected NIP-46 clients for security and revocation support
-- Per NIP-46 spec: secret is single-use, client_pubkey becomes the identifier after connect

-- Add connected client tracking columns to oauth_authorizations
ALTER TABLE oauth_authorizations
ADD COLUMN IF NOT EXISTS connected_client_pubkey TEXT;

ALTER TABLE oauth_authorizations
ADD COLUMN IF NOT EXISTS connected_at TIMESTAMPTZ;

-- Index for efficient client pubkey lookups
CREATE INDEX IF NOT EXISTS idx_oauth_auth_connected_client_pubkey
ON oauth_authorizations(connected_client_pubkey)
WHERE connected_client_pubkey IS NOT NULL;

-- Also add to regular authorizations for consistency
ALTER TABLE authorizations
ADD COLUMN IF NOT EXISTS connected_client_pubkey TEXT;

ALTER TABLE authorizations
ADD COLUMN IF NOT EXISTS connected_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_auth_connected_client_pubkey
ON authorizations(connected_client_pubkey)
WHERE connected_client_pubkey IS NOT NULL;
