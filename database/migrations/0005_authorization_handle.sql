-- Migration: Add authorization_handle for silent re-authentication
-- This implements the authorization_handle feature from SESSION_HINT_PROPOSAL.md

-- Add authorization_handle to oauth_authorizations
-- 64 hex chars = 32 bytes = 256-bit random token
ALTER TABLE oauth_authorizations
ADD COLUMN IF NOT EXISTS authorization_handle CHAR(64);

-- Partial unique index for fast lookups of active handles
-- Only enforces uniqueness on non-NULL handles where authorization is not revoked
CREATE UNIQUE INDEX IF NOT EXISTS idx_oauth_auth_handle
ON oauth_authorizations(authorization_handle)
WHERE authorization_handle IS NOT NULL AND revoked_at IS NULL;

-- Add previous_auth_id to oauth_codes for cleanup tracking
-- Stores the authorization ID that will be revoked after token exchange
ALTER TABLE oauth_codes
ADD COLUMN IF NOT EXISTS previous_auth_id INTEGER;
