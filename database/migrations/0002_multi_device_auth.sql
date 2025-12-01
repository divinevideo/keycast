-- Multi-device OAuth authorization support
-- Allows multiple authorizations per user+app combination
-- Each "Accept" creates a NEW authorization instead of updating existing

-- Add revoked_at column for soft-delete
ALTER TABLE oauth_authorizations
  ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMP WITH TIME ZONE;

-- Drop the unique constraint that prevents multiple auths per user+app
-- This enables multi-device support: same user can authorize same app multiple times
ALTER TABLE oauth_authorizations
  DROP CONSTRAINT IF EXISTS oauth_auth_user_origin_unique;

-- Add index for efficient queries filtering non-revoked authorizations
-- Note: expires_at filtering is done at query time since NOW() is not immutable
CREATE INDEX IF NOT EXISTS oauth_auth_active_idx ON oauth_authorizations (tenant_id, user_pubkey)
WHERE revoked_at IS NULL;

-- Add index for looking up non-revoked auths by bunker pubkey (signer daemon fast path)
CREATE INDEX IF NOT EXISTS oauth_auth_bunker_active_idx ON oauth_authorizations (bunker_public_key)
WHERE revoked_at IS NULL;
