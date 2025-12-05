-- Migration: Add absolute expiration for authorization handles
-- Implements Auth0-style two-lifetime model:
-- - expires_at: idle timeout (refreshes on use)
-- - handle_expires_at: absolute timeout (hard ceiling, never changes)

-- Add handle_expires_at column (NOT NULL - new server, no existing data)
ALTER TABLE oauth_authorizations
ADD COLUMN IF NOT EXISTS handle_expires_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW() + INTERVAL '30 days';

-- Remove the default after column is added (new inserts must provide value)
ALTER TABLE oauth_authorizations
ALTER COLUMN handle_expires_at DROP DEFAULT;

-- Add index for efficient handle validation queries
CREATE INDEX IF NOT EXISTS idx_oauth_auth_handle_expires
ON oauth_authorizations(handle_expires_at)
WHERE revoked_at IS NULL;
