-- Add columns to oauth_codes for pending registration data
-- These allow deferring user creation until token exchange,
-- preventing orphaned user state when BYOK registration doesn't complete

-- Drop foreign key constraint on user_pubkey to allow storing codes for pending registrations
-- (user doesn't exist yet during OAuth registration, only created at token exchange)
ALTER TABLE oauth_codes DROP CONSTRAINT IF EXISTS oauth_codes_user_pubkey_fkey;

-- Add columns for pending registration data
ALTER TABLE oauth_codes ADD COLUMN IF NOT EXISTS pending_email TEXT;
ALTER TABLE oauth_codes ADD COLUMN IF NOT EXISTS pending_password_hash TEXT;
ALTER TABLE oauth_codes ADD COLUMN IF NOT EXISTS pending_email_verification_token TEXT;
ALTER TABLE oauth_codes ADD COLUMN IF NOT EXISTS pending_encrypted_secret BYTEA;
