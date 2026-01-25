-- Add is_headless column to oauth_codes to track codes issued via headless flow
-- This allows us to add first_party:true fact to UCANs for account deletion authorization

ALTER TABLE oauth_codes ADD COLUMN IF NOT EXISTS is_headless BOOLEAN NOT NULL DEFAULT FALSE;
