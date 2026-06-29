-- Add in-app PIN fallback fields to oauth_codes (keycast#262).
--
-- Headless registrations email a 6-digit PIN alongside the verification link as a
-- second transport for the same proof of email control. The PIN is stored hashed,
-- bounded by an attempt cap (brute-force protection), and re-armable via resend.
--
-- pin_hash:     bcrypt hash of the 6-digit PIN (NULL when no PIN was issued).
-- pin_attempts: failed verify-pin attempts; cap enforced at 5, reset on resend.
-- pin_sent_at:  backs the 5-minute PIN-resend cooldown (mirrors users.email_verification_sent_at,
--               but lives on the pending oauth_codes row since headless users have no users row yet).
ALTER TABLE oauth_codes
    ADD COLUMN IF NOT EXISTS pin_hash     TEXT,
    ADD COLUMN IF NOT EXISTS pin_attempts INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS pin_sent_at  TIMESTAMPTZ;
