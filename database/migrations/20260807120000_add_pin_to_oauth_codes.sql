-- Add in-app PIN fallback fields to oauth_codes (keycast#262).
--
-- Headless registrations email a 6-digit PIN alongside the verification link as a
-- second transport for the same proof of email control. The PIN is stored hashed,
-- bounded by an attempt cap (brute-force protection), and re-armable via resend.
--
-- pin_hash:      bcrypt hash of the 6-digit PIN (NULL when no PIN was issued).
-- pin_attempts:  failed verify-pin attempts; cap enforced at 5, reset on resend.
-- pin_sent_at:   when the *current* PIN was handed to the delivery provider. Backs the PIN's own
--                validity window, which is much shorter than the row's 24h registration window.
-- pin_resend_at: when a PIN resend was last performed. Backs the resend cooldown, and is
--                deliberately separate from pin_sent_at: it stays NULL through registration so the
--                first resend a user asks for is never swallowed by a cooldown they never started.
ALTER TABLE oauth_codes
    ADD COLUMN IF NOT EXISTS pin_hash      TEXT,
    ADD COLUMN IF NOT EXISTS pin_attempts  INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS pin_sent_at   TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS pin_resend_at TIMESTAMPTZ;
