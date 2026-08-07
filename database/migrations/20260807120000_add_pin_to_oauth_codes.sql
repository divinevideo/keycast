-- Add in-app PIN fallback fields to oauth_codes (keycast#262).
--
-- Headless registrations email a 6-digit PIN alongside the verification link as a
-- second transport for the same proof of email control. The PIN is stored hashed
-- and bounded by two attempt caps: a per-PIN cap that a resend clears, and a
-- lifetime cap across the whole registration that nothing clears.
--
-- pin_hash:          bcrypt hash of the 6-digit PIN (NULL when no PIN was issued).
-- pin_attempts:      failed attempts against the CURRENT PIN. Reset to 0 by a resend, which is
--                    what makes a resend the recovery path out of a lockout.
-- pin_failed_total:  failed attempts across every PIN this registration has issued. Never reset,
--                    so it bounds guessing over the registration's whole life. Without it the
--                    per-PIN cap would be escapable indefinitely by resending.
-- pin_sent_at:       when the current PIN was handed to the delivery provider. Distinguishes a PIN
--                    the user could be holding from one that was never delivered.
-- pin_resend_at:     when a PIN resend was last performed. Backs the resend cooldown, and is
--                    deliberately separate from pin_sent_at: it stays NULL through registration so
--                    the first resend a user asks for is never swallowed by a cooldown they never
--                    started.
--
-- The PIN itself carries no separate expiry: it is one of two presentations of the same
-- confirmation code as the emailed link, and expires with the registration row's own window.
ALTER TABLE oauth_codes
    ADD COLUMN IF NOT EXISTS pin_hash         TEXT,
    ADD COLUMN IF NOT EXISTS pin_attempts     INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS pin_failed_total INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS pin_sent_at      TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS pin_resend_at    TIMESTAMPTZ;
