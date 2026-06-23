-- Self-serve email change with dual (old + new address) confirmation.
-- Mirrors the per-row token pattern used by password_reset_token / email_verification_token.
-- pending_email_sent_at backs the 5-minute resend cooldown (mirrors email_verification_sent_at).
ALTER TABLE users
    ADD COLUMN pending_email                  TEXT,
    ADD COLUMN pending_email_old_token        TEXT,
    ADD COLUMN pending_email_new_token        TEXT,
    ADD COLUMN pending_email_expires_at       TIMESTAMPTZ,
    ADD COLUMN pending_email_sent_at          TIMESTAMPTZ,
    ADD COLUMN pending_email_old_confirmed_at TIMESTAMPTZ,
    ADD COLUMN pending_email_new_confirmed_at TIMESTAMPTZ;

CREATE INDEX idx_users_pending_email_old_token
    ON users (pending_email_old_token) WHERE pending_email_old_token IS NOT NULL;
CREATE INDEX idx_users_pending_email_new_token
    ON users (pending_email_new_token) WHERE pending_email_new_token IS NOT NULL;
