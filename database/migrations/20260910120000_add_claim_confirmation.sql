-- Add pending-claim state so an account claim completes only after the
-- claimer confirms control of the email they entered (see spec
-- 2026-09-10-claim-email-confirmation-design.md). Mirrors the
-- oauth_codes.pending_* / pending_email_change idioms.
ALTER TABLE account_claim_tokens
    ADD COLUMN pending_email            TEXT,
    ADD COLUMN pending_password_hash    TEXT,
    ADD COLUMN confirmation_token       TEXT,
    ADD COLUMN confirmation_expires_at  TIMESTAMPTZ,
    ADD COLUMN confirmation_sent_at     TIMESTAMPTZ;

-- Confirm lookups are by confirmation_token; unique when present.
CREATE UNIQUE INDEX idx_claim_tokens_confirmation_token
    ON account_claim_tokens (confirmation_token)
    WHERE confirmation_token IS NOT NULL;
