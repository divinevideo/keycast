-- Marketing-communications consent captured at account creation (mobile create-account screen).
-- The choice is made at register time and threaded through the deferred registration: it rides on
-- the oauth_codes pending row (pending_marketing_consent) and is written onto the users row when the
-- registration materializes, mirroring how pending_password_hash / pending_encrypted_secret thread
-- through the same flow. marketing_consent_at is stamped at account creation and only when consent
-- is true, so a NULL timestamp means "never opted in" rather than "opted in at an unknown time".
ALTER TABLE users
    ADD COLUMN marketing_consent    BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN marketing_consent_at TIMESTAMPTZ;

ALTER TABLE oauth_codes
    ADD COLUMN pending_marketing_consent BOOLEAN NOT NULL DEFAULT FALSE;
