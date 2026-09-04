-- Email-marketing consent captured at account creation (mobile create-account screen).
--
-- Two distinct things live here and must not be conflated:
--
--   1. The consent EVENT. What the person answered, when, from where, and under which app
--      version. Immutable. Never overwritten, because overwriting it destroys the evidence that
--      consent was validly obtained.
--   2. The suppression FLOOR. Observed from the email platform, recording that this person opted
--      out of all email. This is Divine's own signal, not a mirror: HubSpot forgets an opt-out as
--      soon as the address changes, so the floor is the only thing that remembers. Any Divine
--      system that sends marketing email must respect it, whatever CRM it uses.
--
-- Tri-state rather than boolean: (false, NULL) cannot distinguish "asked and declined" from
-- "never asked", and that distinction decides whether it is legitimate to ask again.
--
-- Named email_marketing_* rather than marketing_*: divine-engagement is introducing a push opt-in
-- with its own settings, and an unqualified name would be misread.
ALTER TABLE users
    ADD COLUMN email_marketing_consent TEXT NOT NULL DEFAULT 'never_asked'
        CHECK (email_marketing_consent IN ('never_asked', 'declined', 'opted_in')),
    ADD COLUMN email_marketing_consent_at TIMESTAMPTZ,
    ADD COLUMN email_marketing_consent_source TEXT,
    ADD COLUMN email_marketing_consent_app_version TEXT,
    -- NULL means never observed. Deliberately not NOT NULL DEFAULT FALSE, which would let
    -- "we have never checked" masquerade as "safe to email".
    ADD COLUMN email_marketing_global_optout BOOLEAN,
    ADD COLUMN email_marketing_optout_observed_at TIMESTAMPTZ;

ALTER TABLE oauth_codes
    ADD COLUMN pending_email_marketing_consent TEXT NOT NULL DEFAULT 'never_asked'
        CHECK (pending_email_marketing_consent IN ('never_asked', 'declined', 'opted_in')),
    ADD COLUMN pending_email_marketing_app_version TEXT;

-- The sync service reads consent by cursor, ordered by (updated_at, pubkey).
CREATE INDEX idx_users_email_marketing_cursor ON users (updated_at, pubkey);
