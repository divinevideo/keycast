-- Account deletion is a hard delete, so a deleted row is invisible to a "what changed since"
-- query and the sync service would never learn the account went away. Without this, someone who
-- deleted their Divine account would keep receiving Divine marketing, which is the worst outcome
-- this design has to prevent.
--
-- Deliberately transient: a row exists only until the sync service has removed the contact from
-- the email platform, then it is cleared. That bounds how long an address is retained past
-- deletion. No pubkey is stored: the account is gone, and the address is all that is needed.
CREATE TABLE email_marketing_deletions (
    id         BIGSERIAL PRIMARY KEY,
    tenant_id  BIGINT NOT NULL,
    email      TEXT NOT NULL,
    deleted_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
