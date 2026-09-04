-- The old address, captured before it is overwritten.
--
-- `users.email` is updated in place when someone changes their email, so by the time the sync
-- service sees the changed row it knows only the new address. It needs the old one to find and move
-- the existing contact in the email platform. Without this the sync creates a duplicate contact and
-- the previous address stays subscribed indefinitely.
--
-- Transient, like email_marketing_deletions: a row exists only until the sync service has moved the
-- contact, then it is cleared.
CREATE TABLE email_marketing_email_changes (
    id         BIGSERIAL PRIMARY KEY,
    tenant_id  BIGINT NOT NULL,
    pubkey     TEXT NOT NULL,
    old_email  TEXT NOT NULL,
    new_email  TEXT NOT NULL,
    changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
