-- Bound how long a deleted account's address is retained, independently of any consumer.
--
-- The deletions table exists so a sync worker can remove the contact from the email platform after
-- keycast hard-deletes the account. Retention was previously bounded only by that worker
-- acknowledging the row. That is not a bound: if the worker is not deployed, is misconfigured, or
-- is simply switched off, addresses accumulate here indefinitely for accounts that no longer exist.
-- Somebody who deleted their Divine account is entitled to a stronger guarantee than "a service in
-- another repository is expected to be running".
--
-- `expires_at` makes the bound a property of the data rather than of an external process. Rows past
-- it are purged on read, so the guarantee holds even if nothing ever drains the queue. Fourteen days
-- is generous for a worker that runs every five minutes, while still being a real ceiling.
--
-- The trade-off is stated plainly: if the worker is down for longer than the retention window, the
-- pending removal is dropped and that contact stays in the email platform until some other pass
-- catches it. Retaining a deleted person's address forever is the worse of the two failures.
ALTER TABLE email_marketing_deletions
    ADD COLUMN expires_at TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '14 days');

CREATE INDEX idx_email_marketing_deletions_expires_at
    ON email_marketing_deletions (expires_at);

-- The same reasoning applies to email-change rows: they carry two addresses for an account that
-- still exists, but a row nothing drains is retained personal data with no purpose.
ALTER TABLE email_marketing_email_changes
    ADD COLUMN expires_at TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '14 days');

CREATE INDEX idx_email_marketing_email_changes_expires_at
    ON email_marketing_email_changes (expires_at);
