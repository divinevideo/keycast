-- Durable record of service-requested terminal account deletions.
--
-- Funnelcake coordinates the cross-service deletion state machine and calls
-- Keycast to permanently delete the hosted account at the end of it. That call
-- has to be idempotent: a lost response, a timeout, or a coordinator restart
-- must be safe to retry without a second irreversible attempt and without
-- reporting failure for work that already committed.
--
-- One row per deletion_request_id, written inside the same transaction as the
-- deletion itself, is what makes the retry answerable. Replaying a request id
-- returns the stored outcome instead of re-running the deletion.
--
-- Deliberately no foreign key to users: the row records that an account was
-- removed, so it has to outlive the account it names.

CREATE TABLE IF NOT EXISTS service_account_deletions (
    deletion_request_id TEXT PRIMARY KEY,
    tenant_id BIGINT NOT NULL REFERENCES tenants(id),
    user_pubkey CHAR(64) NOT NULL,
    outcome TEXT NOT NULL,
    teams_removed INTEGER NOT NULL DEFAULT 0,
    oauth_authorizations_deleted INTEGER NOT NULL DEFAULT 0,
    bunkers_notified INTEGER NOT NULL DEFAULT 0,
    completed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT service_account_deletions_outcome_check
        CHECK (outcome IN ('deleted', 'already_absent'))
);

CREATE INDEX IF NOT EXISTS idx_service_account_deletions_user_pubkey
    ON service_account_deletions (user_pubkey);

CREATE INDEX IF NOT EXISTS idx_service_account_deletions_completed_at
    ON service_account_deletions (completed_at DESC);
