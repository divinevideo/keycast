-- Minimized replay records for completed account deletion and provisioning.
-- Full operation rows remain authoritative until an authenticated coordinator
-- request compacts them after the approved retention period.

CREATE TABLE service_account_deletion_tombstones (
    deletion_request_id TEXT PRIMARY KEY,
    tenant_id BIGINT NOT NULL REFERENCES tenants(id),
    outcome TEXT NOT NULL,
    completed_at TIMESTAMPTZ NOT NULL,
    binding_digest BYTEA NOT NULL,
    digest_key_version INTEGER NOT NULL CHECK (digest_key_version > 0),
    compacted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT service_account_deletion_tombstones_outcome_check
        CHECK (outcome IN ('deleted', 'already_absent'))
);

CREATE INDEX idx_service_account_deletion_tombstones_completed_at
    ON service_account_deletion_tombstones (completed_at DESC);

ALTER TABLE service_provisioning_operations
    ADD COLUMN deleted_at TIMESTAMPTZ;

-- Accounts deleted before this migration have no trustworthy local deletion
-- timestamp. Start a conservative new retention clock instead of inferring an
-- earlier date and making their operation rows immediately disposable.
UPDATE service_provisioning_operations AS operation
SET deleted_at = NOW()
WHERE NOT EXISTS (
    SELECT 1
    FROM users
    WHERE users.tenant_id = operation.tenant_id
      AND users.pubkey = operation.user_pubkey
);

CREATE INDEX idx_service_provisioning_operations_tenant_pubkey
    ON service_provisioning_operations (tenant_id, user_pubkey);

CREATE INDEX idx_service_provisioning_operations_deleted_at
    ON service_provisioning_operations (deleted_at)
    WHERE deleted_at IS NOT NULL;

CREATE TABLE service_provisioning_operation_tombstones (
    provisioning_operation_id TEXT PRIMARY KEY,
    tenant_id BIGINT NOT NULL REFERENCES tenants(id),
    request_fingerprint_digest BYTEA NOT NULL,
    binding_digest BYTEA NOT NULL,
    digest_key_version INTEGER NOT NULL CHECK (digest_key_version > 0),
    outcome TEXT NOT NULL DEFAULT 'account_deleted',
    completed_at TIMESTAMPTZ NOT NULL,
    compacted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT service_provisioning_operation_tombstones_outcome_check
        CHECK (outcome = 'account_deleted')
);

CREATE INDEX idx_service_provisioning_operation_tombstones_completed_at
    ON service_provisioning_operation_tombstones (completed_at DESC);

CREATE INDEX idx_service_provisioning_operation_tombstones_binding
    ON service_provisioning_operation_tombstones (tenant_id, binding_digest);

-- Holds are deliberately references, not narratives. scope_key is the exact
-- deletion request id or full account pubkey covered by the preservation order.
CREATE TABLE retention_legal_holds (
    hold_id TEXT PRIMARY KEY,
    tenant_id BIGINT NOT NULL REFERENCES tenants(id),
    scope_kind TEXT NOT NULL,
    scope_key TEXT NOT NULL,
    authorizing_role TEXT NOT NULL,
    reason_reference TEXT NOT NULL,
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    review_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ,
    released_at TIMESTAMPTZ,
    CONSTRAINT retention_legal_holds_scope_kind_check
        CHECK (scope_kind IN ('deletion_request', 'account_binding')),
    CONSTRAINT retention_legal_holds_release_check
        CHECK (released_at IS NULL OR released_at >= started_at),
    CONSTRAINT retention_legal_holds_review_check
        CHECK (review_at >= started_at),
    CONSTRAINT retention_legal_holds_expiry_check
        CHECK (expires_at IS NULL OR expires_at >= started_at)
);

CREATE INDEX idx_retention_legal_holds_active_scope
    ON retention_legal_holds (tenant_id, scope_kind, scope_key)
    WHERE released_at IS NULL;
