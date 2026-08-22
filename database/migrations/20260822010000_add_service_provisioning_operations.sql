-- Durable idempotency records for service-requested protected-account provisioning.
--
-- Deliberately no foreign key to users: a completed operation must remain
-- answerable after the resulting account has been deleted.

CREATE TABLE IF NOT EXISTS service_provisioning_operations (
    provisioning_operation_id TEXT PRIMARY KEY,
    tenant_id BIGINT NOT NULL REFERENCES tenants(id),
    request_fingerprint CHAR(64) NOT NULL,
    user_pubkey CHAR(64) NOT NULL,
    outcome TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT service_provisioning_operations_outcome_check
        CHECK (outcome IN ('created'))
);

CREATE INDEX IF NOT EXISTS idx_service_provisioning_operations_created_at
    ON service_provisioning_operations (created_at DESC);
