-- Durable, append-only audit log for admin actions.
-- Initial use is registered_clients create/update/delete; the table is
-- intentionally generic so other admin actions (claim-token regenerate,
-- support-admin add/remove, preload-user) can reuse it without a new schema.
CREATE TABLE IF NOT EXISTS admin_audit_events (
    id BIGSERIAL PRIMARY KEY,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    tenant_id BIGINT NOT NULL,
    actor_pubkey TEXT NOT NULL,
    action TEXT NOT NULL,
    target_resource_type TEXT NOT NULL,
    target_resource_id TEXT,
    target_client_id TEXT,
    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_admin_audit_events_tenant_occurred_at
    ON admin_audit_events (tenant_id, occurred_at DESC);

CREATE INDEX IF NOT EXISTS idx_admin_audit_events_resource
    ON admin_audit_events (tenant_id, target_resource_type, target_resource_id);

CREATE INDEX IF NOT EXISTS idx_admin_audit_events_action_occurred_at
    ON admin_audit_events (action, occurred_at DESC);
