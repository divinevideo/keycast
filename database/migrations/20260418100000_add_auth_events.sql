CREATE TABLE IF NOT EXISTS auth_events (
    id BIGSERIAL PRIMARY KEY,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    request_id TEXT NOT NULL,
    tenant_id BIGINT NOT NULL,
    endpoint TEXT NOT NULL,
    event_type TEXT NOT NULL,
    outcome TEXT NOT NULL,
    reason_code TEXT,
    http_status INTEGER,
    email TEXT,
    email_hash TEXT NOT NULL,
    pubkey TEXT,
    pubkey_prefix TEXT,
    client_id TEXT,
    redirect_origin TEXT,
    user_agent TEXT,
    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_auth_events_occurred_at
    ON auth_events (occurred_at DESC);

CREATE INDEX IF NOT EXISTS idx_auth_events_request_id
    ON auth_events (request_id);

CREATE INDEX IF NOT EXISTS idx_auth_events_tenant_email
    ON auth_events (tenant_id, email, occurred_at DESC);

CREATE INDEX IF NOT EXISTS idx_auth_events_tenant_pubkey
    ON auth_events (tenant_id, pubkey, occurred_at DESC);

CREATE INDEX IF NOT EXISTS idx_auth_events_tenant_endpoint_occurred_at
    ON auth_events (tenant_id, endpoint, occurred_at DESC);
