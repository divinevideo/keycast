-- Support admins: the per-tenant grant list for read-only support tooling.
--
-- This list used to live only in a Redis set keyed per deployment. Redis is
-- for ephemeral, self-healing state; an access-control list is durable
-- security state, so a restart or flush of a non-persistent Redis silently
-- revoked every grant and a Redis outage turned the admin list into a 500.
-- Postgres is now the only source of truth.
--
-- Grants are tenant-scoped. `added_by_pubkey` records the full admin who made
-- the grant and is NULL only for rows created outside the admin API, such as
-- the one-time seed of each deployment's legacy grants (docs/DEPLOYMENT.md).
CREATE TABLE IF NOT EXISTS public.support_admins (
    tenant_id BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    pubkey TEXT NOT NULL CHECK (pubkey ~ '^[0-9a-f]{64}$'),
    added_by_pubkey TEXT CHECK (added_by_pubkey ~ '^[0-9a-f]{64}$'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, pubkey)
);
