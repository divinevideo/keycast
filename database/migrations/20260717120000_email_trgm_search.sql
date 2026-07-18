CREATE EXTENSION IF NOT EXISTS pg_trgm;

CREATE INDEX IF NOT EXISTS idx_users_email_trgm
    ON users USING gin (email gin_trgm_ops)
    WHERE email IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_users_tenant_lower_email
    ON users (tenant_id, LOWER(email))
    WHERE email IS NOT NULL;
