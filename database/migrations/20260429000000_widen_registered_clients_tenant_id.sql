-- Widen registered_clients.tenant_id from INTEGER to BIGINT.
--
-- Every other tenant_id column in this schema is BIGINT (tenants.id,
-- users.tenant_id, refresh_tokens.tenant_id, oauth_authorizations.tenant_id,
-- atproto_oauth_sessions.tenant_id, auth_events.tenant_id). 0008_registered_clients
-- was the lone INTEGER outlier, which forced the i64 API surface to use
-- `tenant_id::BIGINT AS tenant_id` casts on every read. Aligning the column
-- removes the casts and the implicit i64->i32 narrowing on writes.
--
-- Idempotent: only ALTERs when the current data_type is `integer`, so re-runs
-- are no-ops.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'registered_clients'
          AND column_name = 'tenant_id'
          AND data_type = 'integer'
    ) THEN
        ALTER TABLE public.registered_clients
            ALTER COLUMN tenant_id TYPE BIGINT;
    END IF;
END
$$;
