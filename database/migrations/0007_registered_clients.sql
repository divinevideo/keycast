-- Registered OAuth clients with allowed redirect URI patterns
-- Provides security hardening: when a client_id is registered, only its
-- allowed redirect URIs are accepted. Unregistered client_ids fall back
-- to accepting any HTTPS redirect_uri (backward compatible).
CREATE TABLE IF NOT EXISTS public.registered_clients (
    id SERIAL PRIMARY KEY,
    tenant_id INTEGER NOT NULL DEFAULT 1,
    client_id TEXT NOT NULL,
    name TEXT NOT NULL,
    -- Array of allowed redirect URI patterns
    -- Exact match: "https://divine.video/app/callback"
    -- Wildcard subdomain: "https://*.openvine-app.pages.dev/callback"
    -- Localhost any port: "http://localhost:*/callback"
    allowed_redirect_uris TEXT[] NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, client_id)
);
