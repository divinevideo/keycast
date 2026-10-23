-- OIDC identities: links an account to a subject at an upstream OpenID Provider
-- (any OIDC identity provider), so that signing in there opens a Keycast session
-- without a Keycast password. See api/src/api/http/oidc.rs.
--
-- One row per (tenant, issuer, subject). An account has at most one subject per
-- issuer. Rows are created on the first successful upstream login, when the
-- provider's link claim names an existing account (users.vine_id); they are never
-- created for unknown accounts.
CREATE TABLE IF NOT EXISTS public.oidc_identities (
    tenant_id BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    issuer TEXT NOT NULL CHECK (issuer <> ''),
    subject TEXT NOT NULL CHECK (subject <> ''),
    user_pubkey TEXT NOT NULL REFERENCES users(pubkey) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login_at TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, issuer, subject),
    UNIQUE (tenant_id, issuer, user_pubkey)
);

CREATE INDEX IF NOT EXISTS idx_oidc_identities_user ON public.oidc_identities(user_pubkey);
