-- OG Diviner grants: pubkeys that earned the chit without a Keycast signup.
--
-- The chit's signup rule (UserRepository::is_og_diviner) only sees accounts
-- that registered, claimed a preload, or authorized the mobile app through
-- Keycast before the cutoff. People who posted through a Divine app before the
-- cutoff with a key they created or brought themselves have no such record.
-- That cohort is closed, so it is computed once from relay data, outside this
-- repository, and loaded here (keycast#440). The roster is never committed.
--
-- `evidence` names the rule that admitted the pubkey. The vocabulary is
-- closed so that each new kind of evidence arrives as a reviewed migration
-- rather than as a free-text label typed at load time.
--
-- There is deliberately no foreign key to users: most grantees have no
-- Keycast account.
CREATE TABLE IF NOT EXISTS public.og_diviner_grants (
    tenant_id BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    pubkey TEXT NOT NULL CHECK (pubkey ~ '^[0-9a-f]{64}$'),
    evidence TEXT NOT NULL CHECK (evidence IN ('pre_cutoff_app_post')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, pubkey)
);
