-- Group identities reuse team keys; membership and device grants have their own lifecycle.
CREATE TABLE identity_groups (
    id INTEGER PRIMARY KEY REFERENCES teams(id),
    tenant_id BIGINT NOT NULL REFERENCES tenants(id),
    name TEXT NOT NULL,
    pubkey TEXT,
    signing_key_id INTEGER UNIQUE REFERENCES stored_keys(id),
    policy_id INTEGER NOT NULL REFERENCES policies(id),
    mode TEXT NOT NULL CHECK (mode IN ('hosted', 'device', 'frost')),
    key_version INTEGER NOT NULL DEFAULT 1 CHECK (key_version > 0),
    roster_version INTEGER NOT NULL DEFAULT 1 CHECK (roster_version > 0),
    creator_pubkey TEXT NOT NULL,
    request_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, creator_pubkey, request_id),
    UNIQUE (tenant_id, id),
    CHECK (mode != 'hosted' OR (pubkey IS NOT NULL AND signing_key_id IS NOT NULL))
);
CREATE TABLE group_memberships (
    tenant_id BIGINT NOT NULL,
    group_id INTEGER NOT NULL,
    admin_pubkey TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('invited','active','removed')),
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    participant_id INTEGER CHECK (participant_id BETWEEN 1 AND 65535),
    installation_epoch BIGINT NOT NULL DEFAULT 1 CHECK (installation_epoch > 0),
    PRIMARY KEY (tenant_id, group_id, admin_pubkey),
    FOREIGN KEY (tenant_id, group_id) REFERENCES identity_groups(tenant_id,id),
    UNIQUE (group_id, participant_id)
);
CREATE TABLE group_grants (
    authorization_id INTEGER PRIMARY KEY REFERENCES authorizations(id) ON DELETE CASCADE,
    tenant_id BIGINT NOT NULL,
    group_id INTEGER NOT NULL,
    admin_pubkey TEXT NOT NULL,
    membership_version BIGINT NOT NULL,
    key_version INTEGER NOT NULL,
    installation_epoch BIGINT NOT NULL,
    revoked_at TIMESTAMPTZ,
    FOREIGN KEY (tenant_id, group_id, admin_pubkey)
        REFERENCES group_memberships(tenant_id,group_id,admin_pubkey)
);
CREATE INDEX group_grants_member ON group_grants(tenant_id, group_id, admin_pubkey);
CREATE TABLE group_audit (
    id BIGSERIAL PRIMARY KEY,
    tenant_id BIGINT NOT NULL,
    group_id INTEGER NOT NULL,
    admin_pubkey TEXT NOT NULL,
    action TEXT NOT NULL,
    event_id TEXT,
    session_id TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    FOREIGN KEY (tenant_id,group_id) REFERENCES identity_groups(tenant_id,id)
);
