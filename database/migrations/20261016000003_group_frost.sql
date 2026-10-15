-- Public protocol state only. Client nonce/secret packages are never stored here.
CREATE TABLE group_frost_sessions (
    tenant_id BIGINT NOT NULL,
    group_id INTEGER NOT NULL REFERENCES identity_groups(id),
    id TEXT NOT NULL,
    session_kind TEXT NOT NULL CHECK (session_kind IN ('dkg', 'signing')),
    state JSONB NOT NULL,
    aborted BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, group_id, id)
);
-- A commitment is burned for this identity forever, including aborted sessions.
-- Keep this ledger with backups; clients must additionally discard all pending
-- approvals on process death or restore, even if a coordinator backup is older.
CREATE TABLE group_frost_commitments (
    tenant_id BIGINT NOT NULL,
    group_id INTEGER NOT NULL REFERENCES identity_groups(id),
    participant_id INTEGER NOT NULL,
    commitment_hash TEXT NOT NULL,
    session_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, group_id, commitment_hash),
    FOREIGN KEY (tenant_id, group_id, session_id)
        REFERENCES group_frost_sessions(tenant_id, group_id, id)
);
CREATE INDEX group_frost_sessions_group ON group_frost_sessions(tenant_id, group_id, session_kind);
