-- Ciphertext contains the complete binding as authenticated plaintext inside the envelope.
CREATE TABLE group_backups (
    tenant_id BIGINT NOT NULL,
    group_id INTEGER NOT NULL REFERENCES identity_groups(id) ON DELETE CASCADE,
    admin_pubkey TEXT NOT NULL,
    request_id TEXT NOT NULL CHECK (length(request_id) BETWEEN 1 AND 128),
    membership_version BIGINT NOT NULL,
    key_version INTEGER NOT NULL,
    roster_version INTEGER NOT NULL,
    content_hash BYTEA NOT NULL CHECK (octet_length(content_hash) = 32),
    ciphertext BYTEA NOT NULL CHECK (octet_length(ciphertext) > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, group_id, admin_pubkey, request_id)
);
CREATE INDEX group_backups_current ON group_backups (tenant_id, group_id, admin_pubkey, key_version, roster_version, membership_version, created_at DESC);

CREATE TABLE group_backup_restores (
    tenant_id BIGINT NOT NULL,
    group_id INTEGER NOT NULL REFERENCES identity_groups(id) ON DELETE CASCADE,
    admin_pubkey TEXT NOT NULL,
    request_id TEXT NOT NULL CHECK (length(request_id) BETWEEN 1 AND 128),
    backup_request_id TEXT NOT NULL,
    installation_epoch BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, group_id, admin_pubkey, request_id),
    FOREIGN KEY (tenant_id, group_id, admin_pubkey, backup_request_id)
        REFERENCES group_backups (tenant_id, group_id, admin_pubkey, request_id)
);
