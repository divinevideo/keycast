-- A subject can have grants issued to both native and hosted clients.
CREATE TABLE apple_identity_grants (
    identity_id BIGINT NOT NULL REFERENCES user_identities (id) ON DELETE CASCADE,
    client_id TEXT NOT NULL,
    encrypted_token BYTEA NOT NULL,
    PRIMARY KEY (identity_id, client_id)
);

-- No account identifiers: these rows survive account deletion only to revoke a grant.
CREATE TABLE apple_grant_revocations (
    id BIGSERIAL PRIMARY KEY,
    client_id TEXT NOT NULL,
    encrypted_token BYTEA NOT NULL,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '7 days'
);

CREATE INDEX apple_grant_revocations_ready ON apple_grant_revocations (next_attempt_at, id);

REVOKE ALL ON apple_identity_grants, apple_grant_revocations FROM support_reader;
