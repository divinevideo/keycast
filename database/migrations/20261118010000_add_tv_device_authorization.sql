CREATE TABLE oauth_device_grants (
    tenant_id bigint NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    device_code_hash text NOT NULL,
    user_code_hash text NOT NULL,
    user_pubkey character(64) REFERENCES users(pubkey) ON DELETE CASCADE ON UPDATE CASCADE,
    expires_at timestamptz NOT NULL,
    next_poll_at timestamptz NOT NULL,
    poll_interval_seconds integer NOT NULL DEFAULT 5,
    status text NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'approved', 'denied', 'consumed')),
    PRIMARY KEY (tenant_id, device_code_hash),
    UNIQUE (tenant_id, user_code_hash),
    CHECK ((user_pubkey IS NOT NULL) = (status = 'approved'))
);

CREATE INDEX oauth_device_grants_expires_at_idx ON oauth_device_grants (expires_at);
CREATE INDEX oauth_device_grants_user_pubkey_idx ON oauth_device_grants (user_pubkey)
    WHERE user_pubkey IS NOT NULL;

CREATE TABLE oauth_device_sessions (
    id text PRIMARY KEY,
    tenant_id bigint NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_pubkey character(64) NOT NULL REFERENCES users(pubkey) ON DELETE CASCADE ON UPDATE CASCADE,
    refresh_token_hash text NOT NULL UNIQUE,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz
);

CREATE INDEX oauth_device_sessions_expires_at_idx ON oauth_device_sessions (expires_at);
CREATE INDEX oauth_device_sessions_user_pubkey_idx ON oauth_device_sessions (user_pubkey);
