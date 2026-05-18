ALTER TABLE users
    ADD COLUMN status TEXT NOT NULL DEFAULT 'active',
    ADD COLUMN suspended_reason TEXT,
    ADD COLUMN suspended_at TIMESTAMPTZ;

ALTER TABLE users
    ADD CONSTRAINT users_status_check CHECK (status IN ('active', 'suspended', 'banned'));

CREATE INDEX idx_users_status ON users (status) WHERE status != 'active';
