-- Case-insensitive NIP-05 username uniqueness per tenant.
-- Replaces idx_users_username_tenant (tenant_id, username) which allowed Alice vs alice.
--
-- Rare edge case: if multiple rows share the same LOWER(username), all but the lexicographically
-- smallest pubkey lose their username (set NULL) so the migration can complete.

DROP INDEX IF EXISTS idx_users_username_tenant;

UPDATE users u
SET username = NULL, updated_at = NOW()
WHERE u.username IS NOT NULL
  AND EXISTS (
    SELECT 1
    FROM users u2
    WHERE u2.tenant_id = u.tenant_id
      AND u2.username IS NOT NULL
      AND LOWER(u2.username) = LOWER(u.username)
      AND u2.pubkey < u.pubkey
  );

UPDATE users
SET username = LOWER(username), updated_at = NOW()
WHERE username IS NOT NULL;

CREATE UNIQUE INDEX idx_users_username_tenant_lower
    ON users (tenant_id, LOWER(username))
    WHERE username IS NOT NULL;

DROP INDEX IF EXISTS idx_users_lower_username_tenant;
