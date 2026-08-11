-- One live pending registration per (tenant, email).
--
-- The mobile app can POST /api/headless/register twice for a single signup (measured in
-- production: two calls 2.9s apart, and ~25 emails hit the endpoint 2+ times in 8 days, some
-- 1.2s apart). Each call minted a separate pending row, device_code, verification token and
-- email, so the user could open the older link and get a 409 that deleted the stale row,
-- followed by a 401 "Invalid or expired token". Registering twice must supersede the first
-- attempt in place instead of racing a second row into existence.
--
-- Only pending rows are covered: minted exchange-code rows carry pending_email = NULL, and a
-- completed registration is marked consumed_at, so neither participates in the constraint.

-- The migration job runs before the new service rollout while old instances may still insert
-- duplicates. Serialize writes before choosing survivors so a row cannot commit between the
-- DELETE snapshot and unique-index creation. The table is small and the index build is bounded;
-- this brief write pause is safer than a load-dependent migration failure.
LOCK TABLE oauth_codes IN SHARE ROW EXCLUSIVE MODE;

-- Collapse pre-existing duplicates so the unique index can be created. The newest row is the
-- one the app is polling (it holds the device_code returned by the last register call); older
-- rows are already unreachable. Their short-lived minted exchange codes, if any, expire on
-- their own 10-minute window.
WITH ranked AS (
    SELECT code,
           ROW_NUMBER() OVER (
               PARTITION BY tenant_id, lower(pending_email)
               ORDER BY created_at DESC, code DESC
           ) AS dup_rank
    FROM oauth_codes
    WHERE pending_email IS NOT NULL
      AND consumed_at IS NULL
)
DELETE FROM oauth_codes
WHERE code IN (SELECT code FROM ranked WHERE dup_rank > 1);

CREATE UNIQUE INDEX idx_oauth_codes_live_pending_email
    ON oauth_codes (tenant_id, lower(pending_email))
    WHERE pending_email IS NOT NULL AND consumed_at IS NULL;
