WITH ranked_personal_keys AS (
    SELECT
        id,
        ROW_NUMBER() OVER (
            PARTITION BY user_pubkey
            ORDER BY updated_at DESC NULLS LAST, created_at DESC NULLS LAST, id DESC
        ) AS row_number
    FROM personal_keys
)
DELETE FROM personal_keys pk
USING ranked_personal_keys ranked
WHERE pk.id = ranked.id
  AND ranked.row_number > 1;

CREATE UNIQUE INDEX IF NOT EXISTS idx_personal_keys_user_pubkey_unique
    ON personal_keys (user_pubkey);
