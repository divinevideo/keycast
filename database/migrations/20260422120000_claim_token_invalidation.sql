ALTER TABLE account_claim_tokens
  ADD COLUMN IF NOT EXISTS invalidated_at       TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS invalidated_by       TEXT,
  ADD COLUMN IF NOT EXISTS invalidation_reason  TEXT;

CREATE INDEX IF NOT EXISTS idx_claim_tokens_invalidated_at
  ON account_claim_tokens (invalidated_at)
  WHERE invalidated_at IS NOT NULL;
