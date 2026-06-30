-- Add a terminal "consumed" marker to oauth_codes (keycast#262).
--
-- A pending email-verification registration row is re-clickable within its 24h window: re-verifying
-- re-arms a fresh 10-minute exchange code (which makes link prefetch/preview harmless). Once the
-- user actually redeems an exchange code for tokens, the registration is complete and must not be
-- re-minted again. `consumed_at` records that terminal transition: it is set when the exchange code
-- is redeemed at the token endpoint, and finalize refuses to re-mint once it is set. Cleanup deletes
-- consumed (and expired) rows so the pending row has a finite lifecycle.
ALTER TABLE oauth_codes
    ADD COLUMN IF NOT EXISTS consumed_at TIMESTAMPTZ;
