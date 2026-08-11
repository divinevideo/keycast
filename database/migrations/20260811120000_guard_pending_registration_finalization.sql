-- Serialize in-place registration supersession with user materialization.
--
-- A verification handler reads a pending generation before creating its users row. Without a
-- claim, a new registration can rewrite that same oauth_codes row between the read and creation,
-- causing the superseded generation to materialize. The claim is leased so a crashed handler does
-- not permanently block a fresh registration.
ALTER TABLE oauth_codes
    ADD COLUMN finalization_claim TEXT,
    ADD COLUMN finalization_claimed_at TIMESTAMPTZ;
