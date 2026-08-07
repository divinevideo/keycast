-- Preserve whether an OAuth authorization was created by the first-party headless flow.
-- Refresh-token rotation reads this flag when minting a replacement UCAN.
ALTER TABLE oauth_authorizations
ADD COLUMN IF NOT EXISTS is_first_party BOOLEAN NOT NULL DEFAULT FALSE;
