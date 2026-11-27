-- Preserve the checksum of the original identity migration. Apple grants
-- now live in apple_identity_grants, keyed by identity and client.
ALTER TABLE user_identities
    DROP CONSTRAINT user_identities_apple_token_check,
    DROP COLUMN apple_refresh_token_encrypted,
    DROP COLUMN apple_token_client_id;
