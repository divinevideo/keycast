-- Preserve outstanding links while replacing their stored bearer values with
-- lowercase SHA-256 digests. sha256(bytea) is built into supported PostgreSQL.
UPDATE users SET
    password_reset_token = encode(sha256(convert_to(password_reset_token, 'UTF8')), 'hex'),
    email_verification_token = encode(sha256(convert_to(email_verification_token, 'UTF8')), 'hex'),
    pending_email_old_token = encode(sha256(convert_to(pending_email_old_token, 'UTF8')), 'hex'),
    pending_email_new_token = encode(sha256(convert_to(pending_email_new_token, 'UTF8')), 'hex')
WHERE password_reset_token IS NOT NULL OR email_verification_token IS NOT NULL
   OR pending_email_old_token IS NOT NULL OR pending_email_new_token IS NOT NULL;

UPDATE account_claim_tokens SET
    token = encode(sha256(convert_to(token, 'UTF8')), 'hex'),
    confirmation_token = encode(sha256(convert_to(confirmation_token, 'UTF8')), 'hex');

UPDATE oauth_codes SET
    code = encode(sha256(convert_to(code, 'UTF8')), 'hex'),
    device_code = encode(sha256(convert_to(device_code, 'UTF8')), 'hex'),
    pending_email_verification_token = encode(sha256(convert_to(pending_email_verification_token, 'UTF8')), 'hex');

UPDATE atproto_oauth_sessions SET
    authorization_code = encode(sha256(convert_to(authorization_code, 'UTF8')), 'hex');

-- Fail closed on legacy writers during rollout rather than retaining their
-- old raw-token format after the backfill. Issuance requires the new binary.
ALTER TABLE users ADD CONSTRAINT users_bearer_token_digests CHECK (
    (password_reset_token IS NULL OR password_reset_token ~ '^[0-9a-f]{64}$') AND
    (email_verification_token IS NULL OR email_verification_token ~ '^[0-9a-f]{64}$') AND
    (pending_email_old_token IS NULL OR pending_email_old_token ~ '^[0-9a-f]{64}$') AND
    (pending_email_new_token IS NULL OR pending_email_new_token ~ '^[0-9a-f]{64}$')
);
ALTER TABLE account_claim_tokens ADD CONSTRAINT claim_bearer_token_digests CHECK (
    token ~ '^[0-9a-f]{64}$' AND
    (confirmation_token IS NULL OR confirmation_token ~ '^[0-9a-f]{64}$')
);
ALTER TABLE oauth_codes ADD CONSTRAINT oauth_bearer_token_digests CHECK (
    code ~ '^[0-9a-f]{64}$' AND
    (device_code IS NULL OR device_code ~ '^[0-9a-f]{64}$') AND
    (pending_email_verification_token IS NULL OR pending_email_verification_token ~ '^[0-9a-f]{64}$')
);
ALTER TABLE atproto_oauth_sessions ADD CONSTRAINT atproto_authorization_code_digest CHECK (
    authorization_code IS NULL OR authorization_code ~ '^[0-9a-f]{64}$'
);
