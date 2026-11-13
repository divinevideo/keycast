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
