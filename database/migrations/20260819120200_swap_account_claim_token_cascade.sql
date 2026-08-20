-- Once the replacement has been validated, briefly swap it into the original
-- constraint name. A short timeout prevents lock acquisition from building a
-- queue behind live traffic; failure rolls this transaction back for a retry.
SET LOCAL lock_timeout = '5s';

ALTER TABLE ONLY public.account_claim_tokens
    DROP CONSTRAINT account_claim_tokens_user_pubkey_fkey;

ALTER TABLE ONLY public.account_claim_tokens
    RENAME CONSTRAINT account_claim_tokens_user_pubkey_cascade_fkey
    TO account_claim_tokens_user_pubkey_fkey;
