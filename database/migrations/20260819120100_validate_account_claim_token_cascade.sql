-- Validate the replacement claim-token foreign key in a separate transaction.
-- PostgreSQL uses weaker locks for VALIDATE CONSTRAINT, so existing rows can be
-- scanned without blocking ordinary writes to users or account_claim_tokens.
SET LOCAL lock_timeout = '5s';

ALTER TABLE ONLY public.account_claim_tokens
    VALIDATE CONSTRAINT account_claim_tokens_user_pubkey_cascade_fkey;
