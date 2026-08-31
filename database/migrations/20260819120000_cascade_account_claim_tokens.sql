-- Delete an account's claim tokens with the account.
--
-- `account_claim_tokens.user_pubkey` referenced `users(pubkey)` with the default
-- NO ACTION, so `DELETE FROM users` was rejected for any preloaded account that
-- still had a claim token. Production emitted
-- `update or delete on table "users" violates foreign key constraint
-- "account_claim_tokens_user_pubkey_fkey" on table "account_claim_tokens"`,
-- which rolled the whole deletion transaction back and left the user, personal
-- key, and authorizations intact.
--
-- A claim token only exists to hand its account to its owner. Once the account
-- is gone the token can never be redeemed, so it is owned by the account and
-- goes with it.

-- This is the first of three atomic migrations. Adding the replacement as NOT
-- VALID installs enforcement for new writes without scanning existing rows.
-- Validation and the final constraint swap happen in later transactions so
-- this migration does not retain its stronger locks during the validation scan.
SET LOCAL lock_timeout = '5s';

ALTER TABLE ONLY public.account_claim_tokens
    ADD CONSTRAINT account_claim_tokens_user_pubkey_cascade_fkey
    FOREIGN KEY (user_pubkey) REFERENCES public.users(pubkey)
    ON DELETE CASCADE NOT VALID;
