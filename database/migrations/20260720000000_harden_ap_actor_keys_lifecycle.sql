-- Harden AP RSA key custody lifecycle.
-- AP keys must be removed with their user account, and the UNIQUE constraint
-- already provides the lookup index for (tenant_id, user_pubkey).

DELETE FROM public.ap_actor_keys ak
WHERE NOT EXISTS (
    SELECT 1
    FROM public.users u
    WHERE u.pubkey = ak.user_pubkey
      AND u.tenant_id = ak.tenant_id
);

DROP INDEX IF EXISTS public.idx_ap_actor_keys_tenant_user;

ALTER TABLE ONLY public.ap_actor_keys
    ADD CONSTRAINT ap_actor_keys_tenant_id_fkey
    FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pubkey_tenant_unique UNIQUE (pubkey, tenant_id);

ALTER TABLE ONLY public.ap_actor_keys
    ADD CONSTRAINT ap_actor_keys_user_pubkey_fkey
    FOREIGN KEY (user_pubkey, tenant_id) REFERENCES public.users(pubkey, tenant_id) ON DELETE CASCADE;
