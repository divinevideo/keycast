-- ap_actor_keys: per-user RSA keypair for ActivityPub HTTP Signatures.
-- Separate from Nostr/secp256k1 keys (personal_keys/stored_keys): RSA is
-- variable-length PKCS#8 DER + an SPKI public PEM. Bound to the immutable
-- nostr_pubkey (1:1 per tenant), NOT the mutable username — a published
-- publicKeyPem is cached by remote fediverse servers.

CREATE TABLE public.ap_actor_keys (
    id                     bigserial PRIMARY KEY,
    user_pubkey            character(64) NOT NULL,
    tenant_id              bigint NOT NULL DEFAULT 1,
    encrypted_private_key  bytea NOT NULL,                 -- PKCS#8 DER, AES-256-GCM via KeyManager
    public_key_pem         text  NOT NULL,                 -- SPKI PEM, public, safe at rest
    key_type               text  NOT NULL DEFAULT 'rsa-2048',
    created_at             timestamp with time zone NOT NULL DEFAULT now(),
    updated_at             timestamp with time zone NOT NULL DEFAULT now(),
    CONSTRAINT ap_actor_keys_tenant_user_unique UNIQUE (tenant_id, user_pubkey)
);

CREATE INDEX idx_ap_actor_keys_tenant_user ON public.ap_actor_keys (tenant_id, user_pubkey);
