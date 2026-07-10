-- Register Divine Crossposter as a first-party OAuth client.
INSERT INTO public.registered_clients (
    tenant_id,
    client_id,
    name,
    allowed_redirect_uris
)
VALUES (
    1,
    'Divine Crossposter',
    'Divine Crossposter',
    ARRAY['https://crossposter.divine.video/']::TEXT[]
)
ON CONFLICT (tenant_id, client_id) DO UPDATE
SET
    name = EXCLUDED.name,
    allowed_redirect_uris = EXCLUDED.allowed_redirect_uris,
    updated_at = NOW();
