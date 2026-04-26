-- Register the invite admin dashboard as a first-party OAuth client.
-- Production Keycast requires registered OAuth clients, and the embedded
-- invite admin UI redirects back to https://invite.divine.video/admin.
INSERT INTO public.registered_clients (
    tenant_id,
    client_id,
    name,
    allowed_redirect_uris
)
VALUES (
    1,
    'divine-invite-admin',
    'Divine Invite Admin',
    ARRAY['https://invite.divine.video/admin']::TEXT[]
)
ON CONFLICT (tenant_id, client_id) DO UPDATE
SET
    name = EXCLUDED.name,
    allowed_redirect_uris = EXCLUDED.allowed_redirect_uris,
    updated_at = NOW();
