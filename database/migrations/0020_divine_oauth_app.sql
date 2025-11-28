-- Add "divine" OAuth application for divine.video and Flutter app
INSERT INTO oauth_applications (
    client_id,
    client_secret,
    name,
    redirect_uris,
    policy_id,
    tenant_id,
    created_at,
    updated_at
)
VALUES (
    'divine',
    'public-client',
    'Divine Video',
    'https://divine.video/callback,http://localhost:5173/callback,http://localhost:3000/callback,divine://callback',
    (SELECT id FROM policies WHERE name = 'Standard Social (Default)' AND tenant_id = 1 LIMIT 1),
    1,
    NOW(),
    NOW()
)
ON CONFLICT (tenant_id, client_id)
DO UPDATE SET
    client_secret = EXCLUDED.client_secret,
    name = EXCLUDED.name,
    redirect_uris = EXCLUDED.redirect_uris,
    policy_id = EXCLUDED.policy_id,
    updated_at = NOW();
