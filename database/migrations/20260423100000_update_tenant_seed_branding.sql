-- Fix seed tenant branding: "diVine" → "Divine"
-- Only updates the seed row (id=1). Non-seed tenant names are tenant-owned.
UPDATE tenants SET name = 'Divine', updated_at = NOW() WHERE id = 1 AND name = 'diVine';
