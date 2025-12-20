-- Migration: Remove hardcoded relay.damus.io from tenant settings
-- After this migration, tenants without a relay setting will use BUNKER_RELAYS env var
-- This fixes tenants that were auto-provisioned with the old hardcoded default

-- Remove the relay field from settings for tenants using relay.damus.io
-- This allows the application to use BUNKER_RELAYS environment variable as fallback
UPDATE tenants
SET settings = (settings::jsonb - 'relay')::text,
    updated_at = NOW()
WHERE settings IS NOT NULL
  AND settings::jsonb->>'relay' = 'wss://relay.damus.io';


