-- Migration: Simplify oauth_applications
-- Move client_id (app name) directly to oauth_authorizations and oauth_codes
-- Remove unnecessary oauth_applications join table

-- Step 1: Add client_id column to oauth_authorizations
ALTER TABLE oauth_authorizations ADD COLUMN IF NOT EXISTS client_id TEXT;

-- Step 2: Migrate existing data from oauth_applications.name
UPDATE oauth_authorizations oa
SET client_id = COALESCE(
    (SELECT name FROM oauth_applications WHERE id = oa.application_id),
    oa.redirect_origin  -- fallback to redirect_origin if no app found
)
WHERE client_id IS NULL;

-- Step 3: For any remaining nulls, use redirect_origin
UPDATE oauth_authorizations
SET client_id = COALESCE(client_id, redirect_origin, 'Unknown App')
WHERE client_id IS NULL;

-- Step 4: Add client_id column to oauth_codes (temporary storage during OAuth flow)
ALTER TABLE oauth_codes ADD COLUMN IF NOT EXISTS client_id TEXT;

-- Step 5: For existing codes, migrate from oauth_applications (most will have expired anyway)
UPDATE oauth_codes oc
SET client_id = COALESCE(
    (SELECT name FROM oauth_applications WHERE id = oc.application_id),
    'Unknown App'
)
WHERE client_id IS NULL;

-- Step 6: Drop the application_id columns
ALTER TABLE oauth_authorizations DROP COLUMN IF EXISTS application_id;
ALTER TABLE oauth_codes DROP COLUMN IF EXISTS application_id;

-- Step 7: Drop oauth_applications table (no longer needed)
DROP TABLE IF EXISTS oauth_applications CASCADE;

-- Step 8: Drop the sequence for oauth_applications
DROP SEQUENCE IF EXISTS oauth_applications_id_seq;
