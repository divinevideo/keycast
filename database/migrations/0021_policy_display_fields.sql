-- Add display fields to policies table for user-friendly permission descriptions
ALTER TABLE policies ADD COLUMN slug VARCHAR(50);
ALTER TABLE policies ADD COLUMN display_name VARCHAR(100);
ALTER TABLE policies ADD COLUMN description TEXT;

-- Update existing policies with user-friendly names
UPDATE policies SET
    slug = 'social',
    display_name = 'Social App',
    description = 'Post notes, reactions, and private messages'
WHERE name = 'Standard Social (Default)';

UPDATE policies SET
    slug = 'readonly',
    display_name = 'Read Only',
    description = 'View your profile only'
WHERE name = 'Read Only';

-- Each slug must be unique per tenant
CREATE UNIQUE INDEX policies_slug_unique ON policies (tenant_id, slug) WHERE slug IS NOT NULL;
