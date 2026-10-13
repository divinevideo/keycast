-- Let apps on the social policy publish a person's linked-accounts list.
--
-- Linked accounts (NIP-39 `i` tags) used to live in the kind 0 profile, which the
-- social policy allows. They now live in kind 10011, which it did not, so signing
-- that list was refused for every app that signs in with `policy:social`. Kind
-- 10011 is a public, replaceable list, comparable to the profile and contact list
-- these apps can already write.
--
-- The kind is added to the existing permission rather than through a second
-- permission: a policy allows an event only when every one of its permissions
-- does, so a second allowed-kinds permission would refuse every kind, because no
-- kind would be on both lists.
--
-- Only a row that holds a list of kinds is touched, and only once. A missing or
-- null `allowed_kinds` means any kind is allowed, so such a row is left as it is.
-- `config` is stored as text.
UPDATE permissions
SET config = jsonb_set(
        config::jsonb,
        '{allowed_kinds}',
        (config::jsonb -> 'allowed_kinds') || '[10011]'::jsonb
    )::text,
    updated_at = NOW()
WHERE identifier = 'allowed_kinds_social_messaging'
  AND jsonb_typeof(config::jsonb -> 'allowed_kinds') = 'array'
  AND NOT (config::jsonb -> 'allowed_kinds') @> '[10011]'::jsonb;
