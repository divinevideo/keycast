WITH benchmark_id AS (
    SELECT nextval('email_trgm_benchmark.user_sequence') AS value
)
INSERT INTO email_trgm_benchmark.users (
    pubkey,
    tenant_id,
    email,
    email_verified,
    created_at,
    updated_at
)
SELECT
    lpad(to_hex(value), 64, '0'),
    1,
    CASE
        WHEN value % 10000 = 0 THEN 'needle-fragment-' || value || '@rare.test'
        ELSE 'benchmark-' || value || '@example.test'
    END,
    true,
    clock_timestamp(),
    clock_timestamp()
FROM benchmark_id;
