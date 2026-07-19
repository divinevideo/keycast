#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Benchmark users-table INSERT throughput with and without the email trigram GIN index.

The benchmark clones public.users into an isolated benchmark schema, preserving its
baseline indexes without writing to application rows. The schema is removed on exit.

Usage:
  tools/benchmark-email-trgm-inserts.sh --database-url URL [options]

Options:
  --database-url URL    Local PostgreSQL URL (or set DATABASE_URL)
  --clients N           Concurrent pgbench clients (default: 4)
  --transactions N      Transactions per client and per configuration (default: 10000)
  --baseline-rows N     Preloaded rows per configuration and for EXPLAIN (default: 400000)
  --help                Show this help
EOF
}

benchmark_database_url="${DATABASE_URL:-}"
benchmark_clients=4
benchmark_transactions=10000
benchmark_baseline_rows=400000
benchmark_schema="email_trgm_benchmark"
benchmark_workload="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/email-trgm-insert-workload.sql"

while (($# > 0)); do
    case "$1" in
        --database-url)
            benchmark_database_url="${2:-}"
            shift 2
            ;;
        --clients)
            benchmark_clients="${2:-}"
            shift 2
            ;;
        --transactions)
            benchmark_transactions="${2:-}"
            shift 2
            ;;
        --baseline-rows)
            benchmark_baseline_rows="${2:-}"
            shift 2
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            echo "Unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if [[ -z "$benchmark_database_url" ]]; then
    echo "--database-url or DATABASE_URL is required" >&2
    exit 2
fi

database_authority="${benchmark_database_url#*://}"
if [[ "$database_authority" == "$benchmark_database_url" ]]; then
    echo "Refusing to benchmark a non-local database" >&2
    exit 2
fi
database_authority="${database_authority%%/*}"
database_authority="${database_authority%%\?*}"
database_authority="${database_authority%%\#*}"
database_host_and_port="${database_authority##*@}"
database_host="${database_host_and_port%%:*}"
database_host="$(printf '%s' "$database_host" | tr '[:upper:]' '[:lower:]')"

case "$database_host" in
    localhost|127.0.0.1) ;;
    *)
        echo "Refusing to benchmark a non-local database" >&2
        exit 2
        ;;
esac

if [[ ! "$benchmark_clients" =~ ^[1-9][0-9]*$ ]]; then
    echo "--clients must be a positive integer" >&2
    exit 2
fi
if [[ ! "$benchmark_transactions" =~ ^[1-9][0-9]*$ ]]; then
    echo "--transactions must be a positive integer" >&2
    exit 2
fi
if [[ ! "$benchmark_baseline_rows" =~ ^[1-9][0-9]*$ ]]; then
    echo "--baseline-rows must be a positive integer" >&2
    exit 2
fi

for required_command in psql pgbench; do
    if ! command -v "$required_command" >/dev/null 2>&1; then
        echo "$required_command is required" >&2
        exit 2
    fi
done
if [[ ! -f "$benchmark_workload" ]]; then
    echo "Benchmark workload not found: $benchmark_workload" >&2
    exit 2
fi

cleanup() {
    psql "$benchmark_database_url" \
        --set=ON_ERROR_STOP=1 \
        --command="DROP SCHEMA IF EXISTS $benchmark_schema CASCADE" \
        >/dev/null 2>&1 || true
}
trap cleanup EXIT

cleanup

psql "$benchmark_database_url" \
    --set=ON_ERROR_STOP=1 \
    --set=benchmark_schema="$benchmark_schema" <<'SQL'
CREATE SCHEMA :"benchmark_schema";
CREATE TABLE :"benchmark_schema".users (LIKE public.users INCLUDING ALL);
CREATE SEQUENCE :"benchmark_schema".user_sequence;

SELECT format('DROP INDEX %I.%I', schemaname, indexname)
FROM pg_indexes
WHERE schemaname = :'benchmark_schema'
  AND tablename = 'users'
  AND indexdef LIKE '%gin_trgm_ops%'
\gexec
SQL

run_benchmark() {
    local configuration="$1"
    local pgbench_output
    local latency_ms
    local tps

    pgbench_output="$(LC_ALL=C pgbench \
        --no-vacuum \
        --client="$benchmark_clients" \
        --jobs="$benchmark_clients" \
        --transactions="$benchmark_transactions" \
        --file="$benchmark_workload" \
        "$benchmark_database_url" 2>&1)"

    latency_ms="$(awk '$1 == "latency" && $2 == "average" { value = $4 } END { print value }' <<<"$pgbench_output")"
    tps="$(awk '$1 == "tps" && $2 == "=" { value = $3 } END { print value }' <<<"$pgbench_output")"
    if [[ -z "$latency_ms" || -z "$tps" ]]; then
        echo "$pgbench_output" >&2
        echo "Unable to parse pgbench output" >&2
        exit 1
    fi

    printf '%s_latency_ms=%s\n' "$configuration" "$latency_ms"
    printf '%s_tps=%s\n' "$configuration" "$tps"
}

populate_baseline() {
    psql "$benchmark_database_url" \
        --set=ON_ERROR_STOP=1 \
        --set=benchmark_schema="$benchmark_schema" \
        --set=baseline_rows="$benchmark_baseline_rows" <<'SQL' >/dev/null
TRUNCATE TABLE :"benchmark_schema".users;
ALTER SEQUENCE :"benchmark_schema".user_sequence RESTART WITH 1;

INSERT INTO :"benchmark_schema".users (
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
FROM generate_series(1, :baseline_rows) AS value;

SELECT setval(
    format('%I.user_sequence', :'benchmark_schema')::regclass,
    :baseline_rows,
    true
);
SQL
}

total_inserts=$((benchmark_clients * benchmark_transactions))
rows_after_timed_inserts=$((benchmark_baseline_rows + total_inserts))
echo "postgres_version=$(psql "$benchmark_database_url" --tuples-only --no-align --command='SHOW server_version')"
echo "clients=$benchmark_clients"
echo "transactions_per_client=$benchmark_transactions"
echo "inserts_per_configuration=$total_inserts"
echo "baseline_rows_per_configuration=$benchmark_baseline_rows"
echo "rows_after_timed_inserts=$rows_after_timed_inserts"

populate_baseline
without_gin_results="$(run_benchmark without_gin)"
echo "$without_gin_results"
without_gin_tps="$(awk -F= '$1 == "without_gin_tps" { print $2 }' <<<"$without_gin_results")"

populate_baseline
psql "$benchmark_database_url" \
    --set=ON_ERROR_STOP=1 \
    --set=benchmark_schema="$benchmark_schema" <<'SQL' >/dev/null
CREATE INDEX idx_users_email_trgm
    ON :"benchmark_schema".users USING gin (email gin_trgm_ops)
    WHERE email IS NOT NULL;
SQL

with_gin_results="$(run_benchmark with_gin)"
echo "$with_gin_results"
with_gin_tps="$(awk -F= '$1 == "with_gin_tps" { print $2 }' <<<"$with_gin_results")"

throughput_change_percent="$(awk \
    -v without_gin="$without_gin_tps" \
    -v with_gin="$with_gin_tps" \
    'BEGIN { printf "%.2f", ((with_gin - without_gin) / without_gin) * 100 }')"
echo "throughput_change_percent=$throughput_change_percent"

psql "$benchmark_database_url" \
    --set=ON_ERROR_STOP=1 \
    --set=benchmark_schema="$benchmark_schema" <<'SQL'
ANALYZE :"benchmark_schema".users;

SELECT 'gin_index_size_bytes=' || pg_relation_size(format('%I.idx_users_email_trgm', :'benchmark_schema')::regclass);

\echo substring_explain
EXPLAIN (ANALYZE, BUFFERS)
SELECT pubkey
FROM :"benchmark_schema".users
WHERE email IS NOT NULL
  AND email ILIKE '%needle-fragment%';

\echo similarity_explain
EXPLAIN (ANALYZE, BUFFERS)
SELECT pubkey
FROM :"benchmark_schema".users
WHERE email IS NOT NULL
  AND email % 'needle-fragment@rare.test'
ORDER BY similarity(email, 'needle-fragment@rare.test') DESC
LIMIT 5;
SQL
