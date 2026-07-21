#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
benchmark_script="$repo_root/tools/benchmark-email-trgm-inserts.sh"

help_output="$($benchmark_script --help)"

grep -q -- "--database-url" <<<"$help_output"
grep -q -- "--clients" <<<"$help_output"
grep -q -- "--transactions" <<<"$help_output"
grep -q -- "--baseline-rows" <<<"$help_output"
grep -q -- "isolated benchmark schema" <<<"$help_output"
grep -q -- "migration index build duration" <<<"$help_output"
grep -q -- "migration_index_build_ms=" "$benchmark_script"
grep -q -- "LIMIT 100;" "$benchmark_script"

assert_remote_database_rejected() {
    local database_url="$1"
    local output

    if output="$($benchmark_script --database-url "$database_url" 2>&1)"; then
        echo "Expected remote database URL to be rejected: $database_url" >&2
        exit 1
    fi

    grep -q -- "Refusing to benchmark a non-local database" <<<"$output"
}

assert_remote_database_rejected "postgres://localhost:password@remote.invalid/keycast"
assert_remote_database_rejected "postgres://user:password@remote.invalid/localhost"
assert_remote_database_rejected \
    "postgres://user:password@remote.invalid/keycast?application_name=localhost"
assert_remote_database_rejected "postgres://user:password@localhost.invalid/keycast"
