#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
benchmark_script="$repo_root/tools/benchmark-email-trgm-inserts.sh"

help_output="$($benchmark_script --help)"

grep -q -- "--database-url" <<<"$help_output"
grep -q -- "--clients" <<<"$help_output"
grep -q -- "--transactions" <<<"$help_output"
grep -q -- "--explain-rows" <<<"$help_output"
grep -q -- "isolated benchmark schema" <<<"$help_output"
