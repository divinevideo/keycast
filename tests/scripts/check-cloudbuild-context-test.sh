#!/usr/bin/env bash
set -euo pipefail

repo_root=$(git rev-parse --show-toplevel)
guard="$repo_root/scripts/check-cloudbuild-context.sh"
fake_bin="$repo_root/tests/fixtures/bin"
result_file=$(mktemp)
trap 'rm -f "$result_file"' EXIT

if [[ ! -x "$guard" ]]; then
	printf 'FAIL: expected executable guard at %s\n' "$guard" >&2
	exit 1
fi

run_guard() {
	local output=$1
	local status=$2

	PATH="$fake_bin:$PATH" \
		FAKE_GCLOUD_OUTPUT="$output" \
		FAKE_GCLOUD_STATUS="$status" \
		"$guard" >"$result_file" 2>&1
}

if ! run_guard $'.gcloudignore\npackage.json\n' 0; then
	printf 'FAIL: tracked upload paths should pass\n' >&2
	cat "$result_file" >&2
	exit 1
fi

if run_guard $'.gcloudignore\nuntracked-cloudbuild-context-file\n' 0; then
	printf 'FAIL: an untracked upload path should fail\n' >&2
	exit 1
fi

if ! grep -Fq 'untracked-cloudbuild-context-file' "$result_file"; then
	printf 'FAIL: rejection should name the untracked path\n' >&2
	cat "$result_file" >&2
	exit 1
fi

if run_guard '' 23; then
	printf 'FAIL: a gcloud listing error should fail closed\n' >&2
	exit 1
fi

if ! grep -Fq 'Could not determine Cloud Build upload files.' "$result_file"; then
	printf 'FAIL: gcloud failure should explain why the guard stopped\n' >&2
	cat "$result_file" >&2
	exit 1
fi

printf 'Cloud Build context guard tests passed.\n'
