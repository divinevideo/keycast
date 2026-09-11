#!/usr/bin/env bash
set -euo pipefail

repo_root=$(git rev-parse --show-toplevel)
source_guard="$repo_root/scripts/check-cloudbuild-context.sh"
fake_bin="$repo_root/tests/fixtures/bin"
result_file=$(mktemp)
test_repo=$(mktemp -d)
trap 'rm -f "$result_file"; rm -rf "$test_repo"' EXIT

if [[ ! -x "$source_guard" ]]; then
	printf 'FAIL: expected executable guard at %s\n' "$source_guard" >&2
	exit 1
fi

cp "$source_guard" "$test_repo/check-cloudbuild-context.sh"
touch "$test_repo/.gcloudignore" "$test_repo/package.json"
git -C "$test_repo" init --quiet
git -C "$test_repo" add .
git -C "$test_repo" -c user.name='Keycast Tests' -c user.email='tests@keycast.invalid' -c commit.gpgsign=false commit --quiet -m fixture
guard="$test_repo/check-cloudbuild-context.sh"

run_guard() {
	local output=$1
	local status=$2

	(
		cd "$test_repo"
		PATH="$fake_bin:$PATH" \
			FAKE_GCLOUD_OUTPUT="$output" \
			FAKE_GCLOUD_STATUS="$status" \
			"$guard"
	) >"$result_file" 2>&1
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

printf '\n' >>"$test_repo/package.json"
if run_guard $'.gcloudignore\npackage.json\n' 0; then
	printf 'FAIL: modified tracked content should fail\n' >&2
	exit 1
fi

if ! grep -Fq 'Refusing to assign a commit image tag to modified tracked content.' "$result_file"; then
	printf 'FAIL: tracked-content rejection should explain the tag mismatch\n' >&2
	cat "$result_file" >&2
	exit 1
fi

printf 'Cloud Build context guard tests passed.\n'
