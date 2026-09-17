#!/usr/bin/env bash
set -euo pipefail

repo_root=$(git rev-parse --show-toplevel)
cloudbuild="$repo_root/cloudbuild.yaml"
package_json="$repo_root/package.json"
sha_image='us-central1-docker.pkg.dev/${PROJECT_ID}/docker/keycast:${COMMIT_SHA}'
latest_image='us-central1-docker.pkg.dev/${PROJECT_ID}/docker/keycast:latest'

require_text() {
	local file=$1
	local text=$2

	if ! grep -Fq -- "$text" "$file"; then
		printf 'FAIL: expected %s to contain %s\n' "$file" "$text" >&2
		exit 1
	fi
}

reject_text() {
	local file=$1
	local text=$2

	if grep -Fq -- "$text" "$file"; then
		printf 'FAIL: expected %s not to contain %s\n' "$file" "$text" >&2
		exit 1
	fi
}

require_text "$cloudbuild" "- '$sha_image'"
require_text "$cloudbuild" "- '$latest_image'"
require_text "$cloudbuild" "- '--image=$sha_image'"
reject_text "$cloudbuild" "- '--image=$latest_image'"
require_text "$package_json" '--substitutions=COMMIT_SHA=$(git rev-parse HEAD)'
require_text "$package_json" '"deploy:gcp": "bun run deploy"'

printf 'Cloud Build immutable image tag tests passed.\n'
