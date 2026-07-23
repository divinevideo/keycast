#!/usr/bin/env bash
set -euo pipefail

if ! command -v git >/dev/null 2>&1; then
	printf 'Cloud Build context check requires git.\n' >&2
	exit 1
fi

if ! command -v gcloud >/dev/null 2>&1; then
	printf 'Cloud Build context check requires gcloud.\n' >&2
	exit 1
fi

if ! repo_root=$(git rev-parse --show-toplevel 2>/dev/null); then
	printf 'Cloud Build context check must run inside a Git worktree.\n' >&2
	exit 1
fi

cd "$repo_root"

upload_list=$(mktemp)
trap 'rm -f "$upload_list"' EXIT

if ! gcloud meta list-files-for-upload . >"$upload_list"; then
	printf 'Could not determine Cloud Build upload files. Refusing to deploy.\n' >&2
	exit 1
fi

uploaded_count=0
untracked_paths=()

while IFS= read -r path; do
	[[ -z "$path" ]] && continue
	uploaded_count=$((uploaded_count + 1))

	if ! git ls-files --error-unmatch -- "$path" >/dev/null 2>&1; then
		untracked_paths+=("$path")
	fi
done <"$upload_list"

if ((${#untracked_paths[@]} > 0)); then
	printf 'Cloud Build would upload files that are not tracked by Git:\n' >&2
	printf '  %s\n' "${untracked_paths[@]}" >&2
	printf 'Refusing to deploy. Update ignore rules or remove these files.\n' >&2
	exit 1
fi

printf 'Cloud Build context is clean: %d tracked files.\n' "$uploaded_count"
