#!/bin/sh
set -eu

usage() {
  cat <<'EOF'
Usage:
  auth-debug.sh --base-url https://login.divine.video --token <admin-token> [--email <email> | --pubkey <hex> | --npub <npub> | --request-id <id>]

Options:
  --base-url     Keycast base URL, defaults to https://login.divine.video
  --token        Support-admin or full-admin bearer token
  --email        Email address to inspect
  --pubkey       Hex pubkey to inspect
  --npub         npub to inspect
  --request-id   Request ID to inspect
EOF
}

base_url="https://login.divine.video"
token=""
email=""
pubkey=""
npub=""
request_id=""

while [ "$#" -gt 0 ]; do
  case "$1" in
    --base-url)
      base_url="$2"
      shift 2
      ;;
    --token)
      token="$2"
      shift 2
      ;;
    --email)
      email="$2"
      shift 2
      ;;
    --pubkey)
      pubkey="$2"
      shift 2
      ;;
    --npub)
      npub="$2"
      shift 2
      ;;
    --request-id)
      request_id="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [ -z "$token" ]; then
  echo "--token is required" >&2
  usage >&2
  exit 1
fi

query_count=0
[ -n "$email" ] && query_count=$((query_count + 1))
[ -n "$pubkey" ] && query_count=$((query_count + 1))
[ -n "$npub" ] && query_count=$((query_count + 1))
[ -n "$request_id" ] && query_count=$((query_count + 1))

if [ "$query_count" -eq 0 ]; then
  echo "Provide at least one of --email, --pubkey, --npub, or --request-id" >&2
  usage >&2
  exit 1
fi

query=""
append_query() {
  key="$1"
  value="$2"
  if [ -n "$query" ]; then
    query="${query}&"
  fi
  query="${query}${key}=$(printf '%s' "$value" | jq -sRr @uri)"
}

[ -n "$email" ] && append_query "email" "$email"
[ -n "$pubkey" ] && append_query "pubkey" "$pubkey"
[ -n "$npub" ] && append_query "npub" "$npub"
[ -n "$request_id" ] && append_query "request_id" "$request_id"

curl --fail --silent --show-error \
  -H "Authorization: Bearer ${token}" \
  "${base_url%/}/api/admin/auth-debug?${query}"
