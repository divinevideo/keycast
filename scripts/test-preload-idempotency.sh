#!/bin/bash
# Test preload-user idempotency on Keycast
# Usage: ./test-preload-idempotency.sh [BASE_URL]
#
# Known Keycast URLs:
#   https://login.divine.video      (Cloud Run - production)
#   https://login.dvines.org        (GKE - production)
#   https://login.staging.dvines.org (GKE - staging)
#   https://login.poc.dvines.org    (GKE - POC)

set -e

BASE_URL="${1:-https://login.divine.video}"
VINE_ID="idempotency_test_$(date +%s)"

echo "Keycast Preload-User Idempotency Test"
echo "======================================"
echo ""
echo "Target URL: $BASE_URL"
echo ""

# Prompt for admin token if not set
if [ -z "$ADMIN_TOKEN" ]; then
  echo "Get an admin token from: ${BASE_URL}/admin"
  echo "(Login with NIP-07, then click 'Generate Admin Token')"
  echo ""
  read -p "Paste your ADMIN_TOKEN: " ADMIN_TOKEN
  echo ""
fi

if [ -z "$ADMIN_TOKEN" ]; then
  echo "Error: Admin token is required"
  exit 1
fi

echo "Testing preload-user idempotency on $BASE_URL"
echo "vine_id: $VINE_ID"
echo ""

# Call preload-user 3 times with same vine_id
PUBKEYS=()
for i in 1 2 3; do
  RESPONSE=$(curl -s -X POST "$BASE_URL/api/admin/preload-user" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"vine_id\": \"$VINE_ID\", \"username\": \"test_$VINE_ID\"}")

  PUBKEY=$(echo "$RESPONSE" | jq -r '.pubkey // empty')
  ERROR=$(echo "$RESPONSE" | jq -r '.error // empty')

  if [ -n "$ERROR" ] && [ "$ERROR" != "null" ]; then
    echo "Run $i: ERROR - $ERROR"
    exit 1
  fi

  echo "Run $i: $PUBKEY"
  PUBKEYS+=("$PUBKEY")
done

echo ""

# Verify all pubkeys match
if [ "${PUBKEYS[0]}" = "${PUBKEYS[1]}" ] && [ "${PUBKEYS[1]}" = "${PUBKEYS[2]}" ]; then
  echo "SUCCESS: Same pubkey returned all 3 times (idempotency works)"
  exit 0
else
  echo "FAILURE: Different pubkeys returned!"
  exit 1
fi
