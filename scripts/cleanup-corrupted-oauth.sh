#!/bin/bash
# Cleanup corrupted OAuth authorization from Cloud SQL

set -e

PROJECT="openvine-co"
INSTANCE="keycast-db"
PUBKEY="7d2d7b55337d06dc0c0ac2f66f8a73da020af29a2cdc1e348387071efcf332b2"

echo "🧹 Cleaning up corrupted OAuth authorization for pubkey: ${PUBKEY:0:16}..."
echo ""
echo "You'll need to enter the postgres password when prompted."
echo "Get it from: gcloud secrets versions access latest --secret=keycast-database-url --project=$PROJECT"
echo ""
echo "Connecting to Cloud SQL..."

gcloud sql connect $INSTANCE --user=postgres --project=$PROJECT <<SQL
DELETE FROM oauth_authorizations WHERE user_public_key = '$PUBKEY';
DELETE FROM personal_keys WHERE user_public_key = '$PUBKEY';
SELECT COUNT(*) as "Remaining records" FROM oauth_authorizations WHERE user_public_key = '$PUBKEY';
SELECT COUNT(*) as "Total OAuth authorizations" FROM oauth_authorizations;
\q
SQL

echo ""
echo "✅ Cleanup complete!"
