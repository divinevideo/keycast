#!/bin/bash
set -euo pipefail

# Reset production database - USE WITH EXTREME CAUTION
# This drops all tables so migrations run fresh on next deploy

RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${RED}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${RED}║  WARNING: This will DELETE ALL DATA in PRODUCTION database ║${NC}"
echo -e "${RED}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${YELLOW}To confirm, type exactly: RESET PRODUCTION DATABASE${NC}"
echo ""
read -p "> " confirmation

if [ "$confirmation" != "RESET PRODUCTION DATABASE" ]; then
    echo "Aborted. Confirmation did not match."
    exit 1
fi

echo ""
echo "Fetching database URL from GCP Secret Manager..."
DATABASE_URL=$(gcloud secrets versions access latest --secret=keycast-database-url --project=openvine-co)

echo "Connecting to production database and dropping all tables..."
psql "$DATABASE_URL" <<EOF
-- Drop all tables in public schema
DROP SCHEMA public CASCADE;
CREATE SCHEMA public;
GRANT ALL ON SCHEMA public TO postgres;
GRANT ALL ON SCHEMA public TO public;
EOF

echo ""
echo -e "${YELLOW}Database reset complete. All tables dropped.${NC}"
echo "Next deploy will run migrations from scratch."
