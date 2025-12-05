#!/bin/bash
set -euo pipefail

# Reset production database - USE WITH EXTREME CAUTION
# This drops all tables so migrations run fresh on next deploy

RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

PROJECT="openvine-co"

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

INSTANCE="openvine-co:us-central1:keycast-db"
# Use high port unlikely to conflict with anything
PROXY_PORT=54329

cleanup() {
    echo "Cleaning up proxy..."
    kill $PROXY_PID 2>/dev/null || true
    unset PGPASSWORD
}
trap cleanup EXIT

echo ""
echo "Fetching database credentials..."

# Extract password from DATABASE_URL secret (format: postgres://user:pass@host/db)
# Password is set via env var, never printed
export PGPASSWORD=$(gcloud secrets versions access latest --secret=keycast-database-url --project="$PROJECT" | sed 's|.*://[^:]*:\([^@]*\)@.*|\1|')

echo "Starting Cloud SQL Proxy (will auto-terminate when done)..."
cloud-sql-proxy "$INSTANCE" --port "$PROXY_PORT" &
PROXY_PID=$!

# Wait for proxy to be ready
sleep 2

echo "Resetting database..."
psql -h 127.0.0.1 -p "$PROXY_PORT" -U postgres -d keycast -c "DROP SCHEMA public CASCADE;"
psql -h 127.0.0.1 -p "$PROXY_PORT" -U postgres -d keycast -c "CREATE SCHEMA public;"
psql -h 127.0.0.1 -p "$PROXY_PORT" -U postgres -d keycast -c "GRANT ALL ON SCHEMA public TO postgres;"
psql -h 127.0.0.1 -p "$PROXY_PORT" -U postgres -d keycast -c "GRANT ALL ON SCHEMA public TO public;"

# Cleanup happens via trap

echo ""
echo -e "${YELLOW}Database reset complete. All tables dropped.${NC}"
echo "Next deploy will run migrations from scratch."
