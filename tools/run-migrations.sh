#!/bin/bash
set -e

# Run SQLx migrations against Cloud SQL using Cloud SQL Auth Proxy
# Prerequisites:
#   - cloud-sql-proxy in PATH (brew install cloud-sql-proxy or download from Google)
#   - sqlx-cli installed (cargo install sqlx-cli)

# --- CONFIGURATION ---
PROJECT_ID="openvine-co"
REGION="us-central1"
INSTANCE_NAME="keycast-db-plus"
CONNECTION_NAME="$PROJECT_ID:$REGION:$INSTANCE_NAME"

DB_USER="postgres"
DB_NAME="keycast"
DB_PORT="${DB_PORT:-15432}"  # Non-standard port to avoid conflicts with local PostgreSQL
# ---------------------

# Find cloud-sql-proxy binary
PROXY_BIN=$(command -v cloud-sql-proxy 2>/dev/null || echo "/tmp/cloud-sql-proxy")
if [ ! -x "$PROXY_BIN" ]; then
    echo "❌ cloud-sql-proxy not found. Install it:"
    echo "   curl -o /tmp/cloud-sql-proxy https://storage.googleapis.com/cloud-sql-connectors/cloud-sql-proxy/v2.14.0/cloud-sql-proxy.linux.amd64 && chmod +x /tmp/cloud-sql-proxy"
    exit 1
fi

# 1. Auto-Detect DATABASE_URL from Secret Manager
# Use the full URL (rewritten to proxy host) instead of extracting password,
# which avoids shell escaping issues with special characters in passwords.
if [ -z "$DB_URL" ]; then
    echo "🔍 Auto-detecting database credentials..."

    DB_URL=$(gcloud secrets versions access latest --secret="keycast-database-url" --project=$PROJECT_ID 2>/dev/null || true)

    if [ -n "$DB_URL" ]; then
        echo "✅ Found DATABASE_URL from Secret Manager!"
    else
        echo "⚠️  Could not auto-detect credentials."
        read -s -p "🔑 Enter DB Password manually: " DB_PASS
        echo ""
    fi
fi

# 2. Start Cloud SQL Auth Proxy in the background
echo "🔌 Starting Cloud SQL Auth Proxy for [$CONNECTION_NAME]..."

"$PROXY_BIN" "$CONNECTION_NAME" --port $DB_PORT --quiet 2>&1 >&2 &
PROXY_PID=$!

# Cleanup function to stop proxy on exit
cleanup() {
    echo "🧹 Stopping Cloud SQL Auth Proxy..."
    kill $PROXY_PID 2>/dev/null || true
}
trap cleanup EXIT

# 3. Wait for the Proxy to be ready (using bash built-in instead of nc)
echo "⏳ Waiting for proxy to establish connection..."
for i in {1..30}; do
    if (echo > /dev/tcp/127.0.0.1/$DB_PORT) 2>/dev/null; then
        echo "✅ Proxy is ready on localhost:$DB_PORT"
        break
    fi
    sleep 1
done

# 4. Run the SQLx Migration
echo "🚀 Running SQLx Migrations..."

if [ -n "$DB_URL" ]; then
    # Rewrite host in DATABASE_URL to point at the local proxy
    export DATABASE_URL=$(echo "$DB_URL" | sed -E "s/@[^/]+\//@127.0.0.1:$DB_PORT\//")
else
    export DATABASE_URL="postgres://$DB_USER:$DB_PASS@127.0.0.1:$DB_PORT/$DB_NAME?sslmode=disable"
fi

# Change to project root to find migrations
cd "$(dirname "$0")/.."

sqlx migrate run --source database/migrations

echo "✨ Migrations complete!"
