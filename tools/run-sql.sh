#!/bin/bash
set -e

# Run arbitrary SQL against Cloud SQL using Cloud SQL Auth Proxy
# Prerequisites:
#   - cloud-sql-proxy in PATH (brew install cloud-sql-proxy or download from Google)
#   - psql installed (brew install postgresql or apt install postgresql-client)
#
# Usage:
#   ./run-sql.sh "SELECT count(*) FROM users;"
#   echo "SELECT 1;" | ./run-sql.sh
#   ./run-sql.sh < migration.sql
#
# Note: This connects directly to PostgreSQL (port 5432), NOT via the PgBouncer pooler.
# The production app uses the pooler on 10.58.0.3:6432 (private IP, inaccessible locally).
# Query Insights times will differ from direct execution due to pooler queue time.

# --- CONFIGURATION ---
PROJECT_ID="openvine-co"
REGION="us-central1"
INSTANCE_NAME="keycast-db-plus"
CONNECTION_NAME="$PROJECT_ID:$REGION:$INSTANCE_NAME"

DB_USER="postgres"
DB_NAME="keycast"
DB_PORT="15432"  # Non-standard port to avoid conflicts with local PostgreSQL
# ---------------------

# Find cloud-sql-proxy binary
PROXY_BIN=$(command -v cloud-sql-proxy 2>/dev/null || echo "/tmp/cloud-sql-proxy")
if [ ! -x "$PROXY_BIN" ]; then
    echo "❌ cloud-sql-proxy not found. Install it:" >&2
    echo "   curl -o /tmp/cloud-sql-proxy https://storage.googleapis.com/cloud-sql-connectors/cloud-sql-proxy/v2.14.0/cloud-sql-proxy.linux.amd64 && chmod +x /tmp/cloud-sql-proxy" >&2
    exit 1
fi

# 1. Auto-Detect Password from Secret Manager
if [ -z "$DB_PASS" ]; then
    echo "🔍 Auto-detecting database credentials..." >&2

    DB_URL=$(gcloud secrets versions access latest --secret="keycast-database-url" --project=$PROJECT_ID 2>/dev/null || true)

    if [[ "$DB_URL" =~ ://[^:]+:([^@]+)@ ]]; then
        DB_PASS="${BASH_REMATCH[1]}"
        echo "✅ Found password from Secret Manager!" >&2
    else
        echo "⚠️  Could not auto-detect password." >&2
        read -s -p "🔑 Enter DB Password manually: " DB_PASS
        echo "" >&2
    fi
fi

# 2. Prepare SQL input
if [ -n "$1" ]; then
    # Case A: Argument provided (./run-sql.sh "SELECT 1;")
    SQL_QUERY="$1"
elif [ ! -t 0 ]; then
    # Case B: Stdin exists (Pipe or Redirection)
    SQL_QUERY=$(cat)
else
    echo "❌ Error: No input provided." >&2
    echo "Usage:" >&2
    echo "  ./run-sql.sh \"SELECT count(*) FROM users;\"" >&2
    echo "  echo \"SELECT 1;\" | ./run-sql.sh" >&2
    echo "  ./run-sql.sh < migration.sql" >&2
    exit 1
fi

# 3. Start Cloud SQL Auth Proxy in the background
echo "🔌 Starting Cloud SQL Auth Proxy..." >&2

"$PROXY_BIN" "$CONNECTION_NAME" --port $DB_PORT --gcloud-auth --quiet 2>&1 >&2 &
PROXY_PID=$!

# Cleanup function to stop proxy on exit
cleanup() {
    kill $PROXY_PID 2>/dev/null || true
}
trap cleanup EXIT

# 4. Wait for the Proxy to be ready (using bash built-in instead of nc)
echo "⏳ Waiting for proxy..." >&2
for i in {1..30}; do
    if (echo > /dev/tcp/127.0.0.1/$DB_PORT) 2>/dev/null; then
        echo "✅ Connected!" >&2
        break
    fi
    sleep 1
done

# 5. Execute SQL
echo "🚀 Executing SQL..." >&2
export PGPASSWORD="$DB_PASS"
echo "$SQL_QUERY" | psql -h 127.0.0.1 -p $DB_PORT -U $DB_USER -d $DB_NAME -f -

echo "✨ Done!" >&2
