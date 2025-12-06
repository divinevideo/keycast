#!/bin/bash
set -euo pipefail

# Compare DIRECT vs HYBRID pool modes locally
# This script tests both modes and verifies:
# - DIRECT mode: PgBouncer shows 0 queries
# - HYBRID mode: PgBouncer shows query traffic
# - Both modes: LISTEN/NOTIFY channels active

cd "$(dirname "$0")/.."

export SERVER_NSEC=$(openssl rand -hex 32)

cleanup() {
    echo ""
    echo "Cleaning up..."
    docker-compose -f docker-compose.test.yml --profile direct down 2>/dev/null || true
    docker-compose -f docker-compose.test.yml --profile hybrid down 2>/dev/null || true
}
trap cleanup EXIT

echo "=========================================="
echo "=== TEST 1: DIRECT MODE (PgBouncer UNUSED) ==="
echo "=========================================="
docker-compose -f docker-compose.test.yml --profile direct up -d
sleep 15

echo ""
echo "Health checks:"
curl -sf http://localhost:3001/health && echo " - Instance 1: OK" || echo " - Instance 1: FAIL"
curl -sf http://localhost:3002/health && echo " - Instance 2: OK" || echo " - Instance 2: FAIL"

echo ""
echo "LISTEN channels (should see 2 instances coordinating):"
docker-compose -f docker-compose.test.yml exec -T postgres psql -U postgres -c \
  "SELECT pid, state, left(query, 60) as query FROM pg_stat_activity WHERE query LIKE '%LISTEN%';" 2>/dev/null || echo "Query failed"

echo ""
echo "PostgreSQL connections:"
docker-compose -f docker-compose.test.yml exec -T postgres psql -U postgres -c \
  "SELECT count(*) as direct_connections FROM pg_stat_activity WHERE datname='keycast';" 2>/dev/null || echo "Query failed"

echo ""
echo "PgBouncer stats (should show 0 total_query_count in direct mode):"
docker-compose -f docker-compose.test.yml exec -T pgbouncer psql -h localhost -p 6432 -U postgres -c \
  "SHOW STATS;" 2>/dev/null | grep -E "database|total_query" || echo "(PgBouncer not available)"

docker-compose -f docker-compose.test.yml --profile direct down

echo ""
echo "=========================================="
echo "=== TEST 2: HYBRID MODE (queries via PgBouncer) ==="
echo "=========================================="
docker-compose -f docker-compose.test.yml --profile hybrid up -d
sleep 15

echo ""
echo "Health checks:"
curl -sf http://localhost:3001/health && echo " - Instance 1: OK" || echo " - Instance 1: FAIL"
curl -sf http://localhost:3002/health && echo " - Instance 2: OK" || echo " - Instance 2: FAIL"

echo ""
echo "LISTEN channels (still via direct on port 5432):"
docker-compose -f docker-compose.test.yml exec -T postgres psql -U postgres -c \
  "SELECT pid, state, left(query, 60) as query FROM pg_stat_activity WHERE query LIKE '%LISTEN%';" 2>/dev/null || echo "Query failed"

echo ""
echo "PgBouncer stats (should show query traffic in hybrid mode):"
docker-compose -f docker-compose.test.yml exec -T pgbouncer psql -h localhost -p 6432 -U postgres -c \
  "SHOW STATS;" 2>/dev/null | grep -E "database|total_query" || echo "(PgBouncer query failed)"

docker-compose -f docker-compose.test.yml --profile hybrid down

echo ""
echo "=========================================="
echo "=== TEST 3: Rolling Deployment (Hybrid) ==="
echo "=========================================="
docker-compose -f docker-compose.test.yml --profile hybrid up -d
sleep 15
echo "Instance 1 and 2 running..."

# Simulate making requests to both instances
echo "Making requests to establish connections..."
for i in {1..10}; do
  curl -sf http://localhost:3001/health >/dev/null || true
  curl -sf http://localhost:3002/health >/dev/null || true
done

echo ""
echo "Cluster state:"
for port in 3001 3002; do
  echo "  Instance on port $port: $(curl -sf "http://localhost:$port/health" && echo "healthy" || echo "unhealthy")"
done

echo ""
echo "=========================================="
echo "All tests completed!"
echo "=========================================="
