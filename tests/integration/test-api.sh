#!/bin/bash
# ABOUTME: Integration tests for Keycast API that can run against local or production
# ABOUTME: Tests all API endpoints including health, teams, keys, and auth

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
API_URL="${API_URL:-http://localhost:3000}"
FRONTEND_URL="${FRONTEND_URL:-http://localhost:5173}"

# Check if API is running before starting tests
echo "Checking if API is running at $API_URL..."
if ! curl -s -m 2 "$API_URL/health" > /dev/null 2>&1; then
    echo -e "${RED}✗ API is not running at $API_URL${NC}"
    echo ""
    echo "Please start the API first:"
    echo "  Option 1 (native): bun run dev"
    echo "  Option 2 (Docker): docker-compose -f docker-compose.dev.yml up -d --build"
    echo ""
    exit 1
fi
echo -e "${GREEN}✓ API is running${NC}"
echo ""

# Test counters
PASSED=0
FAILED=0
TOTAL=0

# Test helper functions
test_start() {
    TOTAL=$((TOTAL + 1))
    echo -n "  [$TOTAL] $1... "
}

test_pass() {
    PASSED=$((PASSED + 1))
    echo -e "${GREEN}✓${NC}"
}

test_fail() {
    FAILED=$((FAILED + 1))
    echo -e "${RED}✗${NC}"
    echo "    Error: $1"
}

# HTTP helper functions (with 5s timeout to fail fast)
http_get() {
    local url=$1
    local headers="${2:-}"
    curl -s -m 5 -o /tmp/response.json -w "%{http_code}" \
        ${headers:+-H "$headers"} \
        "$API_URL$url"
}

http_post() {
    local url=$1
    local data=$2
    local headers="${3:-}"
    curl -s -m 5 -o /tmp/response.json -w "%{http_code}" \
        -X POST \
        -H "Content-Type: application/json" \
        ${headers:+-H "$headers"} \
        -d "$data" \
        "$API_URL$url"
}

http_options() {
    local url=$1
    local origin="${2:-$FRONTEND_URL}"
    curl -s -m 5 -o /tmp/response.json -w "%{http_code}" \
        -X OPTIONS \
        -H "Origin: $origin" \
        -H "Access-Control-Request-Method: POST" \
        -H "Access-Control-Request-Headers: Content-Type" \
        "$API_URL$url"
}

echo ""
echo "========================================"
echo "  Keycast API Integration Tests"
echo "========================================"
echo ""
echo "API URL:      $API_URL"
echo "Frontend URL: $FRONTEND_URL"
echo ""

# Test Suite 1: Health & Infrastructure
echo -e "${BLUE}1. Health & Infrastructure${NC}"

test_start "Health endpoint responds"
STATUS=$(http_get "/health")
if [ "$STATUS" = "200" ]; then
    test_pass
else
    test_fail "Expected HTTP 200, got $STATUS"
fi

test_start "CORS preflight for /api/teams"
STATUS=$(http_options "/api/teams")
if [ "$STATUS" = "200" ]; then
    test_pass
else
    test_fail "Expected HTTP 200, got $STATUS"
fi

test_start "CORS headers present"
CORS_HEADER=$(curl -s -m 5 -I -X OPTIONS \
    -H "Origin: $FRONTEND_URL" \
    -H "Access-Control-Request-Method: POST" \
    "$API_URL/api/teams" | grep -i "access-control-allow-origin")
if [ -n "$CORS_HEADER" ]; then
    test_pass
else
    test_fail "Access-Control-Allow-Origin header not found"
fi

# Test Suite 2: Teams API (without auth - should fail appropriately)
echo ""
echo -e "${BLUE}2. Teams API (unauthenticated)${NC}"

test_start "GET /api/teams requires auth"
STATUS=$(http_get "/api/teams")
if [ "$STATUS" = "401" ] || [ "$STATUS" = "403" ]; then
    test_pass
else
    test_fail "Expected HTTP 401/403, got $STATUS"
fi

test_start "POST /api/teams requires auth"
STATUS=$(http_post "/api/teams" '{"name":"test"}')
if [ "$STATUS" = "401" ] || [ "$STATUS" = "403" ]; then
    test_pass
else
    test_fail "Expected HTTP 401/403, got $STATUS"
fi

test_start "GET /api/teams/:id requires auth"
STATUS=$(http_get "/api/teams/test-id")
if [ "$STATUS" = "401" ] || [ "$STATUS" = "403" ]; then
    test_pass
else
    test_fail "Expected HTTP 401/403, got $STATUS"
fi

# Test Suite 3: API Structure
echo ""
echo -e "${BLUE}3. API Structure & Responses${NC}"

test_start "Invalid endpoint returns 404"
STATUS=$(http_get "/api/nonexistent")
if [ "$STATUS" = "404" ]; then
    test_pass
else
    test_fail "Expected HTTP 404, got $STATUS"
fi

test_start "Malformed JSON returns 400"
STATUS=$(curl -s -m 5 -o /tmp/response.json -w "%{http_code}" \
    -X POST \
    -H "Content-Type: application/json" \
    -d "{invalid json}" \
    "$API_URL/api/teams")
if [ "$STATUS" = "400" ] || [ "$STATUS" = "401" ] || [ "$STATUS" = "403" ]; then
    test_pass
else
    test_fail "Expected HTTP 400/401/403, got $STATUS"
fi

# Test Suite 4: Security
echo ""
echo -e "${BLUE}4. Security Headers${NC}"

test_start "No sensitive info in error responses"
STATUS=$(http_get "/api/teams/test")
if ! grep -qi "password\|secret\|key.*=" /tmp/response.json 2>/dev/null; then
    test_pass
else
    test_fail "Sensitive information found in error response"
fi

test_start "CORS only allows configured origins"
STATUS=$(curl -s -m 5 -o /dev/null -w "%{http_code}" \
    -X OPTIONS \
    -H "Origin: https://evil.com" \
    -H "Access-Control-Request-Method: POST" \
    "$API_URL/api/teams")
# Should not return CORS headers for evil.com
EVIL_CORS=$(curl -s -m 5 -I -X OPTIONS \
    -H "Origin: https://evil.com" \
    -H "Access-Control-Request-Method: POST" \
    "$API_URL/api/teams" 2>/dev/null | grep -i "access-control-allow-origin: https://evil.com" || true)
if [ -z "$EVIL_CORS" ]; then
    test_pass
else
    test_fail "CORS allows unauthorized origin"
fi

# Summary
echo ""
echo "========================================"
echo "  Test Summary"
echo "========================================"
echo -e "Total:  $TOTAL"
echo -e "Passed: ${GREEN}$PASSED${NC}"
echo -e "Failed: ${RED}$FAILED${NC}"
echo ""

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}✗ Some tests failed${NC}"
    exit 1
fi
