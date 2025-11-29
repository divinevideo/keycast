#!/bin/bash
set -e

echo "=== Keycast QA Test Suite ==="
echo ""

# Configuration
export DATABASE_URL="${DATABASE_URL:-postgres://postgres:password@localhost/keycast_test}"
export RUST_LOG="${RUST_LOG:-info,keycast=debug,keycast_qa_tests=debug}"
export TEST_SERVER_URL="${TEST_SERVER_URL:-http://localhost:3000}"
export BUNKER_RELAYS="${BUNKER_RELAYS:-wss://relay.divine.video}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Track test results
TESTS_PASSED=0
TESTS_FAILED=0

# Cleanup function
cleanup() {
    echo ""
    echo ">>> Cleaning up..."
    if [ -n "$SERVER_PID" ]; then
        kill $SERVER_PID 2>/dev/null || true
        wait $SERVER_PID 2>/dev/null || true
    fi
}
trap cleanup EXIT

# Helper to run a test suite and track results
run_test_suite() {
    local name="$1"
    local command="$2"

    echo ""
    echo -e "${YELLOW}>>> Running: ${name}${NC}"

    if eval "$command"; then
        echo -e "${GREEN}✓ ${name} passed${NC}"
        ((TESTS_PASSED++))
        return 0
    else
        echo -e "${RED}✗ ${name} failed${NC}"
        ((TESTS_FAILED++))
        return 1
    fi
}

# Parse arguments
SKIP_BUILD=false
SKIP_SERVER=false
TEST_FILTER=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --skip-build)
            SKIP_BUILD=true
            shift
            ;;
        --skip-server)
            SKIP_SERVER=true
            shift
            ;;
        --filter)
            TEST_FILTER="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --skip-build    Skip building the server"
            echo "  --skip-server   Don't start server (assumes already running)"
            echo "  --filter NAME   Only run tests matching NAME"
            echo "  -h, --help      Show this help"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

echo "Configuration:"
echo "  DATABASE_URL: $DATABASE_URL"
echo "  TEST_SERVER_URL: $TEST_SERVER_URL"
echo "  BUNKER_RELAYS: $BUNKER_RELAYS"
echo ""

# Step 1: Run existing unit tests
if [ -z "$TEST_FILTER" ] || [[ "unit" == *"$TEST_FILTER"* ]]; then
    run_test_suite "Unit tests" "cargo test --workspace" || true
fi

# Step 2: Build server if needed
if [ "$SKIP_BUILD" = false ]; then
    echo ""
    echo ">>> Building server..."
    cargo build --release
fi

# Step 3: Start server if needed
if [ "$SKIP_SERVER" = false ]; then
    echo ""
    echo ">>> Resetting test database..."
    sqlx database drop --database-url "$DATABASE_URL" -y 2>/dev/null || true
    sqlx database create --database-url "$DATABASE_URL"
    sqlx migrate run --database-url "$DATABASE_URL" --source ./database/migrations

    echo ""
    echo ">>> Starting test server..."
    export ALLOWED_ORIGINS="${ALLOWED_ORIGINS:-http://localhost:3000,http://localhost:5173}"
    export SERVER_NSEC="${SERVER_NSEC:-$(openssl rand -hex 32)}"
    export MASTER_KEY_PATH="${MASTER_KEY_PATH:-./master.key}"
    export USE_GCP_KMS="${USE_GCP_KMS:-false}"
    export ENABLE_EXAMPLES="${ENABLE_EXAMPLES:-true}"
    ./target/release/keycast &
    SERVER_PID=$!

    # Wait for server to be ready
    echo ">>> Waiting for server to be ready..."
    for i in {1..30}; do
        if curl -s "$TEST_SERVER_URL/health" > /dev/null 2>&1; then
            echo "Server ready after ${i}s"
            break
        fi
        if [ $i -eq 30 ]; then
            echo -e "${RED}Server failed to start after 30s${NC}"
            exit 1
        fi
        sleep 1
    done
else
    echo ""
    echo ">>> Skipping server start (--skip-server)"
    echo ">>> Checking if server is running..."
    if ! curl -s "$TEST_SERVER_URL/health" > /dev/null 2>&1; then
        echo -e "${RED}Server not responding at $TEST_SERVER_URL${NC}"
        exit 1
    fi
    echo "Server is running"
fi

# Step 4: Run QA tests
cd tests/qa

# API OAuth tests
if [ -z "$TEST_FILTER" ] || [[ "api_oauth" == *"$TEST_FILTER"* ]]; then
    run_test_suite "API OAuth tests" "cargo test --test api_oauth_test -- --test-threads=1" || true
fi

# API RPC tests
if [ -z "$TEST_FILTER" ] || [[ "api_rpc" == *"$TEST_FILTER"* ]]; then
    run_test_suite "API RPC tests" "cargo test --test api_rpc_test -- --test-threads=1" || true
fi

# NIP-46 relay tests
if [ -z "$TEST_FILTER" ] || [[ "nip46" == *"$TEST_FILTER"* ]]; then
    run_test_suite "NIP-46 relay tests" "cargo test --test nip46_relay_test -- --test-threads=1" || true
fi

# Security tests
if [ -z "$TEST_FILTER" ] || [[ "security" == *"$TEST_FILTER"* ]]; then
    run_test_suite "Security tests" "cargo test --test security_test -- --test-threads=1" || true
fi

# User journey tests
if [ -z "$TEST_FILTER" ] || [[ "journey" == *"$TEST_FILTER"* ]]; then
    run_test_suite "User journey tests" "cargo test --test user_journey_test -- --test-threads=1" || true
fi

cd ../..

# Summary
echo ""
echo "========================================"
echo "           TEST SUMMARY"
echo "========================================"
echo -e "Passed: ${GREEN}${TESTS_PASSED}${NC}"
echo -e "Failed: ${RED}${TESTS_FAILED}${NC}"
echo "========================================"

if [ $TESTS_FAILED -gt 0 ]; then
    echo -e "${RED}Some tests failed!${NC}"
    exit 1
else
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
fi
