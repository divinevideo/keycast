#!/bin/bash
# Flamegraph profiling script for Keycast HTTP RPC
# Usage: sudo ./tools/loadtest/flamegraph.sh [options]
#
# Options:
#   --users N        Number of test users (default: 50)
#   --concurrency N  Concurrent requests (default: 50)
#   --duration N     Test duration in seconds (default: 30)
#   --scenario S     warm-cache|cold-start|mixed (default: warm-cache)
#   --method M       get-public-key|sign-event (default: get-public-key)
#   --output DIR     Output directory (default: /tmp)
#   --skip-setup     Skip user creation (reuse existing users file)

set -e

# Default values
USERS=50
CONCURRENCY=50
DURATION=30
SCENARIO="warm-cache"
METHOD="get-public-key"
OUTPUT_DIR="/tmp"
SKIP_SETUP=false
URL="http://localhost:3000"
MANUAL_MODE=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --users) USERS="$2"; shift 2 ;;
        --concurrency) CONCURRENCY="$2"; shift 2 ;;
        --duration) DURATION="$2"; shift 2 ;;
        --scenario) SCENARIO="$2"; shift 2 ;;
        --method) METHOD="$2"; shift 2 ;;
        --output) OUTPUT_DIR="$2"; shift 2 ;;
        --skip-setup) SKIP_SETUP=true; shift ;;
        --url) URL="$2"; shift 2 ;;
        --manual) MANUAL_MODE=true; shift ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# Find project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$PROJECT_ROOT"

# Output files
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
NSEC_FILE="$OUTPUT_DIR/flamegraph-nsec.txt"
USERS_FILE="$OUTPUT_DIR/flamegraph-users.json"
RESULTS_FILE="$OUTPUT_DIR/flamegraph-results-$TIMESTAMP.json"
FLAMEGRAPH_FILE="$OUTPUT_DIR/keycast-flamegraph-$TIMESTAMP.svg"

echo "=== Keycast Flamegraph Profiler ==="
echo "Project root: $PROJECT_ROOT"
echo "Output dir:   $OUTPUT_DIR"
echo "Users:        $USERS"
echo "Concurrency:  $CONCURRENCY"
echo "Duration:     ${DURATION}s"
echo "Scenario:     $SCENARIO"
echo "Method:       $METHOD"
echo ""

# Check if running as root (required for dtrace on macOS)
if [[ $EUID -ne 0 ]]; then
    echo "Error: This script must be run with sudo for dtrace access"
    echo "Usage: sudo $0 [options]"
    exit 1
fi

# Check dependencies
if ! command -v flamegraph &> /dev/null; then
    echo "Error: flamegraph not found. Install with: cargo install flamegraph"
    exit 1
fi

# Always rebuild to ensure latest code is tested
echo "Building keycast with debug symbols..."
CARGO_PROFILE_RELEASE_DEBUG=true cargo build --release -p keycast

echo "Building loadtest tool..."
cargo build --release -p keycast-loadtest

# Fix ownership of target directory (cargo builds as root create root-owned files)
if [[ -n "$SUDO_USER" ]]; then
    echo "Fixing ownership of target directory..."
    chown -R "$SUDO_USER" "$PROJECT_ROOT/target"
fi

# Generate consistent SERVER_NSEC
if [[ ! -f "$NSEC_FILE" ]]; then
    echo "Generating SERVER_NSEC..."
    openssl rand -hex 32 > "$NSEC_FILE"
fi
SERVER_NSEC=$(cat "$NSEC_FILE")

# Kill any existing server on port 3000
echo "Checking port 3000..."
lsof -ti:3000 | xargs kill -9 2>/dev/null || true
sleep 1

# Clean up any existing trace files from previous runs (may be root-owned)
rm -rf "$PROJECT_ROOT/cargo-flamegraph.trace" 2>/dev/null || true
rm -f "$PROJECT_ROOT/perf.data" 2>/dev/null || true

# Manual mode: print instructions and exit
if [[ "$MANUAL_MODE" == "true" ]]; then
    echo ""
    echo "=== Manual Mode ==="
    echo "Run these commands in separate terminals:"
    echo ""
    echo "Terminal 1 (flamegraph - run first):"
    echo "  cd $PROJECT_ROOT"
    echo "  sudo DATABASE_URL=postgres://postgres:password@localhost/keycast \\"
    echo "    ALLOWED_ORIGINS=$URL \\"
    echo "    SERVER_NSEC=$SERVER_NSEC \\"
    echo "    MASTER_KEY_PATH=./master.key \\"
    echo "    flamegraph -o $FLAMEGRAPH_FILE -- ./target/release/keycast"
    echo ""
    echo "Terminal 2 (load test - after server starts):"
    if [[ "$SKIP_SETUP" == "false" ]]; then
        echo "  ./target/release/keycast-loadtest setup --url $URL --users $USERS --output $USERS_FILE"
    fi
    echo "  ./target/release/keycast-loadtest run \\"
    echo "    --url $URL --users-file $USERS_FILE \\"
    echo "    --concurrency $CONCURRENCY --duration $DURATION \\"
    echo "    --scenario $SCENARIO --method $METHOD \\"
    echo "    --output $RESULTS_FILE"
    echo ""
    echo "After load test: Press Ctrl+C in Terminal 1 to generate flamegraph"
    echo "Output will be at: $FLAMEGRAPH_FILE"
    exit 0
fi

# Create a script for the load test that will run in background
LOADTEST_SCRIPT=$(mktemp)
cat > "$LOADTEST_SCRIPT" << 'LOADTEST_EOF'
#!/bin/bash
URL="$1"
USERS_FILE="$2"
USERS="$3"
CONCURRENCY="$4"
DURATION="$5"
SCENARIO="$6"
METHOD="$7"
RESULTS_FILE="$8"
SKIP_SETUP="$9"
LOADTEST_BIN="${10}"

# Wait for server to be ready
echo "[loadtest] Waiting for server..."
for i in {1..30}; do
    if curl -s "$URL/health" > /dev/null 2>&1; then
        echo "[loadtest] Server ready!"
        break
    fi
    sleep 1
done

# Create test users if needed
if [[ "$SKIP_SETUP" == "false" ]] || [[ ! -f "$USERS_FILE" ]]; then
    echo "[loadtest] Creating users..."
    "$LOADTEST_BIN" setup --url "$URL" --users "$USERS" --output "$USERS_FILE"
fi

# Run load test
echo "[loadtest] Running load test for ${DURATION}s..."
"$LOADTEST_BIN" run \
    --url "$URL" \
    --users-file "$USERS_FILE" \
    --concurrency "$CONCURRENCY" \
    --duration "$DURATION" \
    --scenario "$SCENARIO" \
    --method "$METHOD" \
    --output "$RESULTS_FILE"

echo ""
echo "============================================"
echo "[loadtest] DONE! Press Ctrl+C to generate flamegraph"
echo "============================================"
LOADTEST_EOF
chmod +x "$LOADTEST_SCRIPT"

# Run load test in background
echo "Starting load test in background..."
"$LOADTEST_SCRIPT" "$URL" "$USERS_FILE" "$USERS" "$CONCURRENCY" "$DURATION" \
    "$SCENARIO" "$METHOD" "$RESULTS_FILE" "$SKIP_SETUP" \
    "$PROJECT_ROOT/target/release/keycast-loadtest" &
LOADTEST_PID=$!

# Trap to clean up on exit
cleanup() {
    kill $LOADTEST_PID 2>/dev/null || true
    rm -f "$LOADTEST_SCRIPT"
}
trap cleanup EXIT

# Run flamegraph in FOREGROUND (this is key for proper signal handling)
echo ""
echo "Starting keycast under flamegraph profiler..."
echo ">>> Press Ctrl+C after load test completes to generate flamegraph <<<"
echo ""

DATABASE_URL="${DATABASE_URL:-postgres://postgres:password@localhost/keycast}" \
ALLOWED_ORIGINS="$URL" \
SERVER_NSEC="$SERVER_NSEC" \
MASTER_KEY_PATH="${MASTER_KEY_PATH:-./master.key}" \
flamegraph -o "$FLAMEGRAPH_FILE" -- ./target/release/keycast

# Flamegraph exited (user pressed Ctrl+C), clean up
rm -f "$LOADTEST_SCRIPT"

# Check if SVG was created
if [[ ! -f "$FLAMEGRAPH_FILE" ]] || [[ ! -s "$FLAMEGRAPH_FILE" ]]; then
    echo ""
    echo "WARNING: Flamegraph SVG was not created."
    exit 1
fi

# Show results summary
echo ""
echo "=== Results ==="
if [[ -f "$RESULTS_FILE" ]]; then
    ./target/release/keycast-loadtest report --input "$RESULTS_FILE"
fi

echo ""
echo "=== Output Files ==="
echo "Flamegraph: $FLAMEGRAPH_FILE"
echo "Results:    $RESULTS_FILE"
echo "Users:      $USERS_FILE"

# Open flamegraph in browser (macOS)
if [[ -f "$FLAMEGRAPH_FILE" ]] && command -v open &> /dev/null; then
    echo ""
    echo "Opening flamegraph in browser..."
    open "$FLAMEGRAPH_FILE"
fi

echo ""
echo "Done!"
