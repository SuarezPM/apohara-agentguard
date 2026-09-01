#!/usr/bin/env bash
# E2E tests for packaging/install.sh
# Hermetic: uses a local HTTP server with fake release artifacts.
# Run: bash tests/e2e/install_e2e.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
INSTALL_SH="$REPO_ROOT/packaging/install.sh"

# --- Test infrastructure ---
PASS=0; FAIL=0; TOTAL=0

pass() { PASS=$((PASS+1)); TOTAL=$((TOTAL+1)); echo "  ✅ $1"; }
fail() { FAIL=$((FAIL+1)); TOTAL=$((TOTAL+1)); echo "  ❌ $1"; }

# Create a fake release directory with a real binary and SHA256SUMS
setup_fake_release() {
  local fake_dir
  fake_dir=$(mktemp -d)

  # Build the binary once (if not already built)
  local bin="$REPO_ROOT/target/release/apohara-agentguard"
  if [ ! -f "$bin" ]; then
    echo "Building release binary..."
    cargo build --release --locked 2>/dev/null
  fi

  # Create fake release structure
  local target="x86_64-unknown-linux-gnu"
  mkdir -p "$fake_dir"
  cp "$bin" "$fake_dir/apohara-agentguard-$target"
  (cd "$fake_dir" && sha256sum apohara-agentguard-$target > SHA256SUMS)

  echo "$fake_dir"
}

# Start a local HTTP server serving the fake release.
# Writes "PORT PID" to stdout so the caller can read both.
start_server() {
  local serve_dir="$1"
  local port=$((8000 + RANDOM % 1000))
  python3 -m http.server "$port" --directory "$serve_dir" &>/dev/null &
  local pid=$!
  # Give the server a moment to bind
  sleep 0.5
  echo "$port $pid"
}

stop_server() {
  local pid="$1"
  kill "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
}

# Run install.sh and capture combined stdout+stderr into a temp file.
# Uses INSTALL_OUTPUT_FILE (set by caller) and sets INSTALL_EXIT_CODE.
# Avoids piping directly to grep — with set -euo pipefail, a downstream
# grep that exits early causes SIGPIPE on the still-running install.sh,
# which pipefail treats as failure.
run_install() {
  local out_file="$1"; shift
  INSTALL_EXIT_CODE=0
  bash "$INSTALL_SH" "$@" >"$out_file" 2>&1 || INSTALL_EXIT_CODE=$?
}

# --- Per-test state for cleanup ---
FAKE_DIR=""
SERVER_PID=""
TEST_HOME=""

cleanup() {
  if [ -n "${SERVER_PID:-}" ]; then stop_server "$SERVER_PID"; fi
  if [ -n "${FAKE_DIR:-}" ]; then rm -rf "$FAKE_DIR"; fi
  if [ -n "${TEST_HOME:-}" ]; then rm -rf "$TEST_HOME"; fi
}
trap cleanup EXIT

# --- Tests ---

echo "=== install.sh E2E tests ==="

# Test 1: Fresh install with valid manifest
echo "Test 1: Fresh install with valid manifest"
FAKE_DIR=$(setup_fake_release)
read -r SERVER_PORT SERVER_PID <<< "$(start_server "$FAKE_DIR")"
TEST_HOME=$(mktemp -d)

INSTALL_OUT=$(mktemp)
AGENTGUARD_VERSION="0.5.4" \
AGENTGUARD_DOWNLOAD_BASE="http://localhost:$SERVER_PORT" \
AGENTGUARD_PREFIX="$TEST_HOME" \
AGENTGUARD_NO_INIT=1 \
HOME="$TEST_HOME" \
  run_install "$INSTALL_OUT"

grep -q "installed" "$INSTALL_OUT" && pass "Fresh install succeeds" || fail "Fresh install failed"
[ -f "$TEST_HOME/bin/apohara-agentguard" ] && pass "Binary placed correctly" || fail "Binary not found"
rm -f "$INSTALL_OUT"

stop_server "$SERVER_PID"
cleanup

# Test 2: Idempotent install (already installed)
echo "Test 2: Idempotent install"
FAKE_DIR=$(setup_fake_release)
read -r SERVER_PORT SERVER_PID <<< "$(start_server "$FAKE_DIR")"
TEST_HOME=$(mktemp -d)
mkdir -p "$TEST_HOME/bin"
cp "$FAKE_DIR/apohara-agentguard-x86_64-unknown-linux-gnu" "$TEST_HOME/bin/apohara-agentguard"

INSTALL_OUT=$(mktemp)
AGENTGUARD_VERSION="0.5.4" \
AGENTGUARD_DOWNLOAD_BASE="http://localhost:$SERVER_PORT" \
AGENTGUARD_PREFIX="$TEST_HOME" \
AGENTGUARD_NO_INIT=1 \
HOME="$TEST_HOME" \
  run_install "$INSTALL_OUT"

grep -q "already installed" "$INSTALL_OUT" && pass "Idempotent: already installed detected" || fail "Idempotent check failed"
rm -f "$INSTALL_OUT"

stop_server "$SERVER_PID"
cleanup

# Test 3: Invalid manifest (404)
echo "Test 3: Invalid manifest (SHA256SUMS missing)"
TEST_HOME=$(mktemp -d)
FAKE_DIR=$(mktemp -d)
# Empty directory — no SHA256SUMS file

read -r SERVER_PORT SERVER_PID <<< "$(start_server "$FAKE_DIR")"

INSTALL_OUT=$(mktemp)
AGENTGUARD_VERSION="0.5.4" \
AGENTGUARD_DOWNLOAD_BASE="http://localhost:$SERVER_PORT" \
AGENTGUARD_PREFIX="$TEST_HOME" \
AGENTGUARD_NO_INIT=1 \
HOME="$TEST_HOME" \
  run_install "$INSTALL_OUT"

[ "$INSTALL_EXIT_CODE" -ne 0 ] && pass "Missing manifest correctly aborted" || fail "Should have failed on missing manifest"
rm -f "$INSTALL_OUT"

stop_server "$SERVER_PID"
cleanup

# Test 4: --no-init flag
echo "Test 4: --no-init flag"
FAKE_DIR=$(setup_fake_release)
read -r SERVER_PORT SERVER_PID <<< "$(start_server "$FAKE_DIR")"
TEST_HOME=$(mktemp -d)

INSTALL_OUT=$(mktemp)
AGENTGUARD_VERSION="0.5.4" \
AGENTGUARD_DOWNLOAD_BASE="http://localhost:$SERVER_PORT" \
AGENTGUARD_PREFIX="$TEST_HOME" \
HOME="$TEST_HOME" \
  run_install "$INSTALL_OUT" --no-init

grep -q "wiring skipped" "$INSTALL_OUT" && pass "--no-init accepted" || fail "--no-init not working"
rm -f "$INSTALL_OUT"

stop_server "$SERVER_PID"
cleanup

# --- Summary ---
echo ""
echo "=== Results: $PASS/$TOTAL passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
