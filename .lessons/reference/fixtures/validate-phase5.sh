#!/bin/bash
#===============================================================================
# Phase 5 Validation: Graceful Shutdown & Polish
#===============================================================================
# Run from project root: ./.lessons/reference/fixtures/validate-phase5.sh
#
# Tests:
#   1. --json flag produces valid JSON
#   2. --quiet flag suppresses progress output
#   3. Exit codes are correct
#   4. Signal handling (graceful shutdown)
#   5. Rate limiting doesn't block indefinitely

set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
FIXTURES="$SCRIPT_DIR"

cd "$PROJECT_ROOT"

PASS=0
FAIL=0
SKIP=0

pass() { echo "  ✓ $1"; ((PASS++)); }
fail() { echo "  ✗ $1"; ((FAIL++)); }
skip() { echo "  ⊘ $1 (skipped)"; ((SKIP++)); }

echo "═══════════════════════════════════════════════════════════════"
echo " Phase 5 Validation: Graceful Shutdown & Polish"
echo "═══════════════════════════════════════════════════════════════"
echo ""

# Ensure binary is built
go build -o scanner ./cmd/scanner 2>/dev/null

#-------------------------------------------------------------------------------
echo "Test 1: --json flag exists"
#-------------------------------------------------------------------------------
OUTPUT=$(./scanner --help 2>&1 || true)
if echo "$OUTPUT" | grep -qi "\-\-json"; then
    pass "--json flag documented"
else
    fail "--json flag not found"
fi

#-------------------------------------------------------------------------------
echo "Test 2: --json produces valid JSON"
#-------------------------------------------------------------------------------
OUTPUT=$(./scanner --parse-file "$FIXTURES/sample-package-lock.json" \
         --config "$FIXTURES/test-threat.conf" --json 2>&1 || true)

# Check if output is valid JSON (starts with { or [)
if echo "$OUTPUT" | grep -qE '^\s*[\{\[]'; then
    pass "JSON output starts with { or ["
else
    fail "JSON output should start with { or ["
fi

# Try to validate with jq if available
if command -v jq &>/dev/null; then
    if echo "$OUTPUT" | jq . >/dev/null 2>&1; then
        pass "JSON output is valid (jq parsed)"
    else
        fail "JSON output is invalid (jq failed to parse)"
    fi
else
    skip "JSON validation (jq not installed)"
fi

#-------------------------------------------------------------------------------
echo "Test 3: --quiet flag exists"
#-------------------------------------------------------------------------------
if echo "$(./scanner --help 2>&1)" | grep -qi "quiet"; then
    pass "--quiet flag documented"
else
    fail "--quiet flag not found"
fi

#-------------------------------------------------------------------------------
echo "Test 4: --quiet suppresses progress"
#-------------------------------------------------------------------------------
NORMAL=$(./scanner --parse-file "$FIXTURES/sample-package-lock.json" \
         --config "$FIXTURES/test-threat.conf" 2>&1 || true)
QUIET=$(./scanner --parse-file "$FIXTURES/sample-package-lock.json" \
        --config "$FIXTURES/test-threat.conf" --quiet 2>&1 || true)

NORMAL_LINES=$(echo "$NORMAL" | wc -l)
QUIET_LINES=$(echo "$QUIET" | wc -l)

if [ "$QUIET_LINES" -lt "$NORMAL_LINES" ]; then
    pass "--quiet produces less output"
else
    fail "--quiet should suppress progress messages"
fi

#-------------------------------------------------------------------------------
echo "Test 5: Exit code 0 on success"
#-------------------------------------------------------------------------------
./scanner --parse-file "$FIXTURES/sample-package-lock.json" \
    --config "$FIXTURES/test-threat.conf" >/dev/null 2>&1
EXIT_CODE=$?
if [ $EXIT_CODE -eq 0 ]; then
    pass "Exit code 0 on successful scan"
else
    fail "Expected exit code 0, got $EXIT_CODE"
fi

#-------------------------------------------------------------------------------
echo "Test 6: Exit code non-zero on error"
#-------------------------------------------------------------------------------
./scanner --config nonexistent.conf --org test >/dev/null 2>&1 || EXIT_CODE=$?
if [ ${EXIT_CODE:-0} -ne 0 ]; then
    pass "Non-zero exit code on error"
else
    fail "Should return non-zero exit code on error"
fi

#-------------------------------------------------------------------------------
echo "Test 7: Graceful shutdown on SIGINT"
#-------------------------------------------------------------------------------
if [ -z "$GH_TOKEN" ]; then
    skip "SIGINT test (GH_TOKEN not set)"
else
    # Start scanner in background, send SIGINT, check for graceful message
    ./scanner --config "$FIXTURES/test-threat.conf" --org golang --workers 2 \
        > /tmp/scanner-output.txt 2>&1 &
    PID=$!
    sleep 2
    kill -INT $PID 2>/dev/null || true
    sleep 1

    OUTPUT=$(cat /tmp/scanner-output.txt 2>/dev/null || true)
    rm -f /tmp/scanner-output.txt

    if echo "$OUTPUT" | grep -qi "shutdown\|graceful\|interrupt\|stopping"; then
        pass "Scanner acknowledges SIGINT"
    else
        fail "Scanner should print shutdown message on SIGINT"
    fi

    # Clean up
    kill $PID 2>/dev/null || true
fi

#-------------------------------------------------------------------------------
echo "Test 8: JSON contains required fields"
#-------------------------------------------------------------------------------
OUTPUT=$(./scanner --parse-file "$FIXTURES/sample-package-lock.json" \
         --config "$FIXTURES/test-threat.conf" --json 2>&1 || true)

if echo "$OUTPUT" | grep -qi "package\|name"; then
    pass "JSON contains package/name field"
else
    fail "JSON should contain package information"
fi

if echo "$OUTPUT" | grep -qi "severity\|CRITICAL"; then
    pass "JSON contains severity field"
else
    fail "JSON should contain severity information"
fi

#-------------------------------------------------------------------------------
# Summary
#-------------------------------------------------------------------------------
echo ""
echo "═══════════════════════════════════════════════════════════════"
TOTAL=$((PASS+FAIL))
if [ $FAIL -eq 0 ]; then
    echo " Phase 5 PASSED ($PASS passed, $SKIP skipped)"
    echo "═══════════════════════════════════════════════════════════════"
    exit 0
else
    echo " Phase 5 FAILED ($PASS passed, $FAIL failed, $SKIP skipped)"
    echo "═══════════════════════════════════════════════════════════════"
    exit 1
fi
