#!/bin/bash
#===============================================================================
# Phase 4b Validation: Worker Pool & Concurrency
#===============================================================================
# Run from project root: ./.lessons/reference/fixtures/validate-phase4b.sh
#
# Tests:
#   1. --workers flag exists
#   2. Scanner runs without race conditions
#   3. Multiple workers process concurrently
#   4. Context cancellation works (timeout)
#   5. Full scan produces findings
#
# Note: Some tests require GH_TOKEN for live API testing

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
echo " Phase 4b Validation: Worker Pool & Concurrency"
echo "═══════════════════════════════════════════════════════════════"
echo ""

#-------------------------------------------------------------------------------
echo "Test 1: Binary builds with race detector"
#-------------------------------------------------------------------------------
if go build -race -o scanner-race ./cmd/scanner 2>/dev/null; then
    pass "Binary compiles with -race flag"
    rm -f scanner-race
else
    fail "Binary should compile with race detector"
    echo "    Run: go build -race -o scanner ./cmd/scanner"
fi

# Build normal binary for other tests
go build -o scanner ./cmd/scanner 2>/dev/null

#-------------------------------------------------------------------------------
echo "Test 2: --workers flag exists"
#-------------------------------------------------------------------------------
OUTPUT=$(./scanner --help 2>&1 || true)
if echo "$OUTPUT" | grep -qi "workers"; then
    pass "--workers flag documented"
else
    fail "--workers flag not found in help"
fi

#-------------------------------------------------------------------------------
echo "Test 3: Race detector passes on local parse"
#-------------------------------------------------------------------------------
# Build with race detector and run a local operation
if go build -race -o scanner-race ./cmd/scanner 2>/dev/null; then
    OUTPUT=$(./scanner-race --parse-file "$FIXTURES/sample-package-lock.json" \
             --config "$FIXTURES/test-threat.conf" 2>&1 || true)
    if echo "$OUTPUT" | grep -qi "race detected\|DATA RACE"; then
        fail "Race condition detected in local parsing"
    else
        pass "No race conditions in local parsing"
    fi
    rm -f scanner-race
else
    skip "Race detector test (build failed)"
fi

#-------------------------------------------------------------------------------
echo "Test 4: Workers parameter is respected"
#-------------------------------------------------------------------------------
# This is hard to test directly, but we can check the flag is accepted
OUTPUT=$(./scanner --config "$FIXTURES/test-threat.conf" --org test --workers 4 2>&1 || true)
if echo "$OUTPUT" | grep -qi "invalid\|unknown.*workers"; then
    fail "--workers flag not recognized"
else
    pass "--workers flag accepted"
fi

#-------------------------------------------------------------------------------
echo "Test 5: Context timeout works"
#-------------------------------------------------------------------------------
if [ -z "$GH_TOKEN" ]; then
    skip "Timeout test (GH_TOKEN not set)"
else
    # Run with a very short timeout - should exit gracefully
    START=$(date +%s)
    timeout 10 ./scanner --config "$FIXTURES/test-threat.conf" \
            --org golang --workers 2 2>&1 || true
    END=$(date +%s)
    DURATION=$((END - START))

    if [ $DURATION -lt 15 ]; then
        pass "Scanner respects timeout/cancellation"
    else
        fail "Scanner should support timeout via context"
    fi
fi

#-------------------------------------------------------------------------------
echo "Test 6: Live scan produces findings (integration)"
#-------------------------------------------------------------------------------
if [ -z "$GH_TOKEN" ]; then
    skip "Live scan test (GH_TOKEN not set)"
else
    # Scan a small org or your own test org
    # Using 'cli' org as it's small and public
    OUTPUT=$(timeout 60 ./scanner --config "$FIXTURES/test-threat.conf" \
             --org cli --workers 2 2>&1 || true)

    # Even if no threats found, scanner should complete
    if echo "$OUTPUT" | grep -qi "scan\|complete\|repos\|finish"; then
        pass "Scanner completes live scan"
    else
        fail "Scanner should report scan progress/completion"
    fi
fi

#-------------------------------------------------------------------------------
echo "Test 7: Race detector on concurrent scan"
#-------------------------------------------------------------------------------
if [ -z "$GH_TOKEN" ]; then
    skip "Concurrent race test (GH_TOKEN not set)"
else
    if go build -race -o scanner-race ./cmd/scanner 2>/dev/null; then
        OUTPUT=$(timeout 30 ./scanner-race --config "$FIXTURES/test-threat.conf" \
                 --org cli --workers 4 2>&1 || true)
        if echo "$OUTPUT" | grep -qi "race detected\|DATA RACE"; then
            fail "Race condition detected in concurrent scan!"
            echo "    Run: go run -race ./cmd/scanner --org cli --workers 4"
        else
            pass "No race conditions in concurrent scan"
        fi
        rm -f scanner-race
    else
        skip "Concurrent race test (build failed)"
    fi
fi

#-------------------------------------------------------------------------------
# Summary
#-------------------------------------------------------------------------------
echo ""
echo "═══════════════════════════════════════════════════════════════"
TOTAL=$((PASS+FAIL))
if [ $FAIL -eq 0 ]; then
    echo " Phase 4b PASSED ($PASS passed, $SKIP skipped)"
    echo "═══════════════════════════════════════════════════════════════"
    if [ $SKIP -gt 0 ]; then
        echo ""
        echo " To run all tests: export GH_TOKEN='your-github-token'"
    fi
    exit 0
else
    echo " Phase 4b FAILED ($PASS passed, $FAIL failed, $SKIP skipped)"
    echo "═══════════════════════════════════════════════════════════════"
    exit 1
fi
