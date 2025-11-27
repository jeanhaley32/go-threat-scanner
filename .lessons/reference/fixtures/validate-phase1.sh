#!/bin/bash
#===============================================================================
# Phase 1 Validation: CLI + Config Parsing
#===============================================================================
# Run from project root: ./.lessons/reference/fixtures/validate-phase1.sh
#
# Tests:
#   1. Binary builds successfully
#   2. --help flag works
#   3. Missing config file returns error
#   4. Missing --org flag returns error
#   5. Valid config parses correctly
#   6. Config values are parsed accurately

set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
FIXTURES="$SCRIPT_DIR"

cd "$PROJECT_ROOT"

PASS=0
FAIL=0

pass() { echo "  ✓ $1"; ((PASS++)); }
fail() { echo "  ✗ $1"; ((FAIL++)); }

echo "═══════════════════════════════════════════════════════════════"
echo " Phase 1 Validation: CLI + Config Parsing"
echo "═══════════════════════════════════════════════════════════════"
echo ""

#-------------------------------------------------------------------------------
echo "Test 1: Binary builds"
#-------------------------------------------------------------------------------
if go build -o scanner ./cmd/scanner 2>/dev/null; then
    pass "Binary compiles"
else
    fail "Binary failed to compile"
    echo "    Run: go build -o scanner ./cmd/scanner"
    exit 1
fi

#-------------------------------------------------------------------------------
echo "Test 2: --help flag works"
#-------------------------------------------------------------------------------
OUTPUT=$(./scanner --help 2>&1 || true)
if echo "$OUTPUT" | grep -qi "usage\|config\|org"; then
    pass "--help shows usage information"
else
    fail "--help doesn't show usage"
fi

#-------------------------------------------------------------------------------
echo "Test 3: Missing config file returns error"
#-------------------------------------------------------------------------------
OUTPUT=$(./scanner --config nonexistent.conf --org test 2>&1 || true)
if echo "$OUTPUT" | grep -qi "error\|not found\|no such file"; then
    pass "Missing config file returns error"
else
    fail "Missing config file should return error"
fi

#-------------------------------------------------------------------------------
echo "Test 4: Missing --org flag returns error"
#-------------------------------------------------------------------------------
OUTPUT=$(./scanner --config "$FIXTURES/test-threat.conf" 2>&1 || true)
if echo "$OUTPUT" | grep -qi "error\|required\|org"; then
    pass "Missing --org returns error"
else
    fail "Missing --org should return error"
fi

#-------------------------------------------------------------------------------
echo "Test 5: Valid config loads successfully"
#-------------------------------------------------------------------------------
OUTPUT=$(./scanner --config "$FIXTURES/test-threat.conf" --org testorg 2>&1 || true)
if echo "$OUTPUT" | grep -qi "Test Threat\|loaded\|config"; then
    pass "Valid config loads"
else
    fail "Valid config should load and display name"
    echo "    Expected output to mention 'Test Threat'"
fi

#-------------------------------------------------------------------------------
echo "Test 6: Config parses package list correctly"
#-------------------------------------------------------------------------------
OUTPUT=$(./scanner --config "$FIXTURES/test-threat.conf" --org testorg 2>&1 || true)
if echo "$OUTPUT" | grep -q "evil-package"; then
    pass "Config contains evil-package"
else
    fail "Config should parse THREAT_PACKAGES (evil-package)"
fi

if echo "$OUTPUT" | grep -q "crypto-stealer\|malicious"; then
    pass "Config contains @malicious/crypto-stealer"
else
    fail "Config should parse scoped package @malicious/crypto-stealer"
fi

#-------------------------------------------------------------------------------
echo "Test 7: Config parses version list correctly"
#-------------------------------------------------------------------------------
if echo "$OUTPUT" | grep -q "event-stream@3.3.6\|event-stream.*3.3.6"; then
    pass "Config contains event-stream@3.3.6"
else
    fail "Config should parse THREAT_PACKAGE_VERSIONS"
fi

#-------------------------------------------------------------------------------
# Summary
#-------------------------------------------------------------------------------
echo ""
echo "═══════════════════════════════════════════════════════════════"
if [ $FAIL -eq 0 ]; then
    echo " Phase 1 PASSED ($PASS/$((PASS+FAIL)) tests)"
    echo "═══════════════════════════════════════════════════════════════"
    exit 0
else
    echo " Phase 1 FAILED ($PASS passed, $FAIL failed)"
    echo "═══════════════════════════════════════════════════════════════"
    exit 1
fi
