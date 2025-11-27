#!/bin/bash
#===============================================================================
# Phase 3 Validation: Lock File Parsing
#===============================================================================
# Run from project root: ./.lessons/reference/fixtures/validate-phase3.sh
#
# Tests:
#   1. --parse-file flag exists
#   2. npm parser extracts packages correctly
#   3. yarn parser extracts packages correctly
#   4. Parser detects file format automatically
#   5. Threat detection finds known bad packages
#   6. Threat detection finds known bad versions
#   7. Clean packages are not flagged

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
echo " Phase 3 Validation: Lock File Parsing"
echo "═══════════════════════════════════════════════════════════════"
echo ""

# Ensure binary is built
if [ ! -f ./scanner ]; then
    echo "Building scanner..."
    go build -o scanner ./cmd/scanner 2>/dev/null || {
        fail "Binary failed to compile"
        exit 1
    }
fi

#-------------------------------------------------------------------------------
echo "Test 1: --parse-file flag exists"
#-------------------------------------------------------------------------------
OUTPUT=$(./scanner --help 2>&1 || true)
if echo "$OUTPUT" | grep -qi "parse-file\|parse"; then
    pass "--parse-file flag documented"
else
    fail "--parse-file flag not found"
fi

#-------------------------------------------------------------------------------
echo "Test 2: npm parser extracts packages"
#-------------------------------------------------------------------------------
OUTPUT=$(./scanner --parse-file "$FIXTURES/sample-package-lock.json" 2>&1 || true)

if echo "$OUTPUT" | grep -q "lodash"; then
    pass "npm parser finds lodash"
else
    fail "npm parser should find lodash"
fi

if echo "$OUTPUT" | grep -q "express"; then
    pass "npm parser finds express"
else
    fail "npm parser should find express"
fi

if echo "$OUTPUT" | grep -q "evil-package"; then
    pass "npm parser finds evil-package"
else
    fail "npm parser should find evil-package"
fi

#-------------------------------------------------------------------------------
echo "Test 3: npm parser extracts versions"
#-------------------------------------------------------------------------------
if echo "$OUTPUT" | grep -q "4.17.21\|lodash@4"; then
    pass "npm parser extracts lodash version"
else
    fail "npm parser should extract version 4.17.21"
fi

if echo "$OUTPUT" | grep -q "3.3.6\|event-stream@3"; then
    pass "npm parser extracts event-stream version"
else
    fail "npm parser should extract event-stream@3.3.6"
fi

#-------------------------------------------------------------------------------
echo "Test 4: yarn parser extracts packages"
#-------------------------------------------------------------------------------
OUTPUT=$(./scanner --parse-file "$FIXTURES/sample-yarn.lock" 2>&1 || true)

if echo "$OUTPUT" | grep -q "lodash"; then
    pass "yarn parser finds lodash"
else
    fail "yarn parser should find lodash"
fi

if echo "$OUTPUT" | grep -qi "malicious/crypto-stealer\|crypto-stealer"; then
    pass "yarn parser finds @malicious/crypto-stealer"
else
    fail "yarn parser should find @malicious/crypto-stealer"
fi

if echo "$OUTPUT" | grep -q "typosquat-lodash"; then
    pass "yarn parser finds typosquat-lodash"
else
    fail "yarn parser should find typosquat-lodash"
fi

#-------------------------------------------------------------------------------
echo "Test 5: Threat detection - bad packages"
#-------------------------------------------------------------------------------
OUTPUT=$(./scanner --parse-file "$FIXTURES/sample-package-lock.json" \
         --config "$FIXTURES/test-threat.conf" 2>&1 || true)

if echo "$OUTPUT" | grep -qi "evil-package.*CRITICAL\|CRITICAL.*evil-package"; then
    pass "Detects evil-package as threat"
else
    fail "Should flag evil-package as CRITICAL"
fi

#-------------------------------------------------------------------------------
echo "Test 6: Threat detection - bad versions"
#-------------------------------------------------------------------------------
if echo "$OUTPUT" | grep -qi "event-stream.*3.3.6.*CRITICAL\|CRITICAL.*event-stream"; then
    pass "Detects event-stream@3.3.6 as threat"
else
    fail "Should flag event-stream@3.3.6 as CRITICAL"
fi

if echo "$OUTPUT" | grep -qi "flatmap-stream.*0.1.1\|CRITICAL.*flatmap"; then
    pass "Detects flatmap-stream@0.1.1 as threat"
else
    fail "Should flag flatmap-stream@0.1.1 as CRITICAL"
fi

#-------------------------------------------------------------------------------
echo "Test 7: Clean packages not flagged"
#-------------------------------------------------------------------------------
# lodash and express are NOT in the threat list
if echo "$OUTPUT" | grep -qi "CRITICAL.*lodash\|lodash.*CRITICAL"; then
    fail "lodash should NOT be flagged as threat"
else
    pass "lodash correctly not flagged"
fi

if echo "$OUTPUT" | grep -qi "CRITICAL.*express\|express.*CRITICAL"; then
    fail "express should NOT be flagged as threat"
else
    pass "express correctly not flagged"
fi

#-------------------------------------------------------------------------------
echo "Test 8: Yarn threat detection"
#-------------------------------------------------------------------------------
OUTPUT=$(./scanner --parse-file "$FIXTURES/sample-yarn.lock" \
         --config "$FIXTURES/test-threat.conf" 2>&1 || true)

if echo "$OUTPUT" | grep -qi "typosquat-lodash.*CRITICAL\|CRITICAL.*typosquat"; then
    pass "Detects typosquat-lodash in yarn.lock"
else
    fail "Should flag typosquat-lodash in yarn.lock"
fi

if echo "$OUTPUT" | grep -qi "crypto-stealer.*CRITICAL\|CRITICAL.*crypto"; then
    pass "Detects @malicious/crypto-stealer in yarn.lock"
else
    fail "Should flag @malicious/crypto-stealer in yarn.lock"
fi

#-------------------------------------------------------------------------------
echo "Test 9: Findings count"
#-------------------------------------------------------------------------------
# npm should have 3 findings: evil-package, event-stream@3.3.6, flatmap-stream@0.1.1
OUTPUT=$(./scanner --parse-file "$FIXTURES/sample-package-lock.json" \
         --config "$FIXTURES/test-threat.conf" 2>&1 || true)
COUNT=$(echo "$OUTPUT" | grep -ci "CRITICAL" || true)
if [ "$COUNT" -ge 3 ]; then
    pass "npm lock has at least 3 threats detected"
else
    fail "npm lock should have 3 threats (found $COUNT)"
fi

#-------------------------------------------------------------------------------
# Summary
#-------------------------------------------------------------------------------
echo ""
echo "═══════════════════════════════════════════════════════════════"
if [ $FAIL -eq 0 ]; then
    echo " Phase 3 PASSED ($PASS/$((PASS+FAIL)) tests)"
    echo "═══════════════════════════════════════════════════════════════"
    exit 0
else
    echo " Phase 3 FAILED ($PASS passed, $FAIL failed)"
    echo "═══════════════════════════════════════════════════════════════"
    exit 1
fi
