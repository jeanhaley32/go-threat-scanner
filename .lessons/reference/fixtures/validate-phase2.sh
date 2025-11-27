#!/bin/bash
#===============================================================================
# Phase 2 Validation: GitHub API Client
#===============================================================================
# Run from project root: ./.lessons/reference/fixtures/validate-phase2.sh
#
# Tests:
#   1. --test-api flag exists
#   2. Missing GH_TOKEN returns helpful error
#   3. Invalid org returns wrapped error with context
#   4. Valid org returns repo list (requires GH_TOKEN)
#
# Note: Tests 3-4 require a valid GH_TOKEN environment variable

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
echo " Phase 2 Validation: GitHub API Client"
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
echo "Test 1: --test-api flag exists"
#-------------------------------------------------------------------------------
OUTPUT=$(./scanner --help 2>&1 || true)
if echo "$OUTPUT" | grep -qi "test-api"; then
    pass "--test-api flag documented in help"
else
    fail "--test-api flag not found in --help output"
    echo "    Add a --test-api flag to test GitHub API separately"
fi

#-------------------------------------------------------------------------------
echo "Test 2: Missing/invalid token returns helpful error"
#-------------------------------------------------------------------------------
# Temporarily unset token
OLD_TOKEN="${GH_TOKEN:-}"
unset GH_TOKEN

OUTPUT=$(./scanner --test-api --org golang 2>&1 || true)
if echo "$OUTPUT" | grep -qi "token\|GH_TOKEN\|unauthorized\|authentication\|401"; then
    pass "Missing token returns helpful error"
else
    fail "Should mention token/authentication when GH_TOKEN missing"
fi

# Restore token
if [ -n "$OLD_TOKEN" ]; then
    export GH_TOKEN="$OLD_TOKEN"
fi

#-------------------------------------------------------------------------------
echo "Test 3: Invalid org returns error with context"
#-------------------------------------------------------------------------------
if [ -z "$GH_TOKEN" ]; then
    skip "Invalid org test (GH_TOKEN not set)"
else
    OUTPUT=$(./scanner --test-api --org "this-org-definitely-does-not-exist-xyz123" 2>&1 || true)
    if echo "$OUTPUT" | grep -qi "this-org-definitely-does-not-exist\|not found\|404"; then
        pass "Error includes org name context"
    else
        fail "Error should include the org name for debugging"
    fi
fi

#-------------------------------------------------------------------------------
echo "Test 4: Valid org returns repositories"
#-------------------------------------------------------------------------------
if [ -z "$GH_TOKEN" ]; then
    skip "Valid org test (GH_TOKEN not set)"
else
    OUTPUT=$(./scanner --test-api --org golang 2>&1 || true)
    if echo "$OUTPUT" | grep -qi "repositories\|repos\| go \|found"; then
        pass "Valid org returns repository list"
    else
        fail "Should list repositories for valid org"
        echo "    Try: ./scanner --test-api --org golang"
    fi

    # Check for actual repo names
    if echo "$OUTPUT" | grep -q "go\|vscode-go\|tools"; then
        pass "Output includes actual repo names"
    else
        fail "Output should include repo names (go, tools, etc.)"
    fi
fi

#-------------------------------------------------------------------------------
echo "Test 5: Error wrapping preserves cause"
#-------------------------------------------------------------------------------
if [ -z "$GH_TOKEN" ]; then
    skip "Error wrapping test (GH_TOKEN not set)"
else
    # This tests that errors are wrapped with context
    OUTPUT=$(./scanner --test-api --org "x" 2>&1 || true)
    # Error should mention both the operation AND the underlying cause
    if echo "$OUTPUT" | grep -qi "fetch\|get\|repos"; then
        pass "Error mentions the operation (fetching repos)"
    else
        fail "Error should wrap with context about what operation failed"
    fi
fi

#-------------------------------------------------------------------------------
# Summary
#-------------------------------------------------------------------------------
echo ""
echo "═══════════════════════════════════════════════════════════════"
TOTAL=$((PASS+FAIL))
if [ $FAIL -eq 0 ]; then
    echo " Phase 2 PASSED ($PASS passed, $SKIP skipped)"
    echo "═══════════════════════════════════════════════════════════════"
    if [ $SKIP -gt 0 ]; then
        echo ""
        echo " To run all tests: export GH_TOKEN='your-github-token'"
    fi
    exit 0
else
    echo " Phase 2 FAILED ($PASS passed, $FAIL failed, $SKIP skipped)"
    echo "═══════════════════════════════════════════════════════════════"
    exit 1
fi
