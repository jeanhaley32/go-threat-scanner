#!/bin/bash
#===============================================================================
# Full Validation Suite: All Phases
#===============================================================================
# Run from project root: ./.lessons/reference/fixtures/validate-all.sh
#
# Runs all phase validation scripts in order.
# Stops on first failure unless --continue flag is passed.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

cd "$PROJECT_ROOT"

CONTINUE_ON_FAIL=false
if [ "$1" = "--continue" ]; then
    CONTINUE_ON_FAIL=true
fi

echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║           GO THREAT SCANNER - FULL VALIDATION                ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""

PHASES_PASSED=0
PHASES_FAILED=0

run_phase() {
    PHASE=$1
    SCRIPT=$2

    echo ""
    echo "Running Phase $PHASE validation..."
    echo ""

    if bash "$SCRIPT"; then
        ((PHASES_PASSED++))
        return 0
    else
        ((PHASES_FAILED++))
        if [ "$CONTINUE_ON_FAIL" = false ]; then
            echo ""
            echo "╔═══════════════════════════════════════════════════════════════╗"
            echo "║  VALIDATION STOPPED - Phase $PHASE failed                      "
            echo "║  Fix the issues above before continuing.                      ║"
            echo "║                                                               ║"
            echo "║  To continue anyway: $0 --continue               "
            echo "╚═══════════════════════════════════════════════════════════════╝"
            exit 1
        fi
        return 1
    fi
}

# Run each phase
run_phase "1" "$SCRIPT_DIR/validate-phase1.sh"
run_phase "2" "$SCRIPT_DIR/validate-phase2.sh"
run_phase "3" "$SCRIPT_DIR/validate-phase3.sh"
run_phase "4b" "$SCRIPT_DIR/validate-phase4b.sh"
run_phase "5" "$SCRIPT_DIR/validate-phase5.sh"

# Final summary
echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
if [ $PHASES_FAILED -eq 0 ]; then
    echo "║           ALL PHASES PASSED! ($PHASES_PASSED/5)                         ║"
    echo "╠═══════════════════════════════════════════════════════════════╣"
    echo "║  Congratulations! Your scanner implementation is complete.   ║"
    echo "║                                                               ║"
    echo "║  Next: Run the final review with your tutor.                 ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    exit 0
else
    echo "║           VALIDATION INCOMPLETE                              ║"
    echo "║           $PHASES_PASSED passed, $PHASES_FAILED failed                           ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    exit 1
fi
