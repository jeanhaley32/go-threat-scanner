#!/usr/bin/env bash
# Regression test for the config-injection fix: parse_threat_config must treat
# the config as DATA, never execute it. Sources the scanner (which no longer
# runs main() when sourced) and exercises parse_threat_config directly.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=/dev/null
source "${SCRIPT_DIR}/gh-threat-scanner.sh"
# The scanner's log() writes to globals that main() initializes; this unit test
# exercises parse_threat_config in isolation, so stub logging to a no-op. Also
# drop the scanner's inherited errexit/nounset — the harness drives assertions
# explicitly rather than relying on abort-on-error.
log() { :; }
set +eu

fail=0
check() { if [[ "$2" == "$3" ]]; then echo "ok  - $1"; else echo "FAIL- $1: got [$2] want [$3]"; fail=1; fi; }

workdir="$(mktemp -d)"
trap 'rm -rf "${workdir}"' EXIT
marker="${workdir}/PWNED"

# A malicious config: a command substitution payload, a bare command line, and
# a disallowed key — none of these must execute or be assigned.
cat > "${workdir}/evil.conf" <<CONF
THREAT_ENABLED=true
THREAT_NAME="\$(touch ${marker})"
touch ${marker}
EVIL_KEY="whatever"
THREAT_PACKAGES="left-pad malicious-pkg"
CONF

# reset any inherited values, then parse
THREAT_NAME=""; THREAT_PACKAGES=""; THREAT_ENABLED=""; EVIL_KEY="unset"
parse_threat_config "${workdir}/evil.conf" >/dev/null 2>&1

check "no code executed (marker absent)" "$( [[ -e "${marker}" ]] && echo YES || echo NO )" "NO"
check "payload stored literally, not run" "${THREAT_NAME}" "\$(touch ${marker})"
check "legit scalar parsed" "${THREAT_PACKAGES}" "left-pad malicious-pkg"
check "legit bool parsed" "${THREAT_ENABLED}" "true"
check "disallowed key rejected" "${EVIL_KEY}" "unset"

# A well-formed config still parses correctly
cat > "${workdir}/good.conf" <<CONF
THREAT_ENABLED=false
THREAT_NAME="Template Attack"
THREAT_DATE="2026-01-02"
CONF
THREAT_NAME=""; THREAT_DATE=""
parse_threat_config "${workdir}/good.conf" >/dev/null 2>&1
check "valid config name" "${THREAT_NAME}" "Template Attack"
check "valid config date" "${THREAT_DATE}" "2026-01-02"

if [[ ${fail} -eq 0 ]]; then echo "ALL PASS"; exit 0; else echo "TESTS FAILED"; exit 1; fi
