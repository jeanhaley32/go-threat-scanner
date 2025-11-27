#!/bin/bash
#
# GitHub Supply Chain Threat Scanner
# Version: 3.0.0
#
# ==============================================================================
# OVERVIEW
# ==============================================================================
#
# This script scans GitHub organizations and local codebases for indicators of
# compromise (IoCs) related to npm supply chain attacks. The scanner is config-
# driven and agnostic to specific attack campaigns - all threat intelligence
# is loaded from external config files.
#
# ==============================================================================
# THREAT MODEL
# ==============================================================================
#
# npm supply chain attacks typically involve:
#
# 1. COMPROMISED PACKAGES
#    - Legitimate npm packages are hijacked or typosquatted
#    - Malicious versions are published with backdoors
#    - Common targets: popular utility packages with many dependents
#
# 2. MALICIOUS PREINSTALL SCRIPTS
#    - package.json contains preinstall/postinstall hooks
#    - These scripts execute during `npm install` before user code runs
#    - Often download and execute additional payloads
#
# 3. CREDENTIAL EXFILTRATION
#    - Malicious code harvests environment variables, tokens, SSH keys
#    - Data is exfiltrated to attacker-controlled endpoints
#    - May drop files (e.g., bac.js, dac.js) for persistence
#
# 4. GITHUB ACTIONS ABUSE
#    - Compromised workflows can access repository secrets
#    - Self-hosted runners may be targeted for lateral movement
#    - Malicious branches may contain weaponized workflows
#
# ==============================================================================
# DETECTION CAPABILITIES
# ==============================================================================
#
# This scanner checks for:
#   - Known compromised package names and versions in lock files
#   - Malicious SHA256 hashes in package-lock.json
#   - Suspicious preinstall/postinstall scripts
#   - Known malicious payload files (bac.js, dac.js, etc.)
#   - Suspicious GitHub Actions workflows
#   - Malicious self-hosted runner names
#   - Suspicious repository names/descriptions
#   - Credential exfiltration file patterns
#
# ==============================================================================
# CONFIGURATION FILE FORMAT (threat-patterns.conf)
# ==============================================================================
#
# The threat patterns config file should define:
#
#   THREAT_ENABLED=true|false
#   THREAT_NAME="Attack Name"
#   THREAT_SEVERITY=CRITICAL|WARNING|INFO
#   THREAT_PACKAGES="pkg1 pkg2 pkg3"           # Space-separated
#   THREAT_PACKAGE_VERSIONS="pkg1@1.0.0 pkg2@2.0.0"
#   THREAT_HASHES="sha256hash1 sha256hash2"
#   THREAT_MALICIOUS_SCRIPTS="bac.js dac.js"
#   THREAT_PREINSTALL_PATTERNS="curl wget node -e"
#   THREAT_WORKFLOW_PATTERNS="base64 -d|curl.*POST"
#   THREAT_MALICIOUS_WORKFLOWS="ci.yml build.yml"
#   THREAT_RUNNER_PATTERNS="miner crypto"
#   THREAT_REPO_PATTERNS="compromised malware"
#   THREAT_REPO_SEARCH="attack-name backdoor"
#   THREAT_MIGRATION_SUFFIX="-archived"
#   THREAT_BRANCH_PATTERNS="exploit payload"
#   THREAT_EXFIL_FILES=".env.stolen credentials.txt"
#
#   CUSTOM_WATCHLIST_ENABLED=true|false
#   CUSTOM_WATCHLIST_PACKAGES="internal-pkg1 internal-pkg2"
#
# See threat-patterns.conf.template for full documentation.
#
# ==============================================================================
# EXIT CODES
# ==============================================================================
#
#   0 - Scan completed successfully, no threats detected
#   1 - Scan completed with warnings or >50% API errors
#   2 - Scan completed with CRITICAL findings (immediate action required)
#
# ==============================================================================
# REQUIREMENTS
# ==============================================================================
#
#   - GitHub CLI (gh) authenticated with appropriate permissions
#   - jq for JSON parsing
#   - bash 4.0+ (for associative arrays and mapfile)
#
# ==============================================================================
# USAGE
# ==============================================================================
#
#   ./gh-threat-scanner.sh --org ORG_NAME [OPTIONS]
#   ./gh-threat-scanner.sh --local /path/to/project [OPTIONS]
#
# See --help for full usage information.

set -euo pipefail
IFS=$'\n\t'

#===============================================================================
# Testability Hooks
#===============================================================================
#
# These variables allow injecting mock commands for testing.
# Set these environment variables before running the script to override defaults.
#
# Example usage in tests:
#   GH_CMD="cat test-fixtures/mock-response.json" ./gh-threat-scanner.sh --local ./
#
: "${GH_CMD:=gh}"        # GitHub CLI command

# Wrapper functions that use the testability hooks
# These can be overridden by setting the corresponding environment variables

gh_api() {
  ${GH_CMD} api "$@"
}

gh_repo() {
  ${GH_CMD} repo "$@"
}

gh_auth() {
  ${GH_CMD} auth "$@"
}

gh_search() {
  ${GH_CMD} search "$@"
}

#===============================================================================
# Constants (readonly)
#===============================================================================

readonly VERSION="3.0.0"

# Terminal colors
readonly RED='\033[0;31m'
readonly YELLOW='\033[1;33m'
readonly GREEN='\033[0;32m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly GRAY='\033[0;90m'
readonly NC='\033[0m'

# API rate limiting
readonly API_DELAY=0.5

# Display and output limits
readonly DESCRIPTION_TRUNCATE_LENGTH=80
readonly DISPLAY_LIMIT=10
readonly PROGRESS_REPORT_INTERVAL=10
readonly MAX_REPOS_TO_FETCH=1000
readonly ERROR_THRESHOLD_PERCENT=50

# Return code conventions (for check_* functions)
# These constants document the semantic meaning of return values.
# All check_* functions follow this convention:
#   RC_SUCCESS (0) - Check completed successfully (no errors, findings recorded via add_finding)
#   RC_ERROR (1)   - Check could not complete due to an error (API failure, parse error, etc.)
readonly RC_SUCCESS=0
readonly RC_ERROR=1

# Lock file types (used for detection and parsing)
readonly LOCKFILE_NPM="package-lock.json"
readonly LOCKFILE_YARN="yarn.lock"
readonly LOCKFILE_PNPM="pnpm-lock.yaml"

#===============================================================================
# Global State
#===============================================================================

# Configuration (set via command-line args)
g_org_name=""
g_repo_name=""
g_output_dir=""
g_threat_config_path=""
g_local_scan_path=""

# Output files (initialized in setup_logging)
g_log_file=""
g_findings_file=""
g_summary_file=""
g_errors_file=""

# Scan type flags
g_scan_packages=true
g_scan_workflows=true
g_scan_runners=true
g_scan_repos=true
g_scan_exfil=true

# Output mode flags
g_deep_scan=false
g_quiet_mode=false
g_json_output=false

# Counters
g_total_repos=0
g_repos_scanned=0
g_critical_findings=0
g_warning_findings=0
g_repos_with_errors=0
g_api_errors=0

# Scan statistics
g_scan_start_time=0
g_workflows_scanned=0
g_packages_checked=0
g_verified_safe_count=0

# Internal state
g_cleanup_registered=0

# Findings buffer (for efficient JSON output)
# Instead of writing to disk on each finding, we buffer in memory and flush at end
declare -a g_findings_buffer=()
declare -a g_errors_buffer=()

# Watched packages tracking (package -> list of repos using it)
# Format: "package|repo1,repo2,repo3" (pipe-delimited to support @ in package names)
declare -a g_watched_package_repos=()

#===============================================================================
# Threat Intelligence Configuration
#===============================================================================

# load_threat_config: Load and validate threat patterns from config file
#
# The config file must define THREAT_* variables. The script is agnostic
# to specific attack campaigns - all context comes from the config.
#
load_threat_config() {
  local config_file
  local script_dir

  if [[ -n "${g_threat_config_path}" ]]; then
    config_file="${g_threat_config_path}"
  else
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    config_file="${script_dir}/threat-patterns.conf"
  fi

  if [[ ! -f "${config_file}" ]]; then
    log "CRITICAL" "Threat patterns config not found: ${config_file}"
    log "INFO" "Use --config to specify a custom config file path"
    log "INFO" "See threat-patterns.conf.template for format documentation"
    exit 1
  fi

  log "INFO" "Loading threat patterns from: ${config_file}"
  # shellcheck source=/dev/null  # Dynamic config file path
  source "${config_file}"

  # Validate configuration
  if [[ "${THREAT_ENABLED:-false}" != "true" ]] \
      && [[ "${CUSTOM_WATCHLIST_ENABLED:-false}" != "true" ]]; then
    log "WARNING" "No threat patterns are enabled in configuration"
  fi

  # Display which threat we're scanning for
  if is_enabled "${THREAT_ENABLED:-}"; then
    echo ""
    log "INFO" "=========================================="
    log "INFO" "SCANNING FOR: ${THREAT_NAME:-Unknown Threat}"
    [[ -n "${THREAT_DATE:-}" ]] && log "INFO" "Threat Date: ${THREAT_DATE}"
    log "INFO" "=========================================="
    echo ""
  fi
}

#===============================================================================
# Core Infrastructure
#===============================================================================

# cleanup: Exit handler for graceful shutdown
# shellcheck disable=SC2329  # Invoked via trap
cleanup() {
  local exit_code=$?

  set +e
  trap - ERR

  if [[ ${exit_code} -gt 2 ]] && [[ -n "${g_log_file:-}" ]]; then
    log "CRITICAL" "Script terminated with unexpected error code ${exit_code}"
    [[ -f "${g_findings_file:-}" ]] && log "INFO" "Partial results: ${g_output_dir}"
  fi

  exit "${exit_code}"
}

# error_handler: Trap handler for unexpected errors (line, bash_lineno, cmd, code)
# shellcheck disable=SC2329  # Invoked via trap
error_handler() {
  local line_no="$1"
  local bash_lineno="$2"
  local last_command="$3"
  local error_code="$4"

  if [[ -n "${g_log_file:-}" ]]; then
    log "CRITICAL" "Error at line ${line_no} (called from ${bash_lineno}): '${last_command}' exited ${error_code}"
  else
    echo "FATAL: Error at line ${line_no} (called from ${bash_lineno}): '${last_command}' exited ${error_code}" >&2
  fi

  exit "${error_code}"
}

# register_handlers: Set up error and exit traps
register_handlers() {
  if [[ ${g_cleanup_registered} -eq 0 ]]; then
    trap cleanup EXIT
    trap 'error_handler ${LINENO} ${BASH_LINENO} "${BASH_COMMAND}" $?' ERR
    g_cleanup_registered=1
  fi
}

#===============================================================================
# CLI Interface
#===============================================================================

# usage: Display help message and exit
usage() {
  cat << EOF
Usage: $(basename "$0") [OPTIONS]

Scan a GitHub organization for supply chain attack indicators (v${VERSION}).

Options:
  -o, --org ORG_NAME      GitHub organization to scan (required for org scan)
  -r, --repo REPO_NAME    Scan specific repository (requires --org)
  -d, --output DIR        Output directory for logs and reports
  -c, --config FILE       Path to threat patterns config file
  -l, --local PATH        Scan local directory for compromised packages
  -h, --help              Show this help message
  -v, --version           Show version information

Scan Filters:
  --packages-only         Only scan package.json/lock files
  --workflows-only        Only scan GitHub Actions workflows
  --runners-only          Only scan self-hosted runners
  --metadata-only         Only scan repo descriptions and branches
  --exfil-only            Only scan for exfiltration files

Output Options:
  --deep                  Scan all lock files in repo (monorepos), not just root
  -q, --quiet             Suppress output, show only one-line summary
  --json                  Output findings as JSON to stdout (implies --quiet)

Examples:
  $(basename "$0") --org mycompany
  $(basename "$0") --org mycompany --repo my-app --packages-only
  $(basename "$0") --local /path/to/project --config ./watchlist.conf
  $(basename "$0") --local . --deep                  # Scan monorepo
  $(basename "$0") --local . --json | jq '.findings' # Pipe to jq

EOF
  exit 0
}

# set_scan_mode: Enable only the specified scan type (packages|workflows|runners|repos|exfil)
set_scan_mode() {
  g_scan_packages=false
  g_scan_workflows=false
  g_scan_runners=false
  g_scan_repos=false
  g_scan_exfil=false

  case "$1" in
    packages)  g_scan_packages=true ;;
    workflows) g_scan_workflows=true ;;
    runners)   g_scan_runners=true ;;
    repos)     g_scan_repos=true ;;
    exfil)     g_scan_exfil=true ;;
  esac
}

# parse_args: Parse command-line arguments into global config
parse_args() {
  # Set default output directory
  g_output_dir="./threat-scan-$(date +%Y%m%d-%H%M%S)"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -o|--org)
        g_org_name="$2"
        shift 2
        ;;
      -r|--repo)
        g_repo_name="$2"
        shift 2
        ;;
      -d|--output)
        g_output_dir="$2"
        shift 2
        ;;
      -c|--config)
        g_threat_config_path="$2"
        shift 2
        ;;
      -l|--local)
        g_local_scan_path="$2"
        shift 2
        ;;
      --packages-only)  set_scan_mode "packages"; shift ;;
      --workflows-only) set_scan_mode "workflows"; shift ;;
      --runners-only)   set_scan_mode "runners"; shift ;;
      --metadata-only)  set_scan_mode "repos"; shift ;;
      --exfil-only)     set_scan_mode "exfil"; shift ;;
      --deep)           g_deep_scan=true; shift ;;
      -q|--quiet)       g_quiet_mode=true; shift ;;
      --json)           g_json_output=true; g_quiet_mode=true; shift ;;
      -v|--version)
        echo "gh-threat-scanner version ${VERSION}"
        exit 0
        ;;
      -h|--help)
        usage
        ;;
      *)
        echo "Unknown option: $1" >&2
        usage
        ;;
    esac
  done
}

#===============================================================================
# Logging & Output
#===============================================================================

# setup_logging: Initialize output directory and log files
#
# Creates output directory and initializes file paths for logging.
# Note: findings.json is not created until flush_findings() is called at end.
#
# Globals modified:
#   g_log_file, g_findings_file, g_summary_file, g_errors_file, g_scan_start_time
#
setup_logging() {
  # Capture scan start time for duration tracking
  g_scan_start_time=$(date +%s)

  if ! mkdir -p "${g_output_dir}" 2>/dev/null; then
    echo "FATAL: Cannot create output directory: ${g_output_dir}" >&2
    exit 1
  fi

  g_log_file="${g_output_dir}/scan.log"
  g_findings_file="${g_output_dir}/findings.json"
  g_summary_file="${g_output_dir}/summary.txt"
  g_errors_file="${g_output_dir}/scan-errors.log"

  if ! touch "${g_log_file}" 2>/dev/null; then
    echo "FATAL: Cannot write to output directory: ${g_output_dir}" >&2
    exit 1
  fi

  # Note: findings.json is written by flush_findings() at end of scan
  # for better performance (buffered writes instead of per-finding writes)

  log "INFO" "=========================================="
  log "INFO" "Supply Chain Threat Scanner Started"
  log "INFO" "Output Directory: ${g_output_dir}"
  log "INFO" "=========================================="
}

# log: Write formatted message to log file and terminal (level, message)
#
# Respects g_quiet_mode - when true, only writes to log file, not terminal
#
log() {
  local level="$1"
  local message="$2"
  local timestamp
  timestamp=$(date '+%Y-%m-%d %H:%M:%S')

  # Always write to log file
  echo "[${timestamp}] [${level}] ${message}" >> "${g_log_file}"

  # Skip terminal output in quiet mode
  is_enabled "${g_quiet_mode}" && return

  # Output to stderr so it doesn't interfere with command substitution
  case "${level}" in
    CRITICAL) echo -e "${RED}[CRITICAL]${NC} ${message}" >&2 ;;
    WARNING)  echo -e "${YELLOW}[WARNING]${NC} ${message}" >&2 ;;
    INFO)     echo -e "${BLUE}[INFO]${NC} ${message}" >&2 ;;
    SUCCESS)  echo -e "${GREEN}[SUCCESS]${NC} ${message}" >&2 ;;
    SCAN)     echo -e "${CYAN}[SCAN]${NC} ${message}" >&2 ;;
    CHECK)    echo -e "${GRAY}  └─ ${message}${NC}" >&2 ;;
    MATCH)    echo -e "${YELLOW}    ✓ ${message}${NC}" >&2 ;;
    *)        echo "[${level}] ${message}" >&2 ;;
  esac
}

# add_finding: Record a security finding to the buffer
#
# Findings are buffered in memory and written to disk once at end of scan
# for better performance (avoids repeated JSON file read/modify/write cycles).
#
# Args:
#   $1 - Severity (CRITICAL, WARNING, INFO)
#   $2 - Category (e.g., MALICIOUS_SCRIPT, COMPROMISED_VERSION)
#   $3 - Repository name or file path
#   $4 - Description of the finding
#   $5 - Additional details (optional)
#
# Globals modified:
#   g_findings_buffer - Array of JSON finding objects
#   g_critical_findings, g_warning_findings - Counters
#
add_finding() {
  local severity="$1"
  local category="$2"
  local repo="$3"
  local description="$4"
  local details="${5:-}"
  local timestamp
  timestamp=$(date -Iseconds)

  # Update severity counters
  case "${severity}" in
    CRITICAL) ((g_critical_findings++)) || true ;;
    WARNING)  ((g_warning_findings++)) || true ;;
    # INFO findings are not counted - use g_verified_safe_count for verified-safe packages
  esac

  # Escape special characters for JSON
  local escaped_desc escaped_det escaped_repo
  escaped_desc=$(printf '%s' "${description}" | jq -Rs '.')
  escaped_det=$(printf '%s' "${details}" | jq -Rs '.')
  escaped_repo=$(printf '%s' "${repo}" | jq -Rs '.')

  # Buffer the finding as a JSON object
  local json_entry
  json_entry=$(printf '{"timestamp":"%s","severity":"%s","category":"%s","repository":%s,"description":%s,"details":%s}' \
    "${timestamp}" "${severity}" "${category}" "${escaped_repo}" "${escaped_desc}" "${escaped_det}")

  g_findings_buffer+=("${json_entry}")

  log "${severity}" "[${category}] ${repo}: ${description}"
}

# add_scan_error: Record an API or scan error to the buffer
#
# Args:
#   $1 - Repository name
#   $2 - Operation that failed
#   $3 - Error message
#
# Globals modified:
#   g_errors_buffer - Array of JSON error objects
#   g_api_errors - Counter
#
add_scan_error() {
  local repo="$1"
  local operation="$2"
  local error_msg="$3"
  local timestamp
  timestamp=$(date -Iseconds)

  ((g_api_errors++)) || true

  # Also write to errors log file immediately (for debugging long scans)
  echo "[${timestamp}] [${repo}] ${operation}: ${error_msg}" >> "${g_errors_file}"

  # Escape special characters for JSON
  local escaped_repo escaped_op escaped_err
  escaped_repo=$(printf '%s' "${repo}" | jq -Rs '.')
  escaped_op=$(printf '%s' "${operation}" | jq -Rs '.')
  escaped_err=$(printf '%s' "${error_msg}" | jq -Rs '.')

  # Buffer the error as a JSON object
  local json_entry
  json_entry=$(printf '{"timestamp":"%s","repository":%s,"operation":%s,"error":%s}' \
    "${timestamp}" "${escaped_repo}" "${escaped_op}" "${escaped_err}")

  g_errors_buffer+=("${json_entry}")

  log "WARNING" "API error in ${repo} (${operation}): ${error_msg}"
}

# track_watched_package: Record that a watched package is used by a repo
#
# Args:
#   $1 - Package name
#   $2 - Repository name
#
# Globals modified:
#   g_watched_package_repos - Array tracking package->repos (format: "pkg|repo1,repo2")
#
track_watched_package() {
  local pkg="$1"
  local repo="$2"
  local i found=false

  # Search for existing entry for this package
  for i in "${!g_watched_package_repos[@]}"; do
    local entry="${g_watched_package_repos[$i]}"
    local entry_pkg="${entry%%|*}"

    if [[ "${entry_pkg}" == "${pkg}" ]]; then
      found=true
      local entry_repos="${entry#*|}"
      # Check if repo already exists in comma-separated list using glob pattern.
      # Wrapping with commas prevents partial matches (e.g., "repo" matching "repo-fork")
      if [[ ",${entry_repos}," != *",${repo},"* ]]; then
        g_watched_package_repos[i]="${entry_pkg}|${entry_repos},${repo}"
      fi
      break
    fi
  done

  # Add new entry if package not found
  if [[ "${found}" == "false" ]]; then
    g_watched_package_repos+=("${pkg}|${repo}")
  fi
}

# flush_findings: Write all buffered findings and errors to the JSON file
#
# This should be called once at the end of the scan to write all accumulated
# findings to disk in a single operation.
#
# Globals read:
#   g_findings_buffer - Array of JSON finding objects
#   g_errors_buffer - Array of JSON error objects
#   g_findings_file - Path to output JSON file
#   g_org_name - Organization name (for metadata)
#
flush_findings() {
  local findings_json="[]"
  local errors_json="[]"

  # Join findings array into JSON array
  if [[ ${#g_findings_buffer[@]} -gt 0 ]]; then
    findings_json=$(printf '%s\n' "${g_findings_buffer[@]}" | jq -s '.')
  fi

  # Join errors array into JSON array
  if [[ ${#g_errors_buffer[@]} -gt 0 ]]; then
    errors_json=$(printf '%s\n' "${g_errors_buffer[@]}" | jq -s '.')
  fi

  # Build complete JSON structure
  jq -n \
    --arg date "$(date -Iseconds)" \
    --arg org "${g_org_name}" \
    --argjson findings "${findings_json}" \
    --argjson errors "${errors_json}" \
    '{scan_date: $date, organization: $org, findings: $findings, errors: $errors}' \
    > "${g_findings_file}"

  log "INFO" "Wrote ${#g_findings_buffer[@]} findings and ${#g_errors_buffer[@]} errors to ${g_findings_file}"
}

#===============================================================================
# Utility Functions
#===============================================================================

# check_prerequisites: Verify required tools are available
check_prerequisites() {
  log "INFO" "Checking prerequisites..."

  local missing_deps=()

  command -v gh &>/dev/null || missing_deps+=("gh (GitHub CLI)")
  command -v jq &>/dev/null || missing_deps+=("jq")

  if [[ ${#missing_deps[@]} -gt 0 ]]; then
    log "CRITICAL" "Missing dependencies: ${missing_deps[*]}"
    exit 1
  fi

  if ! gh_auth status &>/dev/null; then
    log "CRITICAL" "GitHub CLI not authenticated. Run 'gh auth login' first."
    exit 1
  fi

  log "SUCCESS" "All prerequisites satisfied"
}

# is_enabled: Check if a boolean string is "true"
# Usage: if is_enabled "${g_quiet_mode}"; then ...
is_enabled() {
  [[ "${1:-false}" == "true" ]]
}

# truncate_with_ellipsis: Truncate string and add ellipsis if needed (string, max_len)
truncate_with_ellipsis() {
  local str="$1" max_len="${2:-${DESCRIPTION_TRUNCATE_LENGTH}}"
  if [[ ${#str} -gt ${max_len} ]]; then
    printf '%s...' "${str:0:${max_len}}"
  else
    printf '%s' "${str}"
  fi
}

# patterns_to_regex: Convert space-separated patterns to pipe-separated regex
patterns_to_regex() {
  printf '%s' "${1// /|}"
}

# patterns_to_escaped_regex: Convert space-separated patterns to escaped regex
# Escapes dots and converts spaces to pipe alternation for literal matching
patterns_to_escaped_regex() {
  local patterns="$1"
  # Replace spaces with \| for alternation, escape dots for literal matching
  printf '%s' "${patterns}" | sed 's/ /\\|/g; s/\./\\./g'
}

# fetch_gh_file: Fetch and decode file from GitHub (repo, path) → stdout, ret 0/1/2
fetch_gh_file() {
  local repo="$1"
  local file_path="$2"
  local api_path
  local response
  local content

  # Build API path
  if [[ "${repo}" == *"/"* ]]; then
    api_path="repos/${repo}/contents/${file_path}"
  else
    api_path="repos/${g_org_name}/${repo}/contents/${file_path}"
  fi

  log "CHECK" "API Call: gh_api ${api_path}"

  if ! response=$(gh_api "${api_path}" 2>&1); then
    if echo "${response}" | grep -q "404"; then
      return 1  # Not found
    fi
    log "CHECK" "❌ API call FAILED: ${response}"
    return 2  # Other error
  fi

  log "CHECK" "✅ API call SUCCESS - ${file_path} found"

  content=$(echo "${response}" | jq -r '.content // ""')
  if [[ -z "${content}" ]]; then
    return 1
  fi

  log "CHECK" "✅ Extracted base64 content (${#content} chars)"

  if ! content=$(echo "${content}" | base64 -d 2>&1); then
    log "CHECK" "❌ Base64 decode FAILED: ${content}"
    return 2
  fi

  log "CHECK" "✅ Base64 decode SUCCESS (${#content} bytes)"
  echo "${content}"
}

#===============================================================================
# Detection Functions
#===============================================================================

# check_repo_description: Scan repo description for threat indicators
#
# Args:
#   $1 - Repository name (without org prefix)
#
# Globals read:
#   g_org_name - Organization name
#   THREAT_REPO_PATTERNS - Space-separated patterns to match
#   THREAT_SEVERITY - Severity level for findings
#
# Returns:
#   RC_SUCCESS (0) - Check completed (findings recorded via add_finding if any)
#   RC_ERROR (1) - Check failed due to API or other error
#
check_repo_description() {
  local repo="$1"
  local description
  local patterns
  local regex

  log "CHECK" "Checking repository description..."

  if ! description=$(gh_repo view "${g_org_name}/${repo}" --json description -q '.description // ""' 2>&1); then
    add_scan_error "${repo}" "check_repo_description" "Failed to fetch: ${description}"
    return ${RC_ERROR}
  fi

  if [[ -z "${description}" ]]; then
    log "CHECK" "No description found ✓"
    return ${RC_SUCCESS}
  fi

  log "CHECK" "Description: $(truncate_with_ellipsis "${description}")"

  patterns="${THREAT_REPO_PATTERNS:-}"
  if [[ -z "${patterns}" ]]; then
    log "CHECK" "No patterns configured ✓"
    return ${RC_SUCCESS}
  fi

  regex=$(patterns_to_regex "${patterns}")
  if echo "${description}" | grep -qiE "${regex}"; then
    log "MATCH" "FOUND indicator in description!"
    add_finding "${THREAT_SEVERITY:-CRITICAL}" "REPO_DESCRIPTION" "${repo}" \
      "Repository description contains threat indicator" \
      "Description: ${description}"
  else
    log "CHECK" "Description clean ✓"
  fi

  return ${RC_SUCCESS}
}

# check_suspicious_branches: Scan branch names for threat indicators
#
# Args:
#   $1 - Repository name (without org prefix)
#
# Globals read:
#   g_org_name - Organization name
#   THREAT_BRANCH_PATTERNS - Space-separated patterns to match
#   THREAT_SEVERITY - Severity level for findings
#
# Returns:
#   RC_SUCCESS (0) - Check completed (findings recorded via add_finding if any)
#   RC_ERROR (1) - Check failed due to API or other error
#
check_suspicious_branches() {
  local repo="$1"
  local branches
  local patterns
  local regex
  local branch_count
  local branch_names

  log "CHECK" "Fetching branch list..."

  if ! branches=$(gh_api "repos/${g_org_name}/${repo}/branches" --paginate 2>&1); then
    add_scan_error "${repo}" "check_suspicious_branches" "Failed to fetch: ${branches}"
    return ${RC_ERROR}
  fi

  if ! echo "${branches}" | jq empty 2>/dev/null; then
    add_scan_error "${repo}" "check_suspicious_branches" "Invalid JSON response"
    return ${RC_ERROR}
  fi

  patterns="${THREAT_BRANCH_PATTERNS:-}"
  if [[ -z "${patterns}" ]]; then
    log "CHECK" "No branch patterns configured ✓"
    return ${RC_SUCCESS}
  fi

  branch_count=$(echo "${branches}" | jq 'length' 2>/dev/null)
  regex=$(patterns_to_regex "${patterns}")
  log "CHECK" "Scanning ${branch_count} branch(es) for: ${regex}"

  if echo "${branches}" | grep -qiE "${regex}"; then
    branch_names=$(echo "${branches}" | jq -r --arg pat "${regex}" '.[].name | select(test($pat; "i"))' 2>/dev/null)
    log "MATCH" "FOUND suspicious branch: ${branch_names}"
    add_finding "${THREAT_SEVERITY:-CRITICAL}" "MALICIOUS_BRANCH" "${repo}" \
      "Found suspicious branch matching threat pattern" \
      "Branches: ${branch_names}"
  else
    log "CHECK" "All ${branch_count} branches clean ✓"
  fi

  return ${RC_SUCCESS}
}

# check_workflows: Scan GitHub Actions workflows for threats
#
# Args:
#   $1 - Repository name (without org prefix)
#
# Globals read:
#   g_org_name - Organization name
#   THREAT_MALICIOUS_WORKFLOWS - Space-separated list of known bad workflow names
#   THREAT_WORKFLOW_PATTERNS - Space-separated content patterns to match
#   THREAT_SEVERITY - Severity level for findings
#
# Returns:
#   RC_SUCCESS (0) - Check completed (findings recorded via add_finding if any)
#   RC_ERROR (1) - Check failed due to API or other error
#
check_workflows() {
  local repo="$1"
  local workflow_response
  local workflow_count
  local malicious_workflows
  local workflow_patterns
  local regex
  local clean_count=0

  log "CHECK" "Checking GitHub Actions workflows..."

  if ! workflow_response=$(gh_api "repos/${g_org_name}/${repo}/contents/.github/workflows" 2>&1); then
    if echo "${workflow_response}" | grep -q "404"; then
      log "CHECK" "No workflows directory ✓"
      return ${RC_SUCCESS}
    fi
    add_scan_error "${repo}" "check_workflows" "Failed to fetch: ${workflow_response}"
    return ${RC_ERROR}
  fi

  if ! echo "${workflow_response}" | jq empty 2>/dev/null; then
    add_scan_error "${repo}" "check_workflows" "Invalid JSON response"
    return ${RC_ERROR}
  fi

  workflow_count=$(echo "${workflow_response}" | jq 'length' 2>/dev/null)
  ((g_workflows_scanned += workflow_count)) || true
  log "CHECK" "Found ${workflow_count} workflow(s)"

  # Check for known malicious workflow files
  malicious_workflows="${THREAT_MALICIOUS_WORKFLOWS:-}"
  if [[ -n "${malicious_workflows}" ]]; then
    local wf_name
    for wf_name in ${malicious_workflows}; do
      if echo "${workflow_response}" | jq -e --arg wf "${wf_name}" '.[] | select(.name == $wf)' &>/dev/null; then
        log "MATCH" "FOUND malicious workflow: ${wf_name}"
        add_finding "${THREAT_SEVERITY:-CRITICAL}" "MALICIOUS_WORKFLOW" "${repo}" \
          "Found known malicious workflow: ${wf_name}" \
          "May contain injection vulnerabilities"
        # Continue checking other workflows rather than returning early
      fi
    done
  fi

  # Check workflow contents
  workflow_patterns="${THREAT_WORKFLOW_PATTERNS:-}"
  if [[ -z "${workflow_patterns}" ]]; then
    log "CHECK" "No content patterns configured ✓"
    return ${RC_SUCCESS}
  fi

  regex=$(patterns_to_regex "${workflow_patterns}")
  log "CHECK" "Scanning contents for: ${regex}"

  local workflow_name
  local content
  while IFS= read -r workflow_name; do
    [[ -z "${workflow_name}" ]] && continue

    if ! content=$(fetch_gh_file "${repo}" ".github/workflows/${workflow_name}"); then
      continue
    fi

    if echo "${content}" | grep -qiE "${regex}"; then
      log "MATCH" "FOUND suspicious pattern in ${workflow_name}"
      add_finding "WARNING" "SUSPICIOUS_WORKFLOW" "${repo}" \
        "Workflow contains suspicious patterns" \
        "Workflow: ${workflow_name}"
    else
      ((clean_count++))
    fi
  done < <(echo "${workflow_response}" | jq -r '.[].name' 2>/dev/null)

  log "CHECK" "Workflows scanned: ${clean_count} clean ✓"
  return ${RC_SUCCESS}
}

# check_package_json: Scan package.json for malicious scripts
#
# Args:
#   $1 - Repository name (without org prefix)
#
# Globals read:
#   THREAT_MALICIOUS_SCRIPTS - Space-separated list of malicious script filenames
#   THREAT_PREINSTALL_PATTERNS - Space-separated patterns for suspicious preinstall scripts
#   THREAT_SEVERITY - Severity level for findings
#
# Returns:
#   RC_SUCCESS (0) - Check completed (findings recorded via add_finding if any)
#   RC_ERROR (1) - Check failed due to API or other error
#
check_package_json() {
  local repo="$1"
  local package_json
  local fetch_result

  log "CHECK" "Checking package.json..."

  # Don't capture stderr - let log messages display to terminal
  fetch_result=$(fetch_gh_file "${repo}" "package.json")
  local fetch_status=$?

  if [[ ${fetch_status} -eq 1 ]]; then
    log "CHECK" "✅ No package.json (non-Node.js repo) ✓"
    return ${RC_SUCCESS}
  elif [[ ${fetch_status} -eq 2 ]]; then
    add_scan_error "${repo}" "check_package_json" "Failed to fetch package.json"
    return ${RC_ERROR}
  fi

  package_json="${fetch_result}"

  # Validate JSON
  if ! echo "${package_json}" | jq empty 2>/dev/null; then
    add_scan_error "${repo}" "check_package_json" "Invalid JSON in package.json"
    return ${RC_ERROR}
  fi

  log "CHECK" "✅ JSON validation SUCCESS"

  # Check for malicious script files
  local malicious_scripts="${THREAT_MALICIOUS_SCRIPTS:-}"
  if [[ -n "${malicious_scripts}" ]]; then
    local script_pattern
    script_pattern=$(patterns_to_escaped_regex "${malicious_scripts}")
    log "CHECK" "Scanning for malicious payloads: ${malicious_scripts}"

    if echo "${package_json}" | grep -qE "${script_pattern}"; then
      log "MATCH" "FOUND malicious script reference!"
      add_finding "${THREAT_SEVERITY:-CRITICAL}" "MALICIOUS_SCRIPT" "${repo}" \
        "package.json references malicious payload files" \
        "Patterns: ${malicious_scripts}"
    else
      log "CHECK" "✅ No malicious payloads ✓"
    fi
  fi

  # Check preinstall scripts
  local preinstall_patterns="${THREAT_PREINSTALL_PATTERNS:-}"
  local preinstall
  preinstall=$(echo "${package_json}" | jq -r '.scripts.preinstall // ""')

  if [[ -n "${preinstall}" ]]; then
    log "CHECK" "Found preinstall: ${preinstall}"
    if [[ -n "${preinstall_patterns}" ]]; then
      local regex
      regex=$(patterns_to_regex "${preinstall_patterns}")
      if echo "${preinstall}" | grep -qiE "${regex}"; then
        log "MATCH" "FOUND suspicious preinstall!"
        add_finding "WARNING" "SUSPICIOUS_PREINSTALL" "${repo}" \
          "Suspicious preinstall script detected" \
          "Script: ${preinstall}"
      fi
    fi
  else
    log "CHECK" "✅ No preinstall script ✓"
  fi

  return ${RC_SUCCESS}
}

# lock_has_package: Check if package exists in lock file content (pipefail-safe)
#
# Uses jq for package-lock.json (reliable JSON parsing)
# Uses grep for yarn.lock (custom format, grep is appropriate)
#
lock_has_package() {
  local content="$1" type="$2" pkg="$3"

  if [[ "${type}" == "${LOCKFILE_NPM}" ]]; then
    # Use jq for reliable JSON parsing
    # Check both npm v2+ (.packages) and npm v1 (.dependencies) formats
    echo "${content}" | jq -e --arg pkg "$pkg" '
      (.packages["node_modules/\($pkg)"] // .packages["\($pkg)"] // .dependencies[$pkg]) != null
    ' >/dev/null 2>&1
  elif [[ "${type}" == "${LOCKFILE_PNPM}" ]]; then
    # pnpm format: packages keys are like "/@scope/pkg@version" or "/pkg@version"
    echo "${content}" | grep -E "^/?${pkg}@|^  ${pkg}: " >/dev/null 2>&1
  else
    # yarn.lock: entries start with "pkg@version" or "@scope/pkg@version"
    echo "${content}" | grep -E "^\"?${pkg}@" >/dev/null 2>&1
  fi
}

# lock_get_version: Extract installed version for a package from lock content
#
# Uses jq for package-lock.json, grep for yarn.lock/pnpm-lock.yaml
#
lock_get_version() {
  local content="$1" type="$2" pkg="$3"

  if [[ "${type}" == "${LOCKFILE_NPM}" ]]; then
    # Use jq - handles npm v1, v2, v3 lockfile formats
    echo "${content}" | jq -r --arg pkg "$pkg" '
      .packages["node_modules/\($pkg)"].version //
      .packages["\($pkg)"].version //
      .dependencies[$pkg].version //
      empty
    ' 2>/dev/null | head -1
  elif [[ "${type}" == "${LOCKFILE_PNPM}" ]]; then
    # pnpm: version is in the key itself "/@scope/pkg@1.0.0:" or as "version:" field
    # Try yq first, fall back to grep
    if command -v yq &>/dev/null; then
      # shellcheck disable=SC2016  # Single quotes intentional for yq expression
      echo "${content}" | yq -r --arg pkg "$pkg" '.packages | keys | .[] | select(test("/" + $pkg + "@")) | split("@") | .[-1]' 2>/dev/null | head -1
    else
      # Grep fallback: extract version from key pattern /pkg@version:
      echo "${content}" | grep -oE "/?${pkg}@[0-9][^:]*" 2>/dev/null | head -1 | sed 's/.*@//'
    fi
  else
    # yarn.lock: version is on line after the package entry
    # Handles both: "pkg@^1.0.0": and pkg@^1.0.0:
    echo "${content}" | grep -EA3 "^\"*${pkg}@" 2>/dev/null \
      | grep -E "^  version " | head -1 | sed 's/.*version "\([^"]*\)".*/\1/'
  fi
}

# lock_has_version: Check if specific package@version exists in lock content
#
# Uses jq for package-lock.json (exact version match)
# Uses grep for yarn.lock/pnpm-lock.yaml
#
lock_has_version() {
  local content="$1" type="$2" pkg="$3" ver="$4"

  if [[ "${type}" == "${LOCKFILE_NPM}" ]]; then
    # Use jq for exact version matching
    echo "${content}" | jq -e --arg pkg "$pkg" --arg ver "$ver" '
      (.packages["node_modules/\($pkg)"].version == $ver) or
      (.packages["\($pkg)"].version == $ver) or
      (.dependencies[$pkg].version == $ver)
    ' >/dev/null 2>&1
  elif [[ "${type}" == "${LOCKFILE_PNPM}" ]]; then
    # pnpm: check for exact /pkg@version: key
    echo "${content}" | grep -E "^/?${pkg}@${ver}:" >/dev/null 2>&1
  else
    # yarn.lock: check version field matches, or resolution field for yarn berry
    local found_version
    found_version=$(lock_get_version "${content}" "${type}" "${pkg}")
    [[ "${found_version}" == "${ver}" ]] && return 0

    # Also check yarn berry resolution format
    echo "${content}" | grep "resolution: \"${pkg}@npm:${ver}\"" >/dev/null 2>&1
  fi
}

# scan_lock_content: Scan lock file content for compromised packages and hashes
#
# This is a shared helper used by both check_package_lock (GitHub API) and
# scan_local_directory (local files) to avoid code duplication.
#
# Args:
#   $1 - Lock file identifier (repo name or file path, for logging)
#   $2 - Lock file content
#   $3 - Lock file type (package-lock.json, yarn.lock, or pnpm-lock.yaml)
#
# Returns:
#   Number of findings (via echo)
#
scan_lock_content() {
  local lock_id="$1"
  local lock_content="$2"
  local lock_type="$3"
  local findings=0

  # Check for malicious hashes (package-lock.json only)
  if [[ "${lock_type}" == "${LOCKFILE_NPM}" ]]; then
    local hashes="${THREAT_HASHES:-}"
    if [[ -n "${hashes}" ]]; then
      log "CHECK" "Scanning for malicious SHA256 hashes..."
      local hash
      for hash in ${hashes}; do
        if echo "${lock_content}" | grep -q "${hash}"; then
          log "MATCH" "FOUND malicious hash: ${hash:0:16}..."
          add_finding "${THREAT_SEVERITY:-CRITICAL}" "MALICIOUS_HASH" "${lock_id}" \
            "Lock file contains malicious bundle hash" "Hash: ${hash}"
          ((findings++))
        fi
      done
    fi
  fi

  # Scan for compromised packages
  log "CHECK" "Scanning ${lock_type} for compromised packages..."

  local pkg
  while IFS= read -r pkg; do
    [[ -z "${pkg}" ]] && continue

    if ! lock_has_package "${lock_content}" "${lock_type}" "${pkg}"; then
      continue
    fi

    # Track this watched package for the summary report
    track_watched_package "${pkg}" "${lock_id}"
    ((g_packages_checked++)) || true

    # Check against known compromised versions
    local pkg_version
    while IFS= read -r pkg_version; do
      [[ -z "${pkg_version}" ]] && continue
      local check_name="${pkg_version%@*}"
      local check_ver="${pkg_version##*@}"

      if [[ "${pkg}" == "${check_name}" ]]; then
        if lock_has_version "${lock_content}" "${lock_type}" "${check_name}" "${check_ver}"; then
          ((findings++))
          log "MATCH" "🚨 CRITICAL: ${check_name}@${check_ver} (COMPROMISED)"
          add_finding "CRITICAL" "COMPROMISED_VERSION" "${lock_id}" \
            "CONFIRMED compromised: ${check_name}@${check_ver}" \
            "This version is known malicious. Immediate action required."
        fi
      fi
    done < <(get_compromised_versions)
  done < <(get_compromised_packages)

  echo "${findings}"
}

# check_package_lock: Scan lock files for compromised packages
#
# Args:
#   $1 - Repository name (without org prefix)
#
# Globals read:
#   THREAT_HASHES - Space-separated list of malicious SHA256 hashes
#   THREAT_SEVERITY - Severity level for findings
#
# Returns:
#   RC_SUCCESS (0) - Check completed (findings recorded via add_finding if any)
#   RC_ERROR (1) - Check failed due to API or other error
#
check_package_lock() {
  local repo="$1"
  local lock_content=""
  local lock_type=""

  log "CHECK" "Checking for lock files (${LOCKFILE_NPM}, ${LOCKFILE_YARN}, ${LOCKFILE_PNPM})..."

  # Try package-lock.json first, then yarn.lock, then pnpm-lock.yaml
  if lock_content=$(fetch_gh_file "${repo}" "${LOCKFILE_NPM}" 2>&1); then
    lock_type="${LOCKFILE_NPM}"
    log "CHECK" "Found ${LOCKFILE_NPM}"
  elif lock_content=$(fetch_gh_file "${repo}" "${LOCKFILE_YARN}" 2>&1); then
    lock_type="${LOCKFILE_YARN}"
    log "CHECK" "Found ${LOCKFILE_YARN}"
  elif lock_content=$(fetch_gh_file "${repo}" "${LOCKFILE_PNPM}" 2>&1); then
    lock_type="${LOCKFILE_PNPM}"
    log "CHECK" "Found ${LOCKFILE_PNPM}"
    # Warn if yq is not available for optimal parsing
    if ! command -v yq &>/dev/null; then
      log "WARNING" "yq not installed - ${LOCKFILE_PNPM} parsing will use grep fallback"
    fi
  else
    log "CHECK" "✅ No lock file found ✓"
    return ${RC_SUCCESS}
  fi

  [[ -z "${lock_content}" ]] && return ${RC_SUCCESS}

  # Check for malicious hashes (package-lock.json only)
  if [[ "${lock_type}" == "${LOCKFILE_NPM}" ]]; then
    local hashes="${THREAT_HASHES:-}"
    if [[ -n "${hashes}" ]]; then
      log "CHECK" "Scanning for malicious SHA256 hashes..."
      local hash
      for hash in ${hashes}; do
        if echo "${lock_content}" | grep -q "${hash}"; then
          log "MATCH" "FOUND malicious hash: ${hash:0:16}..."
          add_finding "${THREAT_SEVERITY:-CRITICAL}" "MALICIOUS_HASH" "${repo}" \
            "Lock file contains malicious bundle hash" "Hash: ${hash}"
        fi
      done
    fi
  fi

  # Scan for compromised packages
  log "CHECK" "Scanning ${lock_type} for compromised packages..."

  local found_count=0
  local compromised_count=0
  local verified_safe=()
  local pkg

  while IFS= read -r pkg; do
    [[ -z "${pkg}" ]] && continue

    if ! lock_has_package "${lock_content}" "${lock_type}" "${pkg}"; then
      continue
    fi

    ((found_count++))

    # Track this watched package for the summary report
    track_watched_package "${pkg}" "${repo}"
    local installed_version
    installed_version=$(lock_get_version "${lock_content}" "${lock_type}" "${pkg}")
    local is_compromised=false

    # Check against known compromised versions
    local pkg_version
    while IFS= read -r pkg_version; do
      [[ -z "${pkg_version}" ]] && continue
      local check_name="${pkg_version%@*}"
      local check_ver="${pkg_version##*@}"

      if [[ "${pkg}" == "${check_name}" ]]; then
        if lock_has_version "${lock_content}" "${lock_type}" "${check_name}" "${check_ver}"; then
          ((compromised_count++))
          is_compromised=true
          log "MATCH" "🚨 CRITICAL: ${check_name}@${check_ver} (COMPROMISED)"
          add_finding "CRITICAL" "COMPROMISED_VERSION" "${repo}" \
            "CONFIRMED compromised: ${check_name}@${check_ver}" \
            "This version is known malicious. Immediate action required."
        fi
      fi
    done < <(get_compromised_versions)

    if [[ "${is_compromised}" == "false" ]] && [[ -n "${installed_version}" ]]; then
      verified_safe+=("${pkg}@${installed_version}")
    fi
  done < <(get_compromised_packages)

  # Report results
  if [[ ${found_count} -eq 0 ]]; then
    log "CHECK" "✅ No watched packages found ✓"
    return ${RC_SUCCESS}
  fi

  # Track packages checked for summary
  ((g_packages_checked += found_count)) || true

  if [[ ${compromised_count} -gt 0 ]]; then
    log "CRITICAL" "🚨 Found ${compromised_count} COMPROMISED version(s)!"
  else
    log "SUCCESS" "✅ Found ${found_count} watched packages - all SAFE"

    # Track verified safe count for summary
    ((g_verified_safe_count += ${#verified_safe[@]})) || true

    # Show first N verified packages
    if [[ ${#verified_safe[@]} -gt 0 ]]; then
      local display="${verified_safe[*]:0:${DISPLAY_LIMIT}}"
      [[ ${#verified_safe[@]} -gt ${DISPLAY_LIMIT} ]] && display="${display} ... and $((${#verified_safe[@]} - DISPLAY_LIMIT)) more"
      log "CHECK" "Verified safe: ${display// /, }"
    fi

    # Note: INFO findings for verified-safe packages are tracked separately
    # and not counted as "threats" in the summary
  fi

  return ${RC_SUCCESS}
}

# check_runners: Scan for malicious self-hosted runners
#
# This is an organization-level check that scans both org-level and
# repo-level runners for suspicious naming patterns.
#
# Args:
#   None
#
# Globals read:
#   g_org_name - Organization name
#   g_output_dir - Output directory (for repos.json)
#   THREAT_RUNNER_PATTERNS - Space-separated runner name patterns
#   THREAT_SEVERITY - Severity level for findings
#
# Returns:
#   RC_SUCCESS (0) - Check completed (findings recorded via add_finding if any)
#
check_runners() {
  echo ""
  log "INFO" "=========================================="
  log "INFO" "Checking Self-Hosted Runners"
  log "INFO" "=========================================="

  local patterns="${THREAT_RUNNER_PATTERNS:-}"
  if [[ -z "${patterns}" ]]; then
    log "CHECK" "No runner patterns configured ✓"
    return ${RC_SUCCESS}
  fi

  local regex
  regex=$(patterns_to_regex "${patterns}")

  # Organization-level runners
  log "CHECK" "Fetching organization-level runners..."
  local runners
  runners=$(gh_api "orgs/${g_org_name}/actions/runners" 2>/dev/null || echo '{"runners": []}')

  local org_count
  org_count=$(echo "${runners}" | jq '.runners | length' 2>/dev/null)

  if [[ "${org_count}" -gt 0 ]]; then
    if echo "${runners}" | jq -e --arg pat "${regex}" '.runners[] | select(.name | test($pat; "i"))' &>/dev/null; then
      local names
      names=$(echo "${runners}" | jq -r --arg pat "${regex}" '.runners[] | select(.name | test($pat; "i")) | .name')
      log "MATCH" "FOUND malicious org runner: ${names}"
      add_finding "${THREAT_SEVERITY:-CRITICAL}" "MALICIOUS_RUNNER" "ORGANIZATION" \
        "Self-hosted runner matches threat pattern" "Runners: ${names}"
    else
      log "CHECK" "Organization runners clean ✓"
    fi
  fi

  # Repository-level runners
  log "CHECK" "Checking repository-level runners..."
  local repos_file="${g_output_dir}/repos.json"
  local total
  total=$(jq length "${repos_file}" 2>/dev/null)
  local checked=0
  local with_runners=0
  local suspicious=0

  local repo
  while IFS= read -r repo; do
    [[ -z "${repo}" ]] && continue
    ((checked++))

    [[ $((checked % PROGRESS_REPORT_INTERVAL)) -eq 0 ]] && log "CHECK" "Progress: ${checked}/${total}"

    local repo_runners
    repo_runners=$(gh_api "repos/${g_org_name}/${repo}/actions/runners" 2>/dev/null || echo '{"runners": []}')

    local count
    count=$(echo "${repo_runners}" | jq '.runners | length' 2>/dev/null)

    if [[ "${count}" -gt 0 ]]; then
      ((with_runners++))
      if echo "${repo_runners}" | jq -e --arg pat "${regex}" '.runners[] | select(.name | test($pat; "i"))' &>/dev/null; then
        ((suspicious++))
        local names
        names=$(echo "${repo_runners}" | jq -r --arg pat "${regex}" '.runners[] | select(.name | test($pat; "i")) | .name')
        log "MATCH" "FOUND malicious runner in ${repo}: ${names}"
        add_finding "${THREAT_SEVERITY:-CRITICAL}" "MALICIOUS_RUNNER" "${repo}" \
          "Self-hosted runner matches threat pattern" "Runners: ${names}"
      fi
    fi
  done < <(jq -r '.[].name' "${repos_file}" 2>/dev/null)

  log "INFO" "Runner scan: ${checked} repos, ${with_runners} with runners, ${suspicious} suspicious"
  return ${RC_SUCCESS}
}

# check_recent_repos: Scan for suspicious repository patterns in org
#
# This is an organization-level check that searches for repositories
# matching suspicious naming patterns or migration indicators.
#
# Args:
#   None
#
# Globals read:
#   g_org_name - Organization name
#   THREAT_REPO_SEARCH - Space-separated search terms
#   THREAT_MIGRATION_SUFFIX - Suffix indicating forced migration
#   THREAT_REPO_PATTERNS - Patterns for suspicious descriptions
#   THREAT_SEVERITY - Severity level for findings
#
# Returns:
#   RC_SUCCESS (0) - Check completed (findings recorded via add_finding if any)
#
check_recent_repos() {
  echo ""
  log "INFO" "=========================================="
  log "INFO" "Checking for Suspicious Repositories"
  log "INFO" "=========================================="

  local repo_search="${THREAT_REPO_SEARCH:-}"
  local migration_suffix="${THREAT_MIGRATION_SUFFIX:-}"
  local repo_patterns="${THREAT_REPO_PATTERNS:-}"

  if [[ -z "${repo_search}" ]] && [[ -z "${migration_suffix}" ]]; then
    log "CHECK" "No repository search patterns configured, skipping ✓"
    return ${RC_SUCCESS}
  fi

  # Search for repos matching configured search terms
  if [[ -n "${repo_search}" ]]; then
    local search_query="${repo_search// / OR }"
    log "CHECK" "Searching for '${search_query}' in repository names/descriptions..."

    local search_results
    search_results=$(gh_search repos --owner "${g_org_name}" "${search_query}" \
      --json name,description,createdAt 2>/dev/null || echo "[]")

    local match_count
    match_count=$(echo "${search_results}" | jq length 2>/dev/null || echo "0")
    log "CHECK" "Found ${match_count} repository(ies) matching search pattern"

    if [[ "${match_count}" -gt 0 ]]; then
      local repo_info name description
      while IFS= read -r repo_info; do
        [[ -z "${repo_info}" ]] && continue
        name=$(echo "${repo_info}" | jq -r '.name')
        description=$(echo "${repo_info}" | jq -r '.description // "N/A"')
        log "MATCH" "FOUND suspicious repo: ${name}"
        log "CHECK" "  Description: $(truncate_with_ellipsis "${description}")"
        add_finding "${THREAT_SEVERITY:-CRITICAL}" "SUSPICIOUS_REPO" "${name}" \
          "Repository matches threat search pattern" \
          "Description: ${description}"
      done < <(echo "${search_results}" | jq -c '.[]')
    else
      log "CHECK" "No repositories matching search pattern ✓"
    fi
  fi

  # Check for repos with migration suffix (indicator of first wave attack)
  if [[ -n "${migration_suffix}" ]]; then
    log "CHECK" "Searching for repositories with '${migration_suffix}' suffix..."

    local migration_results
    migration_results=$(gh_search repos --owner "${g_org_name}" -- "${migration_suffix}" \
      --json name,description 2>/dev/null || echo "[]")

    local migration_count
    migration_count=$(echo "${migration_results}" | jq length 2>/dev/null || echo "0")
    log "CHECK" "Found ${migration_count} repository(ies) with '${migration_suffix}' suffix"

    local suspicious_migration_count=0
    if [[ -n "${repo_patterns}" ]]; then
      local grep_pattern
      grep_pattern=$(patterns_to_regex "${repo_patterns}")

      local repo_info description name
      while IFS= read -r repo_info; do
        [[ -z "${repo_info}" ]] && continue
        description=$(echo "${repo_info}" | jq -r '.description // ""')
        if echo "${description}" | grep -qiE "${grep_pattern}"; then
          ((suspicious_migration_count++))
          name=$(echo "${repo_info}" | jq -r '.name')
          log "MATCH" "FOUND suspicious migration repo: ${name}"
          log "CHECK" "  Description: $(truncate_with_ellipsis "${description}")"
          add_finding "${THREAT_SEVERITY:-CRITICAL}" "MIGRATED_REPO" "${name}" \
            "Repository may be a force-migrated private repo (threat indicator)" \
            "Description: ${description}"
        fi
      done < <(echo "${migration_results}" | jq -c '.[]')
    fi

    if [[ "${migration_count}" -gt 0 ]] && [[ ${suspicious_migration_count} -eq 0 ]]; then
      log "CHECK" "Migration repositories checked - no suspicious patterns ✓"
    fi
  fi

  log "INFO" "Suspicious repository scan complete"
  return ${RC_SUCCESS}
}

# check_exfiltration_files: Scan for credential exfiltration files
#
# Args:
#   $1 - Repository name (without org prefix)
#
# Globals read:
#   g_org_name - Organization name
#   THREAT_EXFIL_FILES - Space-separated list of exfiltration file paths
#   THREAT_SEVERITY - Severity level for findings
#
# Returns:
#   RC_SUCCESS (0) - Check completed (findings recorded via add_finding if any)
#
check_exfiltration_files() {
  local repo="$1"

  log "CHECK" "Checking for credential exfiltration files..."

  local exfil_files="${THREAT_EXFIL_FILES:-}"
  if [[ -z "${exfil_files}" ]]; then
    log "CHECK" "No exfiltration file patterns configured, skipping ✓"
    return ${RC_SUCCESS}
  fi

  local file_array
  read -ra file_array <<< "${exfil_files}"
  local file_count=${#file_array[@]}

  log "CHECK" "Scanning for ${file_count} known exfiltration file patterns..."

  local found_files=0
  local file file_check_result
  for file in "${file_array[@]}"; do
    if file_check_result=$(gh_api "repos/${g_org_name}/${repo}/contents/${file}" 2>&1); then
      ((found_files++))
      log "MATCH" "FOUND exfiltration file: ${file}"
      add_finding "${THREAT_SEVERITY:-CRITICAL}" "EXFILTRATION_FILE" "${repo}" \
        "Found potential exfiltration file: ${file}" \
        "This file pattern is associated with credential theft"
    else
      if ! echo "${file_check_result}" | grep -q "404"; then
        add_scan_error "${repo}" "check_exfiltration_files" \
          "Error checking for ${file}: ${file_check_result}"
      fi
    fi
  done

  if [[ ${found_files} -eq 0 ]]; then
    log "CHECK" "No exfiltration files found ✓"
  fi

  return ${RC_SUCCESS}
}

#===============================================================================
# Local Codebase Scanning
#===============================================================================

# get_compromised_packages: Returns list of compromised package names (newline-separated)
get_compromised_packages() {
  # Threat config packages (word splitting handles space separation, printf adds newlines)
  if is_enabled "${THREAT_ENABLED:-}" && [[ -n "${THREAT_PACKAGES:-}" ]]; then
    # shellcheck disable=SC2086  # Intentional word splitting
    printf '%s\n' ${THREAT_PACKAGES}
  fi

  # Custom watchlist packages
  if is_enabled "${CUSTOM_WATCHLIST_ENABLED:-}" && [[ -n "${CUSTOM_WATCHLIST_PACKAGES:-}" ]]; then
    # shellcheck disable=SC2086  # Intentional word splitting
    printf '%s\n' ${CUSTOM_WATCHLIST_PACKAGES}
  fi
}

# get_compromised_versions: Returns list of compromised package@version pairs
get_compromised_versions() {
  if is_enabled "${THREAT_ENABLED:-}" && [[ -n "${THREAT_PACKAGE_VERSIONS:-}" ]]; then
    # shellcheck disable=SC2086  # Intentional word splitting
    printf '%s\n' ${THREAT_PACKAGE_VERSIONS}
  fi
}

# find_lock_file: Find lock file for a package.json
#
# Args:
#   $1 - Path to package.json
#
# Outputs:
#   Path to lock file (stdout)
#
# Returns:
#   0 if lock file found, 1 otherwise
#
find_lock_file() {
  local package_json="$1"
  local dir
  dir=$(dirname "${package_json}")

  if [[ -f "${dir}/${LOCKFILE_NPM}" ]]; then
    echo "${dir}/${LOCKFILE_NPM}"
    return 0
  fi

  if [[ -f "${dir}/${LOCKFILE_YARN}" ]]; then
    echo "${dir}/${LOCKFILE_YARN}"
    return 0
  fi

  if [[ -f "${dir}/${LOCKFILE_PNPM}" ]]; then
    echo "${dir}/${LOCKFILE_PNPM}"
    return 0
  fi

  return 1
}

# check_local_malicious_scripts: Check a local package.json for malicious script references
#
# Args:
#   $1 - Path to package.json file
#
# Globals read:
#   THREAT_MALICIOUS_SCRIPTS - Space-separated list of malicious script filenames
#   THREAT_SEVERITY - Severity level for findings
#
# Returns:
#   Number of findings (via echo), 0 if none found
#
check_local_malicious_scripts() {
  local package_file="$1"
  local findings=0

  local malicious_scripts="${THREAT_MALICIOUS_SCRIPTS:-}"
  if [[ -z "${malicious_scripts}" ]]; then
    echo "0"
    return
  fi

  local script_pattern
  script_pattern=$(patterns_to_escaped_regex "${malicious_scripts}")
  log "CHECK" "Checking for malicious payload files: ${malicious_scripts}"

  if grep -qE "${script_pattern}" "${package_file}"; then
    log "MATCH" "FOUND malicious script reference!"
    add_finding "${THREAT_SEVERITY:-CRITICAL}" "MALICIOUS_SCRIPT" "${package_file}" \
      "package.json references known malicious payload files" \
      "Matched patterns: ${malicious_scripts}"
    findings=1
  fi

  echo "${findings}"
}

# find_watched_packages_in_file: Find watched packages referenced in a package.json
#
# Args:
#   $1 - Path to package.json file
#
# Outputs:
#   Space-separated list of found package names (stdout)
#
find_watched_packages_in_file() {
  local package_file="$1"
  local found_packages=()
  local pkg

  while IFS= read -r pkg; do
    [[ -z "${pkg}" ]] && continue
    if grep -q "\"${pkg}\"" "${package_file}"; then
      found_packages+=("${pkg}")
    fi
  done < <(get_compromised_packages)

  echo "${found_packages[*]:-}"
}

# verify_package_versions_in_lockfile: Check if watched packages have compromised versions
#
# Args:
#   $1 - Path to package.json (for context in findings)
#   $2 - Lock file content
#   $3 - Lock file type (package-lock.json or yarn.lock)
#   $4 - Space-separated list of packages to check
#
# Returns:
#   Number of compromised versions found (via echo)
#
verify_package_versions_in_lockfile() {
  local package_file="$1"
  local lock_content="$2"
  local lock_type="$3"
  local packages_str="$4"

  local found_bad_versions=0
  local verified_safe=()

  # Convert space-separated string to array
  local packages_to_check
  read -ra packages_to_check <<< "${packages_str}"

  local flagged_pkg
  for flagged_pkg in "${packages_to_check[@]}"; do
    [[ -z "${flagged_pkg}" ]] && continue

    local pkg_is_compromised=false
    local installed_version
    installed_version=$(lock_get_version "${lock_content}" "${lock_type}" "${flagged_pkg}")

    # Check against compromised versions
    local pkg_version pkg_name pkg_ver
    while IFS= read -r pkg_version; do
      [[ -z "${pkg_version}" ]] && continue
      pkg_name="${pkg_version%@*}"
      pkg_ver="${pkg_version##*@}"

      if [[ "${flagged_pkg}" == "${pkg_name}" ]]; then
        if lock_has_version "${lock_content}" "${lock_type}" "${pkg_name}" "${pkg_ver}"; then
          ((found_bad_versions++))
          pkg_is_compromised=true
          log "MATCH" "🚨 CRITICAL: ${pkg_name}@${pkg_ver} (CONFIRMED COMPROMISED)"
          add_finding "CRITICAL" "COMPROMISED_VERSION" "${package_file}" \
            "CONFIRMED compromised version: ${pkg_name}@${pkg_ver}" \
            "This exact version is known to be malicious. Immediate remediation required."
        fi
      fi
    done < <(get_compromised_versions)

    if [[ "${pkg_is_compromised}" == "false" ]]; then
      if [[ -n "${installed_version}" ]]; then
        verified_safe+=("${flagged_pkg}@${installed_version}")
      else
        verified_safe+=("${flagged_pkg}")
      fi
    fi
  done

  # Report verified safe packages
  if [[ ${found_bad_versions} -eq 0 ]] && [[ ${#verified_safe[@]} -gt 0 ]]; then
    log "SUCCESS" "✅ LIKELY SAFE: All flagged packages have clean versions"
    local display_count=${#verified_safe[@]}
    if [[ ${display_count} -gt ${DISPLAY_LIMIT} ]]; then
      log "CHECK" "Verified safe: ${verified_safe[*]:0:${DISPLAY_LIMIT}} ... and $((display_count - DISPLAY_LIMIT)) more"
    else
      log "CHECK" "Verified safe: ${verified_safe[*]}"
    fi
  fi

  echo "${found_bad_versions}"
}

# report_local_scan_results: Display final scan results and remediation advice
#
# Args:
#   $1 - Total findings count
#
# Outputs:
#   - Normal mode: Detailed results
#   - Quiet mode: One-line summary
#   - JSON mode: Findings JSON to stdout
#
# Returns:
#   0 if no findings, 1 if findings detected
#
report_local_scan_results() {
  local total_findings="$1"

  # Flush findings to file
  flush_findings

  # JSON output mode: output findings to stdout
  if is_enabled "${g_json_output}"; then
    if [[ -f "${g_findings_file}" ]]; then
      cat "${g_findings_file}"
    else
      echo '{"findings":[],"summary":{"critical":0,"warning":0}}'
    fi
  # Quiet mode: one-line summary
  elif is_enabled "${g_quiet_mode}"; then
    if [[ ${g_critical_findings} -gt 0 ]]; then
      echo "FAIL: ${g_critical_findings} critical, ${g_warning_findings} warning findings"
    elif [[ ${g_warning_findings} -gt 0 ]]; then
      echo "WARN: ${g_critical_findings} critical, ${g_warning_findings} warning findings"
    else
      echo "PASS: 0 critical, 0 warning findings"
    fi
  else
    # Normal verbose output
    log "INFO" "=========================================="
    log "INFO" "Local Scan Complete"
    log "INFO" "Total Findings: ${total_findings}"
    log "INFO" "=========================================="

    if [[ ${total_findings} -gt 0 ]]; then
      log "CRITICAL" "⚠️  COMPROMISED PACKAGES DETECTED!"
      log "CRITICAL" "Immediate actions required:"
      log "CRITICAL" "1. Review all flagged packages"
      log "CRITICAL" "2. Check package versions against compromise date"
      log "CRITICAL" "3. Update to clean versions or remove packages"
      log "CRITICAL" "4. Clear npm cache: npm cache clean --force"
      log "CRITICAL" "5. Rotate any exposed credentials"
    else
      log "SUCCESS" "No compromised packages detected ✓"
    fi
  fi

  [[ ${total_findings} -gt 0 ]] && return 1
  return 0
}

# scan_local_directory: Scan local directory for compromised packages
#
# Main orchestrator for local directory scanning. Finds all package.json files
# and checks each for malicious scripts and compromised dependencies.
#
# Args:
#   $1 - Path to directory to scan
#
# Returns:
#   0 if no findings, 1 if compromised packages detected
#
scan_local_directory() {
  local scan_path="$1"

  log "INFO" "=========================================="
  log "INFO" "Local Directory Scan"
  log "INFO" "Path: ${scan_path}"
  log "INFO" "=========================================="

  if [[ ! -d "${scan_path}" ]]; then
    log "CRITICAL" "Directory does not exist: ${scan_path}"
    exit 1
  fi

  # Find all package.json files (excluding node_modules)
  log "INFO" "Searching for package.json files..."
  local package_files
  package_files=$(find "${scan_path}" -name "package.json" -type f 2>/dev/null \
    | grep -v node_modules || true)

  if [[ -z "${package_files}" ]]; then
    log "INFO" "No package.json files found in ${scan_path}"
    report_local_scan_results 0
    return 0
  fi

  local file_count
  file_count=$(( $(echo "${package_files}" | wc -l) ))
  log "INFO" "Found ${file_count} package.json file(s) to scan"

  local total_findings=0
  local package_file

  while IFS= read -r package_file; do
    [[ -z "${package_file}" ]] && continue

    log "SCAN" "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    log "SCAN" "Scanning: ${package_file}"
    log "SCAN" "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    # Validate file is readable and valid JSON
    if [[ ! -r "${package_file}" ]]; then
      log "WARNING" "Cannot read file: ${package_file}"
      continue
    fi

    if ! jq empty "${package_file}" 2>/dev/null; then
      log "WARNING" "Invalid JSON in ${package_file}"
      continue
    fi

    # Check for malicious script references
    local script_findings
    script_findings=$(check_local_malicious_scripts "${package_file}")
    ((total_findings += script_findings))

    # Find watched packages in this file
    log "CHECK" "Scanning dependencies for compromised packages..."
    local watched_packages
    watched_packages=$(find_watched_packages_in_file "${package_file}")

    if [[ -z "${watched_packages}" ]]; then
      log "SUCCESS" "No compromised packages found in this file ✓"
      continue
    fi

    # Count packages found
    local found_count
    read -ra found_array <<< "${watched_packages}"
    found_count=${#found_array[@]}
    log "CHECK" "⚠️  Found ${found_count} package(s) from compromised namespaces (version check pending)"

    # Find and check lock file for exact versions
    local lock_file
    lock_file=$(find_lock_file "${package_file}") || true

    if [[ -n "${lock_file}" ]] && [[ -f "${lock_file}" ]]; then
      local lock_type
      lock_type=$(basename "${lock_file}")
      log "CHECK" "Checking ${lock_type} for confirmed compromised versions..."

      local lock_content
      lock_content=$(cat "${lock_file}")

      local bad_versions
      bad_versions=$(verify_package_versions_in_lockfile \
        "${package_file}" "${lock_content}" "${lock_type}" "${watched_packages}")

      if [[ ${bad_versions} -gt 0 ]]; then
        log "CRITICAL" "🚨 Found ${bad_versions} CONFIRMED compromised version(s)!"
        ((total_findings += bad_versions))
      fi
    else
      log "WARNING" "No lock file found - cannot verify exact versions"
      log "WARNING" "Flagged packages: ${watched_packages// /, }"
      add_finding "WARNING" "UNVERIFIED_PACKAGES" "${package_file}" \
        "Found ${found_count} package(s) from compromised namespaces - cannot verify versions" \
        "No lock file found. Packages: ${watched_packages// /, }"
    fi
  done <<< "${package_files}"

  # Deep scan mode: also find and scan all lock files directly
  if is_enabled "${g_deep_scan}"; then
    log "INFO" "Deep scan enabled - searching for all lock files..."

    local lock_files
    lock_files=$(find "${scan_path}" \( -name "${LOCKFILE_NPM}" -o -name "${LOCKFILE_YARN}" -o -name "${LOCKFILE_PNPM}" \) -type f 2>/dev/null \
      | grep -v node_modules || true)

    if [[ -n "${lock_files}" ]]; then
      local lock_count
      lock_count=$(( $(echo "${lock_files}" | wc -l) ))
      log "INFO" "Found ${lock_count} lock file(s) for deep scanning"

      local lock_file
      while IFS= read -r lock_file; do
        [[ -z "${lock_file}" ]] && continue

        # Skip if we already scanned this lock file (adjacent to a package.json)
        local lock_dir
        lock_dir=$(dirname "${lock_file}")
        if echo "${package_files}" | grep -q "${lock_dir}/package.json"; then
          continue
        fi

        log "SCAN" "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        log "SCAN" "Deep scan: ${lock_file}"
        log "SCAN" "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

        local lock_type
        lock_type=$(basename "${lock_file}")
        local lock_content
        lock_content=$(cat "${lock_file}" 2>/dev/null) || continue

        # Use shared helper to scan lock file content
        local findings_count
        findings_count=$(scan_lock_content "${lock_file}" "${lock_content}" "${lock_type}")
        ((total_findings += findings_count))

      done <<< "${lock_files}"
    fi
  fi

  report_local_scan_results "${total_findings}"
}

# scan_repository: Scan a single repository for all enabled threat types (repo)
scan_repository() {
  local repo="$1"
  local repo_error_count=0
  local checks_run=0
  ((g_repos_scanned++)) || true

  echo ""
  log "SCAN" "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  log "SCAN" "Repository: ${repo} [${g_repos_scanned}/${g_total_repos}]"
  log "SCAN" "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

  if is_enabled "${g_scan_repos}"; then
    check_repo_description "${repo}" || ((repo_error_count++))
    check_suspicious_branches "${repo}" || ((repo_error_count++))
    ((checks_run += 2))
  fi

  if is_enabled "${g_scan_workflows}"; then
    check_workflows "${repo}" || ((repo_error_count++))
    ((checks_run++))
  fi

  if is_enabled "${g_scan_packages}"; then
    check_package_json "${repo}" || ((repo_error_count++))
    check_package_lock "${repo}" || ((repo_error_count++))
    ((checks_run += 2))
  fi

  if is_enabled "${g_scan_exfil}"; then
    check_exfiltration_files "${repo}" || ((repo_error_count++))
    ((checks_run++))
  fi

  if [[ ${checks_run} -eq 0 ]]; then
    log "WARNING" "No scan types enabled for repository scanning"
  elif [[ ${repo_error_count} -gt 0 ]]; then
    ((g_repos_with_errors++)) || true
    log "WARNING" "Repository ${repo} had ${repo_error_count} errors during scan"
  else
    log "SUCCESS" "Repository scan complete - no threats detected ✓"
  fi

  # Rate limiting
  sleep "${API_DELAY}"
}

# generate_summary: Create scan summary report to summary file and stdout
#
# This function:
# 1. Flushes all buffered findings to disk
# 2. Generates a human-readable summary with clear verdict
# 3. Writes to both stdout and summary file
#
# Globals read:
#   g_scan_start_time, g_critical_findings, g_warning_findings
#   g_workflows_scanned, g_packages_checked, g_verified_safe_count
#   g_repos_scanned, g_total_repos, g_api_errors, g_repos_with_errors
#   g_org_name, g_findings_file, g_log_file, g_summary_file
#   g_scan_packages, g_scan_workflows, g_scan_repos, g_scan_exfil, g_scan_runners
#
generate_summary() {
  log "INFO" "Generating scan summary..."

  # Flush all buffered findings to JSON file
  flush_findings

  # Calculate scan duration
  local scan_end_time duration_secs
  scan_end_time=$(date +%s)
  duration_secs=$((scan_end_time - g_scan_start_time))

  # In JSON or quiet mode, write summary to file only (not stdout)
  local output_target="/dev/stdout"
  if is_enabled "${g_json_output}" || is_enabled "${g_quiet_mode}"; then
    output_target="/dev/null"
  fi

  {
    echo ""
    echo "================================================================================"

    # Verdict banner
    if [[ ${g_critical_findings} -gt 0 ]]; then
      echo -e "${RED}🚨 SCAN FAILED - CRITICAL THREATS DETECTED${NC}"
    elif [[ ${g_warning_findings} -gt 0 ]]; then
      echo -e "${YELLOW}⚠️  SCAN WARNING - ISSUES DETECTED${NC}"
    else
      echo -e "${GREEN}✅ SCAN PASSED - NO THREATS DETECTED${NC}"
    fi

    echo "================================================================================"
    echo "Threat: ${THREAT_NAME:-Unknown} | Target: ${g_org_name:-LOCAL}"
    echo "Duration: ${duration_secs}s | Repos: ${g_repos_scanned}/${g_total_repos} | Date: $(date '+%Y-%m-%d %H:%M:%S')"
    echo ""

    # Checks performed section
    echo "CHECKS PERFORMED:"
    if is_enabled "${g_scan_repos}"; then
      echo "  ✓ Repository metadata (descriptions, branches)"
    fi
    if is_enabled "${g_scan_workflows}"; then
      echo "  ✓ GitHub Actions workflows (${g_workflows_scanned} scanned)"
    fi
    if is_enabled "${g_scan_packages}"; then
      echo "  ✓ Package dependencies (${g_packages_checked} packages checked)"
    fi
    if is_enabled "${g_scan_exfil}"; then
      echo "  ✓ Exfiltration file patterns"
    fi
    if is_enabled "${g_scan_runners}"; then
      echo "  ✓ Self-hosted runners"
    fi
    echo ""

    # Threat findings section
    echo "THREAT FINDINGS:"
    if [[ ${g_critical_findings} -eq 0 ]] && [[ ${g_warning_findings} -eq 0 ]]; then
      echo "  None"
    else
      echo "  ${g_critical_findings} critical, ${g_warning_findings} warning"
      echo ""
      # List actual threats (CRITICAL and WARNING only)
      jq -r '.findings[] | select(.severity == "CRITICAL" or .severity == "WARNING") | "  [\(.severity)] \(.repository): \(.description)"' "${g_findings_file}" 2>/dev/null || true
    fi
    echo ""

    # Watched packages exposure section
    local watched_pkg_count=${#g_watched_package_repos[@]}
    if [[ ${watched_pkg_count} -gt 0 ]]; then
      echo "WATCHED PACKAGES IN USE (${watched_pkg_count} packages across your codebase):"
      echo "  These packages were targeted by this attack. Your versions are safe,"
      echo "  but awareness of exposure helps prioritize future monitoring."
      echo ""

      # Sort packages and display with repos
      local entry
      for entry in $(printf '%s\n' "${g_watched_package_repos[@]}" | sort); do
        local pkg="${entry%%|*}"
        local repos="${entry#*|}"
        local repo_count commas_only
        commas_only="${repos//[!,]/}"
        repo_count=$(( ${#commas_only} + 1 ))

        if [[ ${repo_count} -le 3 ]]; then
          echo "  • ${pkg}"
          echo "    └─ ${repos//,/, }"
        else
          # Show first 2 repos and count
          local first_repos
          first_repos=$(echo "${repos}" | cut -d',' -f1-2)
          echo "  • ${pkg}"
          echo "    └─ ${first_repos//,/, } (+$((repo_count - 2)) more)"
        fi
      done
      echo ""
    fi

    # Errors section
    if [[ ${g_api_errors} -gt 0 ]]; then
      echo "ERRORS: ${g_api_errors} API errors across ${g_repos_with_errors} repos"
      echo "  (See ${g_errors_file} for details)"
      echo ""
    else
      echo "ERRORS: None"
      echo ""
    fi

    # Critical action items
    if [[ ${g_critical_findings} -gt 0 ]]; then
      echo -e "${RED}⚠️  IMMEDIATE ACTION REQUIRED:${NC}"
      echo "  1. Review all flagged packages and workflows"
      echo "  2. Rotate any potentially exposed credentials"
      echo "  3. Clear npm cache: npm cache clean --force"
      echo "  4. Review GitHub audit logs for suspicious activity"
      echo ""
    fi

    echo "================================================================================"
    echo "Details: ${g_findings_file}"
    echo "Full log: ${g_log_file}"
    echo "================================================================================"
  } | tee "${g_summary_file}" > "${output_target}"
}

#===============================================================================
# Main Execution
#===============================================================================

# main: Entry point for the scanner (CLI args)
main() {
  register_handlers

  parse_args "$@"
  setup_logging
  load_threat_config

  # Local scan mode
  if [[ -n "${g_local_scan_path}" ]]; then
    log "INFO" "Running local directory scan mode"

    if ! command -v jq &>/dev/null; then
      log "CRITICAL" "jq is required for local scanning"
      exit 1
    fi

    # Disable ERR trap - we handle scan_local_directory return explicitly
    trap - ERR
    scan_local_directory "${g_local_scan_path}"
    local scan_result=$?
    trap 'error_handler ${LINENO} ${BASH_LINENO} "${BASH_COMMAND}" $?' ERR

    generate_summary

    if [[ ${scan_result} -eq 0 ]]; then
      log "SUCCESS" "Local scan complete. No compromised packages detected."
      exit 0
    else
      log "CRITICAL" "Local scan complete. COMPROMISED PACKAGES DETECTED!"
      exit 2
    fi
  fi

  # GitHub organization scan mode
  if [[ -z "${g_org_name}" ]]; then
    log "CRITICAL" "No organization specified. Use --org to specify a GitHub organization."
    log "INFO" "Example: $(basename "$0") --org mycompany --config ./threats.conf"
    log "INFO" "Use --help for more options."
    exit 1
  fi

  check_prerequisites

  # Log enabled scan types
  local enabled_scans=""
  is_enabled "${g_scan_packages}" && enabled_scans+="packages "
  is_enabled "${g_scan_workflows}" && enabled_scans+="workflows "
  is_enabled "${g_scan_runners}" && enabled_scans+="runners "
  is_enabled "${g_scan_repos}" && enabled_scans+="metadata "
  is_enabled "${g_scan_exfil}" && enabled_scans+="exfil "
  log "INFO" "Enabled scan types: ${enabled_scans:-none}"

  local repos_file="${g_output_dir}/repos.json"

  # Single repo mode vs full org scan
  if [[ -n "${g_repo_name}" ]]; then
    log "INFO" "Scanning single repository: ${g_org_name}/${g_repo_name}"

    if ! gh_api "repos/${g_org_name}/${g_repo_name}" \
        --jq '{name: .name, url: .html_url, isPrivate: .private}' \
        > "${repos_file}" 2>> "${g_log_file}"; then
      log "CRITICAL" "Repository ${g_org_name}/${g_repo_name} not found or inaccessible."
      exit 1
    fi

    local repo_data
    repo_data=$(cat "${repos_file}")
    echo "[${repo_data}]" > "${repos_file}"

    g_total_repos=1
    log "INFO" "Skipping organization-level checks for single repo scan"
  else
    log "INFO" "Fetching repository list for organization: ${g_org_name}"
    if ! gh_repo list "${g_org_name}" --limit ${MAX_REPOS_TO_FETCH} \
        --json name,url,isPrivate,defaultBranchRef \
        > "${repos_file}" 2>> "${g_log_file}"; then
      log "CRITICAL" "Failed to fetch repository list. Check organization name and permissions."
      exit 1
    fi

    g_total_repos=$(jq length "${repos_file}")
    log "INFO" "Found ${g_total_repos} repositories to scan"

    # Organization-level checks
    if is_enabled "${g_scan_runners}"; then
      check_runners || log "WARNING" "Errors occurred during runner checks"
    fi

    if is_enabled "${g_scan_repos}"; then
      check_recent_repos || log "WARNING" "Errors occurred during recent repo checks"
    fi
  fi

  # Repository-level checks
  log "INFO" "Beginning repository scans..."

  local repo repo_list
  repo_list=$(jq -r '.[].name' "${repos_file}" 2>/dev/null || echo "")

  while IFS= read -r repo; do
    [[ -z "${repo}" ]] && continue
    scan_repository "${repo}"
  done <<< "${repo_list}"

  generate_summary

  # Report scan health
  if [[ ${g_api_errors} -gt 0 ]]; then
    log "WARNING" "Scan completed with ${g_api_errors} API errors across ${g_repos_with_errors} repositories"
    log "INFO" "Review ${g_errors_file} for details"
  fi

  # Exit with appropriate code
  if [[ ${g_critical_findings} -gt 0 ]]; then
    log "CRITICAL" "Scan complete. CRITICAL findings detected - immediate action required!"
    exit 2
  elif [[ ${g_warning_findings} -gt 0 ]]; then
    log "WARNING" "Scan complete. Warning findings detected - review recommended."
    exit 1
  elif [[ ${g_api_errors} -gt $((g_total_repos * ERROR_THRESHOLD_PERCENT / 100)) ]]; then
    log "WARNING" "Scan completed but over 50% of repositories had errors. Results may be incomplete."
    exit 1
  else
    log "SUCCESS" "Scan complete. No indicators of compromise detected."
    exit 0
  fi
}

main "$@"
