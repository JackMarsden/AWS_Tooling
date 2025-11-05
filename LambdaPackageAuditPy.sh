#!/usr/bin/env bash
#
# Lambda Python Audit Script
# Audits all Python Lambda functions and their layers for package vulnerabilities
#
# Features:
# - Audits all Lambda functions with Python runtimes
# - Audits associated Lambda layers
# - Generates summary report with vulnerability counts
# - Supports multiple AWS profiles and regions
# - Optional JSON output for CI/CD integration
#
# Usage: ./LambdaPackageAuditPython.sh [OPTIONS]
#
# Options:
#   --profile PROFILE    AWS profile to use (default: default profile)
#   --region REGION      AWS region to scan (default: all regions)
#   --output-json FILE   Export results to JSON file
#   --severity LEVEL     Only show vulnerabilities >= LEVEL (low|medium|high|critical)
#   --diagnostic         Enable diagnostic mode (shows pip-audit raw output)
#   --v                  Verbose output
#   --help               Show this help message
#

set -euo pipefail

# ====== Configuration ======
PROFILE=""
REGION=""
VERBOSE=false
OUTPUT_JSON=""
MIN_SEVERITY="low"
DIAGNOSTIC=false
TMP_DIR="./lambda_audit_temp_$(date +%s)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors
RED="\e[31m"
GREEN="\e[32m"
YELLOW="\e[33m"
CYAN="\e[36m"
BLUE="\e[34m"
MAGENTA="\e[35m"
BOLD="\e[1m"
RESET="\e[0m"

# Counters
PYTHON_COUNT=0
NON_PYTHON_COUNT=0
LAYER_COUNT=0
TOTAL_CRITICAL=0
TOTAL_HIGH=0
TOTAL_MEDIUM=0
TOTAL_LOW=0

# Arrays to track layers and results
declare -A LAYERS_TO_PROCESS
declare -a AUDIT_RESULTS

# ====== Helper Functions ======
show_help() {
    cat << EOF
Lambda Python Audit Script

Audits all Python Lambda functions and their layers for package vulnerabilities.

USAGE:
    $0 [OPTIONS]

OPTIONS:
    --profile PROFILE       AWS profile to use (default: default profile)
    --region REGION         AWS region to scan (default: current region)
    --output-json FILE      Export results to JSON file
    --severity LEVEL        Minimum severity to report (low|medium|high|critical)
    --diagnostic            Enable diagnostic mode (shows pip-audit raw output)
    --v                     Verbose output
    --help                  Show this help message

EXAMPLES:
    # Audit all Lambda functions in default region
    $0

    # Audit with specific profile and region
    $0 --profile prod --region us-east-1

    # Export results to JSON
    $0 --output-json audit-results.json

    # Only show high and critical vulnerabilities
    $0 --severity high

    # Verbose mode with specific profile
    $0 --profile staging --v

    # Diagnostic mode for troubleshooting
    $0 --diagnostic --v

EOF
}

log_info() {
    echo -e "${CYAN}ℹ ${RESET}$*"
}

log_success() {
    echo -e "${GREEN}✓${RESET} $*"
}

log_warning() {
    echo -e "${YELLOW}⚠${RESET} $*"
}

log_error() {
    echo -e "${RED}✗${RESET} $*"
}

log_verbose() {
    if [[ "$VERBOSE" == true ]]; then
        echo -e "${BLUE}→${RESET} $*"
    fi
}

log_section() {
    echo
    echo -e "${BOLD}${CYAN}═══════════════════════════════════════════════════════${RESET}"
    echo -e "${BOLD}${CYAN} $*${RESET}"
    echo -e "${BOLD}${CYAN}═══════════════════════════════════════════════════════${RESET}"
    echo
}

# ====== Initialization ======
init() {
    log_section "Lambda Python Audit - Initialization"

    # Check required commands
    local missing_deps=()
    for cmd in aws jq unzip curl python3 pip; do
        if ! command -v $cmd >/dev/null 2>&1; then
            missing_deps+=("$cmd")
        fi
    done

    # Check for pip-audit
    if ! python3 -m pip show pip-audit >/dev/null 2>&1; then
        missing_deps+=("pip-audit")
    fi

    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        log_error "Missing required dependencies: ${missing_deps[*]}"
        echo "Please install the missing dependencies:"
        echo "  pip3 install pip-audit"
        exit 1
    fi

    log_success "All dependencies found"

    # Parse script options
    while [[ $# -gt 0 ]]; do
        case $1 in
            --profile)
                PROFILE="$2"
                shift 2
                ;;
            --region)
                REGION="$2"
                shift 2
                ;;
            --output-json)
                OUTPUT_JSON="$2"
                shift 2
                ;;
            --severity)
                MIN_SEVERITY="$2"
                shift 2
                ;;
            --diagnostic)
                DIAGNOSTIC=true
                shift
                ;;
            --v|--verbose)
                VERBOSE=true
                shift
                ;;
            --help|-h)
                show_help
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done

    # Build AWS CLI options
    local AWS_OPTS=""
    [[ -n "$PROFILE" ]] && AWS_OPTS="$AWS_OPTS --profile $PROFILE"
    [[ -n "$REGION" ]] && AWS_OPTS="$AWS_OPTS --region $REGION"

    # Get current AWS context
    local ACCOUNT_ID=$(aws sts get-caller-identity $AWS_OPTS --query 'Account' --output text 2>/dev/null || echo "unknown")
    local CURRENT_REGION=$(aws configure get region $([[ -n "$PROFILE" ]] && echo "--profile $PROFILE") 2>/dev/null || echo "us-east-1")
    [[ -n "$REGION" ]] && CURRENT_REGION="$REGION"

    log_info "AWS Account: ${BOLD}${ACCOUNT_ID}${RESET}"
    log_info "AWS Region: ${BOLD}${CURRENT_REGION}${RESET}"
    [[ -n "$PROFILE" ]] && log_info "AWS Profile: ${BOLD}${PROFILE}${RESET}"

    # Prepare temp directory
    rm -rf "$TMP_DIR"
    mkdir -p "$TMP_DIR"
    log_success "Temporary directory created: $TMP_DIR"
}

# ====== Parse pip-audit JSON output ======
parse_audit_results() {
    local AUDIT_JSON=$1
    local NAME=$2
    local TYPE=$3  # "function" or "layer"

    if [[ ! -f "$AUDIT_JSON" ]]; then
        log_verbose "No audit results file found for $NAME"
        return
    fi

    # pip-audit uses different severity levels: low, medium, high, critical
    local CRITICAL=$(jq -r '[.dependencies[].vulns[] | select(.fix_versions != null and .severity == "critical")] | length' "$AUDIT_JSON" 2>/dev/null || echo 0)
    local HIGH=$(jq -r '[.dependencies[].vulns[] | select(.fix_versions != null and .severity == "high")] | length' "$AUDIT_JSON" 2>/dev/null || echo 0)
    local MEDIUM=$(jq -r '[.dependencies[].vulns[] | select(.fix_versions != null and .severity == "medium")] | length' "$AUDIT_JSON" 2>/dev/null || echo 0)
    local LOW=$(jq -r '[.dependencies[].vulns[] | select(.fix_versions != null and .severity == "low")] | length' "$AUDIT_JSON" 2>/dev/null || echo 0)
    local TOTAL=$((CRITICAL + HIGH + MEDIUM + LOW))

    # Update global counters
    TOTAL_CRITICAL=$((TOTAL_CRITICAL + CRITICAL))
    TOTAL_HIGH=$((TOTAL_HIGH + HIGH))
    TOTAL_MEDIUM=$((TOTAL_MEDIUM + MEDIUM))
    TOTAL_LOW=$((TOTAL_LOW + LOW))

    # Store result
    AUDIT_RESULTS+=("$TYPE|$NAME|$CRITICAL|$HIGH|$MEDIUM|$LOW|$TOTAL")

    # Display summary
    if [[ $TOTAL -gt 0 ]]; then
        local severity_display=""
        [[ $CRITICAL -gt 0 ]] && severity_display="${severity_display}${RED}Critical: $CRITICAL${RESET} "
        [[ $HIGH -gt 0 ]] && severity_display="${severity_display}${MAGENTA}High: $HIGH${RESET} "
        [[ $MEDIUM -gt 0 ]] && severity_display="${severity_display}${YELLOW}Medium: $MEDIUM${RESET} "
        [[ $LOW -gt 0 ]] && severity_display="${severity_display}${BLUE}Low: $LOW${RESET} "

        echo -e "  ${BOLD}Vulnerabilities:${RESET} $severity_display(Total: $TOTAL)"
    else
        log_success "  No vulnerabilities found"
    fi
}

# ====== Audit a Lambda package ======
audit_package() {
    local NAME=$1
    local ZIP_URL=$2
    local TYPE=$3  # "function" or "layer"

    local FUNC_DIR="$TMP_DIR/$NAME"
    rm -rf "$FUNC_DIR"
    mkdir -p "$FUNC_DIR"
    
    # Get absolute path for FUNC_DIR to avoid issues with pushd
    local FUNC_DIR_ABS="$(cd "$FUNC_DIR" && pwd)"
    
    log_verbose "Downloading $TYPE: $NAME"
    
    if ! curl -sL -o "$FUNC_DIR/code.zip" "$ZIP_URL" 2>/dev/null; then
        log_error "Failed to download $TYPE: $NAME"
        return 1
    fi

    pushd "$FUNC_DIR" >/dev/null

    if ! unzip -oq code.zip 2>/dev/null; then
        log_error "Failed to extract $TYPE: $NAME"
        popd >/dev/null
        return 1
    fi

    local found=false
    
    # Look for requirements.txt files
    while IFS= read -r req_file; do
        found=true
        local DIR=$(dirname "$req_file")
        
        log_verbose "Running pip-audit in: $DIR"
        
        # Generate safe filename from directory path
        local DIR_SAFE=$(echo "$DIR" | tr '/' '_' | sed 's/^_*//' | sed 's/_*$//')
        [[ -z "$DIR_SAFE" || "$DIR_SAFE" == "." ]] && DIR_SAFE="root"
        local AUDIT_OUTPUT="$FUNC_DIR_ABS/audit_${DIR_SAFE}.json"
        
        pushd "$DIR" >/dev/null

        # Check Python version
        local PY_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
        log_verbose "Python version: $PY_VERSION"

        # Run pip-audit
        local AUDIT_FAILED=false
        
        log_verbose "Attempting pip-audit -r requirements.txt..."
        
        # Try pip-audit with JSON output
        if python3 -m pip_audit -r requirements.txt --format json > "$AUDIT_OUTPUT" 2>&1; then
            log_verbose "Audit completed successfully"
        else
            AUDIT_FAILED=true
            log_verbose "Audit failed, trying with --no-deps..."
            # Try without checking dependencies
            if python3 -m pip_audit -r requirements.txt --format json --no-deps > "$AUDIT_OUTPUT" 2>&1; then
                log_verbose "Audit completed (no-deps mode)"
            else
                log_verbose "Audit failed, creating empty result..."
                echo '{"dependencies":[]}' > "$AUDIT_OUTPUT"
            fi
        fi

        # Check if audit output is valid JSON
        if [[ ! -s "$AUDIT_OUTPUT" ]]; then
            log_warning "Audit output file is empty for $DIR"
            echo '{"dependencies":[]}' > "$AUDIT_OUTPUT"
        elif ! jq empty "$AUDIT_OUTPUT" 2>/dev/null; then
            log_warning "Invalid JSON in audit results for $DIR"
            if [[ "$VERBOSE" == true ]]; then
                log_verbose "Content: $(head -20 "$AUDIT_OUTPUT")"
            fi
            echo '{"dependencies":[]}' > "$AUDIT_OUTPUT"
        fi

        # Display requirements.txt info for debugging
        if [[ "$VERBOSE" == true ]] && [[ -f requirements.txt ]]; then
            log_verbose "Packages in requirements.txt:"
            head -10 requirements.txt | while read line; do
                [[ -n "$line" ]] && log_verbose "  - $line"
            done
        fi

        # Diagnostic mode - show raw audit output
        if [[ "$DIAGNOSTIC" == true ]]; then
            echo -e "${YELLOW}=== DIAGNOSTIC: Raw pip-audit output ===${RESET}"
            cat "$AUDIT_OUTPUT" | jq '.'
            echo -e "${YELLOW}=== DIAGNOSTIC: requirements.txt ===${RESET}"
            cat requirements.txt || echo "(no requirements.txt)"
            echo -e "${YELLOW}=== DIAGNOSTIC: Installed packages ===${RESET}"
            python3 -m pip list 2>/dev/null | head -20 || true
            echo -e "${YELLOW}=== END DIAGNOSTIC ===${RESET}"
        fi

        # Parse and display results
        parse_audit_results "$AUDIT_OUTPUT" "$NAME ($(basename $DIR))" "$TYPE"

        popd >/dev/null
    done < <(find . -name "requirements.txt" -not -path "*/site-packages/*" -not -path "*/.venv/*")

    # Also check for Poetry/Pipenv
    if [[ -f "pyproject.toml" ]] || [[ -f "Pipfile" ]]; then
        log_verbose "Found pyproject.toml or Pipfile - attempting audit..."
        
        local AUDIT_OUTPUT="$FUNC_DIR_ABS/audit_poetry.json"
        
        # Try to audit using pip-audit's automatic detection
        if python3 -m pip_audit --format json > "$AUDIT_OUTPUT" 2>&1; then
            found=true
            parse_audit_results "$AUDIT_OUTPUT" "$NAME (poetry/pipenv)" "$TYPE"
        fi
    fi

    if [[ "$found" == false ]]; then
        log_warning "No requirements.txt, pyproject.toml, or Pipfile found in $TYPE: $NAME"
    fi

    popd >/dev/null
}

# ====== Process Lambda Functions ======
process_functions() {
    log_section "Auditing Lambda Functions"

    local AWS_OPTS=""
    [[ -n "$PROFILE" ]] && AWS_OPTS="$AWS_OPTS --profile $PROFILE"
    [[ -n "$REGION" ]] && AWS_OPTS="$AWS_OPTS --region $REGION"

    log_info "Listing Lambda functions..."

    local FUNCTION_LIST
    FUNCTION_LIST=$(aws lambda list-functions $AWS_OPTS --query 'Functions[].FunctionName' --output json 2>/dev/null | jq -r '.[]' || echo "")

    if [[ -z "$FUNCTION_LIST" ]]; then
        log_warning "No Lambda functions found"
        return
    fi

    local TOTAL_FUNCS=$(echo "$FUNCTION_LIST" | wc -l | tr -d ' ')
    log_info "Found $TOTAL_FUNCS Lambda function(s)"
    echo

    while IFS= read -r FUNC; do
        [[ -z "$FUNC" ]] && continue

        echo -e "${BOLD}${CYAN}► Lambda Function:${RESET} ${BOLD}$FUNC${RESET}"

        local FUNC_INFO
        FUNC_INFO=$(aws lambda get-function $AWS_OPTS --function-name "$FUNC" --output json 2>/dev/null)

        local RUNTIME=$(echo "$FUNC_INFO" | jq -r '.Configuration.Runtime')
        echo -e "  Runtime: $RUNTIME"

        if [[ ! "$RUNTIME" =~ ^python ]]; then
            log_warning "  Skipping non-Python runtime"
            NON_PYTHON_COUNT=$((NON_PYTHON_COUNT + 1))
            echo
            continue
        fi

        PYTHON_COUNT=$((PYTHON_COUNT + 1))

        local FUNC_URL=$(echo "$FUNC_INFO" | jq -r '.Code.Location')
        if [[ -n "$FUNC_URL" ]]; then
            audit_package "$FUNC" "$FUNC_URL" "function"
        else
            log_error "  Could not retrieve function code location"
        fi

        # Collect layers for second pass
        local LAYERS=$(echo "$FUNC_INFO" | jq -r '.Configuration.Layers[]?.Arn // empty' 2>/dev/null)
        if [[ -n "$LAYERS" ]]; then
            echo -e "  ${BOLD}Layers:${RESET}"
            while IFS= read -r LAYER_ARN; do
                [[ -z "$LAYER_ARN" ]] && continue
                local LAYER_NAME=$(echo "$LAYER_ARN" | awk -F: '{print $(NF-1)}')
                local LAYER_VERSION=$(echo "$LAYER_ARN" | awk -F: '{print $NF}')
                echo -e "    - $LAYER_NAME:$LAYER_VERSION"
                LAYERS_TO_PROCESS["$LAYER_NAME:$LAYER_VERSION"]="$LAYER_ARN"
            done <<< "$LAYERS"
        fi

        echo
    done <<< "$FUNCTION_LIST"

    # Summary after functions
    log_section "Functions Audit Summary"
    log_success "Python Lambdas audited: ${BOLD}$PYTHON_COUNT${RESET}"
    [[ $NON_PYTHON_COUNT -gt 0 ]] && log_info "Non-Python Lambdas skipped: $NON_PYTHON_COUNT"
}

# ====== Process Lambda Layers ======
process_layers() {
    if [[ ${#LAYERS_TO_PROCESS[@]} -eq 0 ]]; then
        log_info "No Lambda layers to audit"
        return
    fi

    log_section "Auditing Lambda Layers"

    local AWS_OPTS=""
    [[ -n "$PROFILE" ]] && AWS_OPTS="$AWS_OPTS --profile $PROFILE"
    [[ -n "$REGION" ]] && AWS_OPTS="$AWS_OPTS --region $REGION"

    log_info "Found ${#LAYERS_TO_PROCESS[@]} unique layer(s) to audit"
    echo

    for key in "${!LAYERS_TO_PROCESS[@]}"; do
        local LAYER_NAME="${key%%:*}"
        local LAYER_VERSION="${key##*:}"

        echo -e "${BOLD}${CYAN}► Lambda Layer:${RESET} ${BOLD}$LAYER_NAME${RESET} (v${LAYER_VERSION})"

        local LAYER_INFO
        LAYER_INFO=$(aws lambda get-layer-version $AWS_OPTS --layer-name "$LAYER_NAME" --version-number "$LAYER_VERSION" --output json 2>/dev/null || echo "")

        if [[ -z "$LAYER_INFO" ]]; then
            log_error "  Failed to retrieve layer information"
            echo
            continue
        fi

        local LAYER_URL=$(echo "$LAYER_INFO" | jq -r '.Content.Location // empty')
        if [[ -n "$LAYER_URL" ]]; then
            audit_package "layer_${LAYER_NAME}_v${LAYER_VERSION}" "$LAYER_URL" "layer"
            LAYER_COUNT=$((LAYER_COUNT + 1))
        else
            log_error "  Could not retrieve layer code location"
        fi

        echo
    done

    log_section "Layers Audit Summary"
    log_success "Layers audited: ${BOLD}$LAYER_COUNT${RESET}"
}

# ====== Generate Final Report ======
generate_report() {
    log_section "Final Audit Report"

    echo -e "${BOLD}Scan Summary:${RESET}"
    echo -e "  Lambda Functions (Python): ${GREEN}$PYTHON_COUNT${RESET}"
    [[ $NON_PYTHON_COUNT -gt 0 ]] && echo -e "  Lambda Functions (Other): $NON_PYTHON_COUNT"
    echo -e "  Lambda Layers: ${GREEN}$LAYER_COUNT${RESET}"
    echo

    echo -e "${BOLD}Total Vulnerabilities Found:${RESET}"
    [[ $TOTAL_CRITICAL -gt 0 ]] && echo -e "  ${RED}${BOLD}Critical:${RESET} $TOTAL_CRITICAL"
    [[ $TOTAL_HIGH -gt 0 ]] && echo -e "  ${MAGENTA}High:${RESET} $TOTAL_HIGH"
    [[ $TOTAL_MEDIUM -gt 0 ]] && echo -e "  ${YELLOW}Medium:${RESET} $TOTAL_MEDIUM"
    [[ $TOTAL_LOW -gt 0 ]] && echo -e "  ${BLUE}Low:${RESET} $TOTAL_LOW"

    local GRAND_TOTAL=$((TOTAL_CRITICAL + TOTAL_HIGH + TOTAL_MEDIUM + TOTAL_LOW))
    if [[ $GRAND_TOTAL -eq 0 ]]; then
        echo
        log_success "No vulnerabilities detected! 🎉"
    else
        echo -e "  ${BOLD}Total: $GRAND_TOTAL${RESET}"
    fi

    # Detailed breakdown
    if [[ ${#AUDIT_RESULTS[@]} -gt 0 ]] && [[ $GRAND_TOTAL -gt 0 ]]; then
        echo
        echo -e "${BOLD}Detailed Breakdown:${RESET}"
        printf "  %-10s %-50s %8s %8s %8s %8s %8s\n" "Type" "Name" "Critical" "High" "Medium" "Low" "Total"
        printf "  %s\n" "$(printf '%.0s─' {1..120})"

        for result in "${AUDIT_RESULTS[@]}"; do
            IFS='|' read -r type name critical high medium low total <<< "$result"
            if [[ $total -gt 0 ]]; then
                # Truncate long names
                local display_name="${name:0:47}"
                [[ ${#name} -gt 47 ]] && display_name="${display_name}..."
                printf "  %-10s %-50s %8s %8s %8s %8s %8s\n" "$type" "$display_name" "$critical" "$high" "$medium" "$low" "$total"
            fi
        done
    fi

    # Exit code based on severity
    if [[ $TOTAL_CRITICAL -gt 0 ]] || [[ $TOTAL_HIGH -gt 0 ]]; then
        echo
        log_warning "High or Critical vulnerabilities detected!"
        return 1
    fi

    return 0
}

# ====== Export to JSON ======
export_json() {
    if [[ -z "$OUTPUT_JSON" ]]; then
        return
    fi

    log_info "Exporting results to: $OUTPUT_JSON"

    local JSON_CONTENT=$(cat <<EOF
{
  "scan_date": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "aws_account": "$(aws sts get-caller-identity $([[ -n "$PROFILE" ]] && echo "--profile $PROFILE") --query 'Account' --output text 2>/dev/null || echo "unknown")",
  "aws_region": "${REGION:-$(aws configure get region $([[ -n "$PROFILE" ]] && echo "--profile $PROFILE") 2>/dev/null || echo "us-east-1")}",
  "summary": {
    "total_functions": $PYTHON_COUNT,
    "total_layers": $LAYER_COUNT,
    "vulnerabilities": {
      "critical": $TOTAL_CRITICAL,
      "high": $TOTAL_HIGH,
      "medium": $TOTAL_MEDIUM,
      "low": $TOTAL_LOW,
      "total": $((TOTAL_CRITICAL + TOTAL_HIGH + TOTAL_MEDIUM + TOTAL_LOW))
    }
  },
  "results": [
EOF
)

    local first=true
    for result in "${AUDIT_RESULTS[@]}"; do
        IFS='|' read -r type name critical high medium low total <<< "$result"
        
        [[ "$first" == true ]] && first=false || JSON_CONTENT="$JSON_CONTENT,"
        
        JSON_CONTENT="$JSON_CONTENT
    {
      \"type\": \"$type\",
      \"name\": \"$name\",
      \"vulnerabilities\": {
        \"critical\": $critical,
        \"high\": $high,
        \"medium\": $medium,
        \"low\": $low,
        \"total\": $total
      }
    }"
    done

    JSON_CONTENT="$JSON_CONTENT
  ]
}"

    echo "$JSON_CONTENT" > "$OUTPUT_JSON"
    log_success "Results exported to $OUTPUT_JSON"
}

# ====== Cleanup ======
cleanup() {
    if [[ -d "$TMP_DIR" ]]; then
        log_verbose "Cleaning up temporary directory: $TMP_DIR"
        rm -rf "$TMP_DIR"
    fi
}

# ====== Main ======
main() {
    # Trap cleanup on exit
    trap cleanup EXIT

    init "$@"
    process_functions
    process_layers
    
    echo
    generate_report
    local EXIT_CODE=$?
    
    export_json
    
    echo
    log_section "Audit Complete"
    
    exit $EXIT_CODE
}

main "$@"
