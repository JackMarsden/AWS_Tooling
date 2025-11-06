#!/usr/bin/env bash
#
# Lambda NPM Audit Script
# Audits all Node.js Lambda functions for npm package vulnerabilities
#
# Usage: ./lambda_audit.sh [OPTIONS]
#
# Options:
#   --profile PROFILE    AWS profile to use
#   --region REGION      AWS region to scan
#   --v                  Verbose output (shows npm audit results in terminal)
#   --help               Show this help message
#

set -uo pipefail

# Disable unbound variable check for specific cases
set +u

# Configuration
PROFILE=""
REGION=""
VERBOSE=false
TMP_DIR=""

# Colors
RED="\e[31m"
GREEN="\e[32m"
YELLOW="\e[33m"
CYAN="\e[36m"
BOLD="\e[1m"
RESET="\e[0m"

# Counters
NODEJS_COUNT=0
NON_NODEJS_COUNT=0
LAYER_COUNT=0
TOTAL_CRITICAL=0
TOTAL_HIGH=0
TOTAL_MODERATE=0
TOTAL_LOW=0
TOTAL_INFO=0

# Arrays to store results
declare -a FUNCTION_NAMES
declare -A FUNCTION_RESULTS

show_help() {
    cat << EOF
Lambda NPM Audit Script

Audits all Node.js Lambda functions for npm package vulnerabilities.

USAGE:
    $0 [OPTIONS]

OPTIONS:
    --profile PROFILE    AWS profile to use
    --region REGION      AWS region to scan
    --v                  Verbose output (shows npm audit in terminal)
    --help               Show this help message

EXAMPLES:
    $0
    $0 --profile prod --region us-east-1 --v
EOF
}

log_info() {
    echo -e "${CYAN}ℹ${RESET} $*"
}

log_success() {
    echo -e "${GREEN}✓${RESET} $*"
}

log_error() {
    echo -e "${RED}✗${RESET} $*"
}

log_section() {
    echo
    echo -e "${BOLD}${CYAN}═══════════════════════════════════════════════════════${RESET}"
    echo -e "${BOLD}${CYAN} $*${RESET}"
    echo -e "${BOLD}${CYAN}═══════════════════════════════════════════════════════${RESET}"
    echo
}

# Parse arguments
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

log_section "Lambda NPM Audit - Initialization"

# Check dependencies
log_info "Checking required dependencies..."
MISSING_DEPS=()
for cmd in aws jq unzip npm curl; do
    if ! command -v $cmd >/dev/null 2>&1; then
        MISSING_DEPS+=("$cmd")
    fi
done

if [[ ${#MISSING_DEPS[@]} -gt 0 ]]; then
    log_error "Missing required dependencies: ${MISSING_DEPS[*]}"
    echo "Please install the missing dependencies and try again."
    exit 1
fi
log_success "All dependencies found (aws, jq, unzip, npm, curl)"

# Build AWS CLI options
AWS_OPTS=""
[[ -n "$PROFILE" ]] && AWS_OPTS="$AWS_OPTS --profile $PROFILE"
[[ -n "$REGION" ]] && AWS_OPTS="$AWS_OPTS --region $REGION"

# Verify AWS authentication
log_info "Verifying AWS authentication..."
if [[ -n "$PROFILE" ]]; then
    echo -e "  ${BOLD}Profile:${RESET} $PROFILE"
else
    echo -e "  ${BOLD}Profile:${RESET} default"
fi

# Test AWS credentials
if ! AWS_IDENTITY=$(aws sts get-caller-identity $AWS_OPTS --output json 2>&1); then
    log_error "AWS authentication failed"
    echo
    echo "Error details:"
    echo "$AWS_IDENTITY"
    echo
    if [[ -n "$PROFILE" ]]; then
        echo "Please verify:"
        echo "  1. Profile '$PROFILE' exists in ~/.aws/credentials or ~/.aws/config"
        echo "  2. Profile has valid credentials"
        echo "  3. You have network connectivity to AWS"
    else
        echo "Please verify:"
        echo "  1. AWS credentials are configured (run 'aws configure')"
        echo "  2. You have network connectivity to AWS"
    fi
    exit 1
fi

# Display authentication info
ACCOUNT_ID=$(echo "$AWS_IDENTITY" | jq -r '.Account')
USER_ARN=$(echo "$AWS_IDENTITY" | jq -r '.Arn')
CURRENT_REGION=$(aws configure get region $([[ -n "$PROFILE" ]] && echo "--profile $PROFILE") 2>/dev/null || echo "us-east-1")
[[ -n "$REGION" ]] && CURRENT_REGION="$REGION"

log_success "AWS authentication successful"
echo -e "  ${BOLD}Account ID:${RESET} $ACCOUNT_ID"
echo -e "  ${BOLD}Identity:${RESET} $USER_ARN"
echo -e "  ${BOLD}Region:${RESET} $CURRENT_REGION"

log_section "Lambda NPM Audit"

# Step 1: Create temp directory and cd into it
TMP_DIR="./lambda_audit_$(date +%s)"
mkdir -p "$TMP_DIR"
cd "$TMP_DIR"
log_success "Created temp directory: $TMP_DIR"

# Cleanup on exit
cleanup() {
    if [[ -n "$TMP_DIR" ]] && [[ -d "$TMP_DIR" ]]; then
        cd ..
        # Remove zip files and unzipped directories, keep result files
        find "$TMP_DIR" -name "*.zip" -delete 2>/dev/null || true
        find "$TMP_DIR" -type d -mindepth 1 -exec rm -rf {} + 2>/dev/null || true
        log_info "Cleaned up zip files and directories (kept audit results)"
    fi
}
trap cleanup EXIT

# Step 2: Download only Node.js Lambda functions
log_info "Fetching Node.js Lambda functions..."

# Get list of Node.js functions with their runtimes
FUNCTIONS_JSON=$(aws lambda list-functions $AWS_OPTS --query 'Functions[?starts_with(Runtime, `nodejs`)].[FunctionName, Runtime]' --output json)
FUNC_COUNT=$(echo "$FUNCTIONS_JSON" | jq -r '. | length')

if [[ $FUNC_COUNT -eq 0 ]]; then
    log_error "No Node.js Lambda functions found"
    exit 0
fi

log_success "Found $FUNC_COUNT Node.js Lambda function(s)"
echo

# Display table of functions to download
echo -e "${BOLD}Node.js Lambda Functions:${RESET}"
echo "$FUNCTIONS_JSON" | jq -r '.[] | "  - \(.[0]) (\(.[1]))"'
echo

# Download all Node.js functions
echo "$FUNCTIONS_JSON" | jq -r '.[][0]' | while read -r FUNC_NAME; do
    log_info "Downloading: $FUNC_NAME"
    
    # Get function code location
    if ! CODE_URL=$(aws lambda get-function $AWS_OPTS --function-name "$FUNC_NAME" --query 'Code.Location' --output text 2>&1); then
        log_error "Failed to get code URL for $FUNC_NAME: $CODE_URL"
        continue
    fi
    
    if [[ -z "$CODE_URL" ]] || [[ "$CODE_URL" == "None" ]]; then
        log_error "No code URL available for $FUNC_NAME"
        continue
    fi
    
    # Download zip file with retries
    RETRY_COUNT=0
    MAX_RETRIES=3
    DOWNLOAD_SUCCESS=false
    
    while [[ $RETRY_COUNT -lt $MAX_RETRIES ]]; do
        if curl -sL -f -o "${FUNC_NAME}.zip" "$CODE_URL" 2>/dev/null; then
            DOWNLOAD_SUCCESS=true
            break
        fi
        RETRY_COUNT=$((RETRY_COUNT + 1))
        [[ $RETRY_COUNT -lt $MAX_RETRIES ]] && sleep 2
    done
    
    if [[ "$DOWNLOAD_SUCCESS" == true ]]; then
        log_success "Downloaded: ${FUNC_NAME}.zip"
    else
        log_error "Failed to download after $MAX_RETRIES attempts: $FUNC_NAME"
    fi
done

echo
log_section "Processing Lambda Functions"

# Step 3 & 4: Unzip and audit each function
for ZIP_FILE in *.zip; do
    [[ ! -f "$ZIP_FILE" ]] && continue
    
    FUNC_NAME="${ZIP_FILE%.zip}"
    FUNC_DIR="$FUNC_NAME"
    
    # Add function name to array
    FUNCTION_NAMES+=("$FUNC_NAME")
    
    # Initialize counters for this function
    FUNCTION_RESULTS["$FUNC_NAME"]="0|0|0|0|0"
    
    echo -e "${BOLD}Processing: $FUNC_NAME${RESET}"
    
    # Unzip into its own directory
    mkdir -p "$FUNC_DIR"
    if ! unzip -q "$ZIP_FILE" -d "$FUNC_DIR" 2>/dev/null; then
        log_error "Failed to unzip: $ZIP_FILE"
        continue
    fi
    
    # Find all package.json files (excluding node_modules)
    PACKAGE_JSONS=$(find "$FUNC_DIR" -type f -name "package.json" -not -path "*/node_modules/*" 2>/dev/null || true)
    
    if [[ -z "$PACKAGE_JSONS" ]]; then
        log_error "No package.json found in $FUNC_NAME"
        echo
        continue
    fi
    
    # Count how many package.json files found
    PKG_COUNT=$(echo "$PACKAGE_JSONS" | wc -l | tr -d ' ')
    log_info "Found $PKG_COUNT package.json file(s) to audit"
    
    # Run npm audit for each package.json found
    PKG_NUM=0
    while IFS= read -r PKG_JSON; do
        PKG_NUM=$((PKG_NUM + 1))
        PKG_DIR=$(dirname "$PKG_JSON")
        
        # Get the absolute path of the package directory
        PKG_DIR_ABS=$(cd "$PKG_DIR" && pwd)
        
        # Create a unique identifier for this package location
        PKG_SUBPATH=$(echo "$PKG_DIR_ABS" | sed "s|^$(cd "$FUNC_DIR" && pwd)||" | sed 's|^/||' | tr '/' '_')
        [[ -z "$PKG_SUBPATH" ]] && PKG_SUBPATH="root"
        
        log_info "Auditing [$PKG_NUM/$PKG_COUNT]: $PKG_DIR"
        
        # Get absolute path for audit file with unique name for each package.json
        AUDIT_FILE="$(pwd)/${FUNC_NAME}-${PKG_SUBPATH}-auditResults.json"
        
        (
            cd "$PKG_DIR_ABS" || exit 0
            
            # Check if there's actually a real package.json (not in node_modules)
            if [[ ! -f "package.json" ]]; then
                log_error "  package.json not found in current directory"
                exit 0
            fi
            
            # Generate package-lock.json if missing (and it's not a hidden file)
            if [[ ! -f "package-lock.json" ]]; then
                log_info "  Generating package-lock.json..."
                npm install --package-lock-only >/dev/null 2>&1 || true
            fi
            
            # Skip if we still don't have a proper package-lock.json after generation
            if [[ ! -f "package-lock.json" ]]; then
                log_error "  Could not generate package-lock.json, skipping..."
                echo '{"metadata":{"vulnerabilities":{"critical":0,"high":0,"moderate":0,"low":0,"info":0,"total":0},"error":"no_package_lock"}}' > "$AUDIT_FILE" 2>/dev/null || true
                exit 0
            fi
            
            # Run npm audit
            if [[ "$VERBOSE" == true ]]; then
                # Show output in terminal AND save to file
                npm audit --json 2>&1 | tee "$AUDIT_FILE" || true
            else
                # Silent mode - only save to file
                npm audit --json > "$AUDIT_FILE" 2>&1 || true
            fi
            
            # Check if we got valid JSON
            if [[ -s "$AUDIT_FILE" ]] && jq empty "$AUDIT_FILE" 2>/dev/null; then
                # Parse vulnerability counts
                CRITICAL=$(jq -r '.metadata.vulnerabilities.critical // 0' "$AUDIT_FILE" 2>/dev/null || echo 0)
                HIGH=$(jq -r '.metadata.vulnerabilities.high // 0' "$AUDIT_FILE" 2>/dev/null || echo 0)
                MODERATE=$(jq -r '.metadata.vulnerabilities.moderate // 0' "$AUDIT_FILE" 2>/dev/null || echo 0)
                LOW=$(jq -r '.metadata.vulnerabilities.low // 0' "$AUDIT_FILE" 2>/dev/null || echo 0)
                INFO=$(jq -r '.metadata.vulnerabilities.info // 0' "$AUDIT_FILE" 2>/dev/null || echo 0)
                TOTAL=$(jq -r '.metadata.vulnerabilities.total // 0' "$AUDIT_FILE" 2>/dev/null || echo 0)
                
                if [[ $TOTAL -gt 0 ]]; then
                    echo -e "  ${RED}Critical: $CRITICAL${RESET} | ${YELLOW}High: $HIGH${RESET} | Moderate: $MODERATE | Low: $LOW | Info: $INFO | ${BOLD}Total: $TOTAL${RESET}"
                else
                    log_success "  No vulnerabilities found"
                fi
            else
                log_error "  Failed to generate valid audit results"
                # Create empty result file with error handling
                mkdir -p "$(dirname "$AUDIT_FILE")" 2>/dev/null || true
                echo '{"metadata":{"vulnerabilities":{"critical":0,"high":0,"moderate":0,"low":0,"info":0,"total":0},"error":"invalid_audit_output"}}' > "$AUDIT_FILE" 2>/dev/null || true
            fi
        ) || {
            log_error "  Audit failed for $PKG_DIR, continuing with next package..."
            # Create error result file with path safety
            mkdir -p "$(dirname "$AUDIT_FILE")" 2>/dev/null || true
            echo '{"metadata":{"vulnerabilities":{"critical":0,"high":0,"moderate":0,"low":0,"info":0,"total":0},"error":"audit_failed"}}' > "$AUDIT_FILE" 2>/dev/null || true
        }
    done <<< "$PACKAGE_JSONS"
    
    echo
done

# Aggregate results per function after all functions have been processed
log_section "Aggregating Results"

# Process each function we tracked
for FUNC_NAME in "${FUNCTION_NAMES[@]}"; do
    FUNC_CRITICAL=0
    FUNC_HIGH=0
    FUNC_MODERATE=0
    FUNC_LOW=0
    FUNC_INFO=0
    
    # Find all audit result files for this function
    for RESULT_FILE in "${FUNC_NAME}"-*-auditResults.json; do
        [[ ! -f "$RESULT_FILE" ]] && continue
        
        if jq empty "$RESULT_FILE" 2>/dev/null; then
            FUNC_CRITICAL=$((FUNC_CRITICAL + $(jq -r '.metadata.vulnerabilities.critical // 0' "$RESULT_FILE" 2>/dev/null || echo 0)))
            FUNC_HIGH=$((FUNC_HIGH + $(jq -r '.metadata.vulnerabilities.high // 0' "$RESULT_FILE" 2>/dev/null || echo 0)))
            FUNC_MODERATE=$((FUNC_MODERATE + $(jq -r '.metadata.vulnerabilities.moderate // 0' "$RESULT_FILE" 2>/dev/null || echo 0)))
            FUNC_LOW=$((FUNC_LOW + $(jq -r '.metadata.vulnerabilities.low // 0' "$RESULT_FILE" 2>/dev/null || echo 0)))
            FUNC_INFO=$((FUNC_INFO + $(jq -r '.metadata.vulnerabilities.info // 0' "$RESULT_FILE" 2>/dev/null || echo 0)))
        fi
    done
    
    # Store function totals
    FUNCTION_RESULTS["$FUNC_NAME"]="$FUNC_CRITICAL|$FUNC_HIGH|$FUNC_MODERATE|$FUNC_LOW|$FUNC_INFO"
    
    # Update global totals
    TOTAL_CRITICAL=$((TOTAL_CRITICAL + FUNC_CRITICAL))
    TOTAL_HIGH=$((TOTAL_HIGH + FUNC_HIGH))
    TOTAL_MODERATE=$((TOTAL_MODERATE + FUNC_MODERATE))
    TOTAL_LOW=$((TOTAL_LOW + FUNC_LOW))
    TOTAL_INFO=$((TOTAL_INFO + FUNC_INFO))
done

log_success "Aggregation complete"

# Step 5: Remove downloaded zips and unzipped directories
log_section "Cleanup"
log_info "Removing zip files and unzipped directories..."

for ZIP_FILE in *.zip; do
    [[ -f "$ZIP_FILE" ]] && rm -f "$ZIP_FILE"
done

for DIR in */; do
    [[ -d "$DIR" ]] && rm -rf "$DIR"
done

log_success "Cleanup complete"

# Show final results
echo
log_section "Audit Results Summary"

# Calculate grand total
GRAND_TOTAL=$((TOTAL_CRITICAL + TOTAL_HIGH + TOTAL_MODERATE + TOTAL_LOW + TOTAL_INFO))

# Display overall summary
echo -e "${BOLD}Overall Vulnerability Summary:${RESET}"
echo
printf "  %-15s %8s\n" "Severity" "Count"
printf "  %s\n" "$(printf '%.0s─' {1..25})"
[[ $TOTAL_CRITICAL -gt 0 ]] && printf "  ${RED}%-15s${RESET} %8d\n" "Critical" "$TOTAL_CRITICAL" || printf "  %-15s %8d\n" "Critical" "$TOTAL_CRITICAL"
[[ $TOTAL_HIGH -gt 0 ]] && printf "  ${YELLOW}%-15s${RESET} %8d\n" "High" "$TOTAL_HIGH" || printf "  %-15s %8d\n" "High" "$TOTAL_HIGH"
[[ $TOTAL_MODERATE -gt 0 ]] && printf "  ${CYAN}%-15s${RESET} %8d\n" "Moderate" "$TOTAL_MODERATE" || printf "  %-15s %8d\n" "Moderate" "$TOTAL_MODERATE"
printf "  %-15s %8d\n" "Low" "$TOTAL_LOW"
printf "  %-15s %8d\n" "Info" "$TOTAL_INFO"
printf "  %s\n" "$(printf '%.0s─' {1..25})"
printf "  ${BOLD}%-15s %8d${RESET}\n" "TOTAL" "$GRAND_TOTAL"

echo
echo

# Display per-function breakdown
if [[ ${#FUNCTION_NAMES[@]} -gt 0 ]]; then
    echo -e "${BOLD}Vulnerabilities by Lambda Function:${RESET}"
    echo
    printf "  %-40s %10s %10s %10s %10s %10s %10s\n" "Function Name" "Critical" "High" "Moderate" "Low" "Info" "Total"
    printf "  %s\n" "$(printf '%.0s─' {1..100})"
    
    # Sort function names by total vulnerabilities (highest first)
    for FUNC_NAME in $(for name in "${FUNCTION_NAMES[@]}"; do
        IFS='|' read -r crit high mod low info <<< "${FUNCTION_RESULTS[$name]}"
        total=$((crit + high + mod + low + info))
        echo "$total|$name"
    done | sort -rn | cut -d'|' -f2); do
        
        IFS='|' read -r CRIT HIGH MOD LOW INFO <<< "${FUNCTION_RESULTS[$FUNC_NAME]}"
        FUNC_TOTAL=$((CRIT + HIGH + MOD + LOW + INFO))
        
        # Truncate long function names
        DISPLAY_NAME="$FUNC_NAME"
        if [[ ${#DISPLAY_NAME} -gt 38 ]]; then
            DISPLAY_NAME="${DISPLAY_NAME:0:35}..."
        fi
        
        # Color code the row if it has critical or high vulnerabilities
        if [[ $CRIT -gt 0 ]]; then
            printf "  ${RED}%-40s %10d %10d %10d %10d %10d %10d${RESET}\n" "$DISPLAY_NAME" "$CRIT" "$HIGH" "$MOD" "$LOW" "$INFO" "$FUNC_TOTAL"
        elif [[ $HIGH -gt 0 ]]; then
            printf "  ${YELLOW}%-40s %10d %10d %10d %10d %10d %10d${RESET}\n" "$DISPLAY_NAME" "$CRIT" "$HIGH" "$MOD" "$LOW" "$INFO" "$FUNC_TOTAL"
        else
            printf "  %-40s %10d %10d %10d %10d %10d %10d\n" "$DISPLAY_NAME" "$CRIT" "$HIGH" "$MOD" "$LOW" "$INFO" "$FUNC_TOTAL"
        fi
    done
    
    printf "  %s\n" "$(printf '%.0s─' {1..100})"
    printf "  ${BOLD}%-40s %10d %10d %10d %10d %10d %10d${RESET}\n" "TOTAL" "$TOTAL_CRITICAL" "$TOTAL_HIGH" "$TOTAL_MODERATE" "$TOTAL_LOW" "$TOTAL_INFO" "$GRAND_TOTAL"
fi

echo
echo

# Show result files location
RESULT_FILES=$(ls *-auditResults.json 2>/dev/null || true)

if [[ -z "$RESULT_FILES" ]]; then
    log_error "No audit result files found"
else
    RESULT_COUNT=$(echo "$RESULT_FILES" | wc -l | tr -d ' ')
    log_success "Generated $RESULT_COUNT audit result file(s) in: $(pwd)"
    
    if [[ $GRAND_TOTAL -eq 0 ]]; then
        echo
        log_success "🎉 No vulnerabilities detected across all Lambda functions!"
    elif [[ $TOTAL_CRITICAL -gt 0 ]] || [[ $TOTAL_HIGH -gt 0 ]]; then
        echo
        log_error "⚠️  Critical or High severity vulnerabilities detected!"
        log_info "Review the audit result files for detailed information"
    fi
fi

echo
log_info "All audit results saved in: $(pwd)"
