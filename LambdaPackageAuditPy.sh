#!/usr/bin/env bash
#
# Lambda Python Security Audit Script
# Audits all Python Lambda functions for package vulnerabilities using pip-audit
#
# Usage: ./lambda_audit_python.sh [OPTIONS]
#
# Options:
#   --profile PROFILE    AWS profile to use
#   --region REGION      AWS region to scan
#   --mode MODE          Operation mode: audit (default), download, auditLocal
#   --v                  Verbose output (shows pip-audit results in terminal)
#   --help               Show this help message
#

set -uo pipefail

# Disable unbound variable check for specific cases
set +u

# Configuration
PROFILE=""
REGION=""
VERBOSE=false
MODE="audit"
TMP_DIR=""

# Colors
RED="\e[31m"
GREEN="\e[32m"
YELLOW="\e[33m"
CYAN="\e[36m"
BOLD="\e[1m"
RESET="\e[0m"

# Counters
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
Lambda Python Security Audit Script

Audits all Python Lambda functions for package vulnerabilities using pip-audit.

USAGE:
    $0 [OPTIONS]

OPTIONS:
    --profile PROFILE    AWS profile to use
    --region REGION      AWS region to scan
    --mode MODE          Operation mode (default: audit)
                           audit       - Download and audit Lambda functions
                           download    - Only download Lambda functions
                           auditLocal  - Audit Lambda functions in current directory
    --v                  Verbose output (shows pip-audit in terminal)
    --help               Show this help message

EXAMPLES:
    $0
    $0 --profile prod --region us-east-1 --v
    $0 --mode download --profile prod
    $0 --mode auditLocal
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
        --mode)
            MODE="$2"
            if [[ "$MODE" != "audit" ]] && [[ "$MODE" != "download" ]] && [[ "$MODE" != "auditLocal" ]]; then
                log_error "Invalid mode: $MODE. Must be 'audit', 'download', or 'auditLocal'"
                show_help
                exit 1
            fi
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

log_section "Lambda Python Security Audit - Initialization"

# Check dependencies based on mode
log_info "Checking required dependencies..."
MISSING_DEPS=()

if [[ "$MODE" == "auditLocal" ]]; then
    # auditLocal mode only needs pip-audit and jq
    for cmd in jq pip-audit; do
        if ! command -v $cmd >/dev/null 2>&1; then
            MISSING_DEPS+=("$cmd")
        fi
    done
else
    # audit and download modes need all dependencies
    for cmd in aws jq unzip pip-audit curl; do
        if ! command -v $cmd >/dev/null 2>&1; then
            MISSING_DEPS+=("$cmd")
        fi
    done
fi

if [[ ${#MISSING_DEPS[@]} -gt 0 ]]; then
    log_error "Missing required dependencies: ${MISSING_DEPS[*]}"
    echo "Please install the missing dependencies and try again."
    echo ""
    echo "To install pip-audit:"
    echo "  pip install pip-audit"
    echo "  or"
    echo "  pipx install pip-audit"
    exit 1
fi

if [[ "$MODE" == "auditLocal" ]]; then
    log_success "All dependencies found (jq, pip-audit)"
else
    log_success "All dependencies found (aws, jq, unzip, pip-audit, curl)"
fi

# Build AWS CLI options
AWS_OPTS=""
[[ -n "$PROFILE" ]] && AWS_OPTS="$AWS_OPTS --profile $PROFILE"
[[ -n "$REGION" ]] && AWS_OPTS="$AWS_OPTS --region $REGION"

# Verify AWS authentication (skip for auditLocal mode)
if [[ "$MODE" != "auditLocal" ]]; then
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
fi

log_section "Lambda Python Security Audit"

# Mode-specific setup
if [[ "$MODE" == "auditLocal" ]]; then
    log_info "Mode: Audit Local - Processing Lambda functions in current directory"
    TMP_DIR="."
    
    # Check if there are any zip files in current directory
    ZIP_COUNT=$(ls -1 *.zip 2>/dev/null | wc -l | tr -d ' ')
    if [[ $ZIP_COUNT -eq 0 ]]; then
        log_error "No Lambda function zip files found in current directory"
        echo "Please ensure you have Lambda function zip files in the current directory"
        exit 1
    fi
    
    log_success "Found $ZIP_COUNT Lambda function zip file(s) to audit"
    
else
    # Step 1: Create temp directory and cd into it
    TMP_DIR="./lambda_audit_python_$(date +%s)"
    mkdir -p "$TMP_DIR"
    cd "$TMP_DIR"
    log_success "Created temp directory: $TMP_DIR"
fi

# Cleanup on exit
cleanup() {
    if [[ "$MODE" == "auditLocal" ]]; then
        # For auditLocal mode, only clean up unzipped directories
        if [[ -n "$TMP_DIR" ]] && [[ -d "$TMP_DIR" ]]; then
            find "$TMP_DIR" -type d -mindepth 1 -maxdepth 1 -not -name "*auditResults.json" -exec rm -rf {} + 2>/dev/null || true
            log_info "Cleaned up unzipped directories (kept zip files and audit results)"
        fi
    elif [[ "$MODE" == "download" ]]; then
        # For download mode, don't clean up anything
        log_info "Download mode: Keeping all downloaded files"
    else
        # For audit mode, clean up as usual
        if [[ -n "$TMP_DIR" ]] && [[ -d "$TMP_DIR" ]]; then
            cd ..
            # Remove zip files and unzipped directories, keep result files
            find "$TMP_DIR" -name "*.zip" -delete 2>/dev/null || true
            find "$TMP_DIR" -type d -mindepth 1 -exec rm -rf {} + 2>/dev/null || true
            log_info "Cleaned up zip files and directories (kept audit results)"
        fi
    fi
}
trap cleanup EXIT

# Step 2: Download only Python Lambda functions (skip for auditLocal mode)
if [[ "$MODE" != "auditLocal" ]]; then
    log_info "Fetching Python Lambda functions..."

    # Get list of Python functions with their runtimes
    FUNCTIONS_JSON=$(aws lambda list-functions $AWS_OPTS --query 'Functions[?starts_with(Runtime, `python`)].[FunctionName, Runtime]' --output json)
    FUNC_COUNT=$(echo "$FUNCTIONS_JSON" | jq -r '. | length')

    if [[ $FUNC_COUNT -eq 0 ]]; then
        log_error "No Python Lambda functions found"
        exit 0
    fi

    log_success "Found $FUNC_COUNT Python Lambda function(s)"
    echo

    # Display table of functions to download
    echo -e "${BOLD}Python Lambda Functions:${RESET}"
    echo "$FUNCTIONS_JSON" | jq -r '.[] | "  - \(.[0]) (\(.[1]))"'
    echo

    # Download all Python functions
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
    
    # If download mode, exit here
    if [[ "$MODE" == "download" ]]; then
        log_section "Download Complete"
        log_success "All Lambda functions downloaded to: $(pwd)"
        exit 0
    fi
    
    log_section "Processing Lambda Functions"
fi

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
    
    # Strategy: Look for Python package directories
    # 1. Find requirements.txt files
    # 2. Find site-packages directories
    # 3. Find directories with .dist-info (installed packages)
    # 4. If nothing found, scan the entire function directory
    
    REQUIREMENTS_FILES=$(find "$FUNC_DIR" -type f -name "requirements.txt" 2>/dev/null || true)
    SITE_PACKAGES_DIRS=$(find "$FUNC_DIR" -type d -name "site-packages" 2>/dev/null || true)
    DIST_INFO_DIRS=$(find "$FUNC_DIR" -type d -name "*.dist-info" 2>/dev/null | head -1 || true)
    
    # Combine into audit targets
    AUDIT_TARGETS=""
    
    if [[ -n "$REQUIREMENTS_FILES" ]]; then
        AUDIT_TARGETS="$REQUIREMENTS_FILES"
    fi
    
    if [[ -n "$SITE_PACKAGES_DIRS" ]]; then
        if [[ -n "$AUDIT_TARGETS" ]]; then
            AUDIT_TARGETS="$AUDIT_TARGETS"$'\n'"$SITE_PACKAGES_DIRS"
        else
            AUDIT_TARGETS="$SITE_PACKAGES_DIRS"
        fi
    fi
    
    # If we found .dist-info but no site-packages, scan parent directory
    if [[ -z "$AUDIT_TARGETS" ]] && [[ -n "$DIST_INFO_DIRS" ]]; then
        PARENT_DIR=$(dirname "$DIST_INFO_DIRS")
        log_info "Found .dist-info in $PARENT_DIR, will scan that directory"
        AUDIT_TARGETS="$PARENT_DIR|path"
    fi
    
    # If nothing found, scan the entire function directory
    if [[ -z "$AUDIT_TARGETS" ]]; then
        log_info "No standard package structure found, scanning entire function directory"
        AUDIT_TARGETS="$FUNC_DIR|path"
    fi
    
    # Count how many targets found
    TARGET_COUNT=$(echo "$AUDIT_TARGETS" | wc -l | tr -d ' ')
    log_info "Found $TARGET_COUNT audit target(s)"
    
    # Run pip-audit for each target found
    TARGET_NUM=0
    while IFS= read -r TARGET_PATH; do
        [[ -z "$TARGET_PATH" ]] && continue
        
        TARGET_NUM=$((TARGET_NUM + 1))
        
        # Check if this is a special path-based target
        if [[ "$TARGET_PATH" == *"|path" ]]; then
            TARGET_PATH="${TARGET_PATH%|path}"
            TARGET_TYPE="directory"
            TARGET_DIR="$TARGET_PATH"
            TARGET_NAME="$(basename "$TARGET_PATH")"
        elif [[ -f "$TARGET_PATH" ]]; then
            TARGET_TYPE="requirements"
            TARGET_DIR=$(dirname "$TARGET_PATH")
            TARGET_NAME=$(basename "$TARGET_PATH")
        else
            TARGET_TYPE="site-packages"
            TARGET_DIR="$TARGET_PATH"
            TARGET_NAME="site-packages"
        fi
        
        # Get the absolute path
        TARGET_DIR_ABS=$(cd "$TARGET_DIR" && pwd)
        
        # Create a unique identifier for this target location
        FUNC_DIR_ABS=$(cd "$FUNC_DIR" && pwd)
        TARGET_SUBPATH=$(echo "$TARGET_DIR_ABS" | sed "s|^${FUNC_DIR_ABS}||" | sed 's|^/||' | tr '/' '_')
        [[ -z "$TARGET_SUBPATH" ]] && TARGET_SUBPATH="root"
        TARGET_SUBPATH="${TARGET_SUBPATH}_${TARGET_NAME}"
        
        log_info "Auditing [$TARGET_NUM/$TARGET_COUNT]: $TARGET_SUBPATH ($TARGET_TYPE)"
        
        # Get absolute path for audit file with unique name for each target
        AUDIT_FILE="$(pwd)/${FUNC_NAME}-${TARGET_SUBPATH}-auditResults.json"
        
        # Run the audit in a subshell
        (
            cd "$TARGET_DIR_ABS" || exit 0
            
            # Run pip-audit based on target type
            if [[ "$TARGET_TYPE" == "requirements" ]]; then
                if [[ ! -f "$TARGET_NAME" ]]; then
                    log_error "  $TARGET_NAME not found"
                    exit 0
                fi
                
                if [[ "$VERBOSE" == true ]]; then
                    pip-audit -r "$TARGET_NAME" --format json 2>&1 | tee "$AUDIT_FILE" || true
                else
                    pip-audit -r "$TARGET_NAME" --format json > "$AUDIT_FILE" 2>&1 || true
                fi
            elif [[ "$TARGET_TYPE" == "directory" ]]; then
                # Generate a temporary requirements.txt from .dist-info directories
                log_info "  Generating requirements from installed packages..."
                
                TEMP_REQ="$(mktemp)"
                
                # Find all .dist-info directories and extract package names/versions
                # Use process substitution to avoid subshell issues
                while read -r dist_info; do
                    METADATA_FILE="$dist_info/METADATA"
                    if [[ -f "$METADATA_FILE" ]]; then
                        # Extract Name and Version from METADATA
                        PKG_NAME=$(grep "^Name:" "$METADATA_FILE" | head -1 | cut -d' ' -f2- | tr -d '[:space:]')
                        PKG_VERSION=$(grep "^Version:" "$METADATA_FILE" | head -1 | cut -d' ' -f2- | tr -d '[:space:]')
                        
                        if [[ -n "$PKG_NAME" ]] && [[ -n "$PKG_VERSION" ]]; then
                            echo "${PKG_NAME}==${PKG_VERSION}" >> "$TEMP_REQ"
                        fi
                    fi
                done < <(find . -type d -name "*.dist-info" 2>/dev/null)
                
                # Check if we found any packages
                if [[ -s "$TEMP_REQ" ]]; then
                    PKG_COUNT=$(wc -l < "$TEMP_REQ" | tr -d ' ')
                    log_info "  Found $PKG_COUNT package(s) to audit"
                    
                    if [[ "$VERBOSE" == true ]]; then
                        echo "  Packages found:"
                        cat "$TEMP_REQ" | sed 's/^/    /'
                        pip-audit -r "$TEMP_REQ" --format json 2>&1 | tee "$AUDIT_FILE" || true
                    else
                        pip-audit -r "$TEMP_REQ" --format json > "$AUDIT_FILE" 2>&1 || true
                    fi
                else
                    log_error "  No packages found in directory"
                    echo '{"dependencies":[]}' > "$AUDIT_FILE"
                fi
                
                rm -f "$TEMP_REQ"
            else
                # site-packages directory
                if [[ "$VERBOSE" == true ]]; then
                    pip-audit --format json 2>&1 | tee "$AUDIT_FILE" || true
                else
                    pip-audit --format json > "$AUDIT_FILE" 2>&1 || true
                fi
            fi
            
            # Parse results
            if [[ -s "$AUDIT_FILE" ]] && jq empty "$AUDIT_FILE" 2>/dev/null; then
                TOTAL=$(jq -r '.dependencies // [] | length' "$AUDIT_FILE" 2>/dev/null || echo 0)
                
                CRITICAL=0
                HIGH=0
                MODERATE=0
                LOW=0
                INFO=0
                
                if [[ $TOTAL -gt 0 ]]; then
                    while read -r vuln; do
                        MODERATE=$((MODERATE + 1))
                    done < <(jq -c '.dependencies[]?' "$AUDIT_FILE" 2>/dev/null || echo "[]")
                    
                    echo -e "  ${YELLOW}Vulnerabilities found: $TOTAL${RESET}"
                else
                    log_success "  No vulnerabilities found"
                fi
                
                jq -n \
                    --arg total "$TOTAL" \
                    --arg critical "$CRITICAL" \
                    --arg high "$HIGH" \
                    --arg moderate "$MODERATE" \
                    --arg low "$LOW" \
                    --arg info "$INFO" \
                    '{metadata: {vulnerabilities: {critical: ($critical|tonumber), high: ($high|tonumber), moderate: ($moderate|tonumber), low: ($low|tonumber), info: ($info|tonumber), total: ($total|tonumber)}}}' \
                    > "${AUDIT_FILE}.summary" 2>/dev/null || true
            else
                log_error "  Failed to generate valid audit results"
                echo '{"metadata":{"vulnerabilities":{"critical":0,"high":0,"moderate":0,"low":0,"info":0,"total":0},"error":"invalid_audit_output"}}' > "${AUDIT_FILE}.summary" 2>/dev/null || true
            fi
        ) || {
            log_error "  Audit failed, continuing..."
            echo '{"metadata":{"vulnerabilities":{"critical":0,"high":0,"moderate":0,"low":0,"info":0,"total":0},"error":"audit_failed"}}' > "${AUDIT_FILE}.summary" 2>/dev/null || true
        }
    done <<< "$AUDIT_TARGETS"
    
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
    
    # Find all audit result summary files for this function
    for RESULT_FILE in "${FUNC_NAME}"-*-auditResults.json.summary; do
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
