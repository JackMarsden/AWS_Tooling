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
        find "$TMP_DIR" -name "*.zip" -delete
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
    
    echo -e "${BOLD}Processing: $FUNC_NAME${RESET}"
    
    # Unzip into its own directory
    mkdir -p "$FUNC_DIR"
    if ! unzip -q "$ZIP_FILE" -d "$FUNC_DIR" 2>/dev/null; then
        log_error "Failed to unzip: $ZIP_FILE"
        continue
    fi
    
    # Find all package.json files (excluding node_modules)
    PACKAGE_JSONS=$(find "$FUNC_DIR" -name "package.json" -not -path "*/node_modules/*" 2>/dev/null || true)
    
    if [[ -z "$PACKAGE_JSONS" ]]; then
        log_error "No package.json found in $FUNC_NAME"
        echo
        continue
    fi
    
    # Run npm audit for each package.json found
    echo "$PACKAGE_JSONS" | while read -r PKG_JSON; do
        PKG_DIR=$(dirname "$PKG_JSON")
        
        log_info "Auditing: $PKG_DIR"
        
        # Get absolute path for audit file to avoid path issues
        AUDIT_FILE="$(pwd)/${FUNC_NAME}-auditResults.json"
        
        (
            cd "$PKG_DIR" || exit 0
            
            # Generate package-lock.json if missing
            if [[ ! -f package-lock.json ]]; then
                npm install --package-lock-only >/dev/null 2>&1 || true
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
                TOTAL=$(jq -r '.metadata.vulnerabilities.total // 0' "$AUDIT_FILE" 2>/dev/null || echo 0)
                
                if [[ $TOTAL -gt 0 ]]; then
                    echo -e "  ${RED}Critical: $CRITICAL${RESET} | ${YELLOW}High: $HIGH${RESET} | Moderate: $MODERATE | Low: $LOW | ${BOLD}Total: $TOTAL${RESET}"
                else
                    log_success "No vulnerabilities found"
                fi
            else
                log_error "Failed to generate valid audit results"
                # Create empty result file with error handling
                mkdir -p "$(dirname "$AUDIT_FILE")" 2>/dev/null || true
                echo '{"metadata":{"vulnerabilities":{"critical":0,"high":0,"moderate":0,"low":0,"total":0},"error":"invalid_audit_output"}}' > "$AUDIT_FILE" 2>/dev/null || true
            fi
        ) || {
            log_error "Audit failed for $PKG_DIR, continuing with next package..."
            # Create error result file with path safety
            mkdir -p "$(dirname "$AUDIT_FILE")" 2>/dev/null || true
            echo '{"metadata":{"vulnerabilities":{"critical":0,"high":0,"moderate":0,"low":0,"total":0},"error":"audit_failed"}}' > "$AUDIT_FILE" 2>/dev/null || true
        }
    done
    
    echo
done

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
log_section "Audit Results"

RESULT_FILES=$(ls *-auditResults.json 2>/dev/null || true)

if [[ -z "$RESULT_FILES" ]]; then
    log_error "No audit result files found"
else
    RESULT_COUNT=$(echo "$RESULT_FILES" | wc -l | tr -d ' ')
    log_success "Generated $RESULT_COUNT audit result file(s):"
    echo
    
    for RESULT_FILE in *-auditResults.json; do
        echo "  📄 $(pwd)/$RESULT_FILE"
    done
fi

echo
log_info "All audit results saved in: $(pwd)"
