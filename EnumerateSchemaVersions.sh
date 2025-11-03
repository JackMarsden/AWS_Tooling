#!/bin/bash
set -euo pipefail

# ========================
# AWS_Tooling: EnumerateSchemaVersions.sh
# Audits AWS policy schema versions across multiple services
# Handles resources without policies safely
# ========================

# Default values
PROFILE="default"
VERBOSE=false
LATEST_SCHEMA_VERSION=""

# Colors for terminal output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Usage
usage() {
    echo "Usage: $0 --latestSchemaVersion <version> [--profile <aws_profile>] [--v]"
    echo "  --latestSchemaVersion   Mandatory, e.g., '2012-10-17'"
    echo "  --profile               Optional, AWS CLI profile to use (default='default')"
    echo "  --v                      Optional, verbose output"
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --latestSchemaVersion)
            LATEST_SCHEMA_VERSION="$2"
            shift 2
            ;;
        --profile)
            PROFILE="$2"
            shift 2
            ;;
        --v)
            VERBOSE=true
            shift
            ;;
        *)
            usage
            exit 1
            ;;
    esac
done

# Mandatory check
if [[ -z "$LATEST_SCHEMA_VERSION" ]]; then
    echo -e "${RED}Error: --latestSchemaVersion is mandatory.${NC}"
    echo "See https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_version.html for details."
    usage
    exit 1
fi

# Pre-flight AWS credentials check
if ! aws sts get-caller-identity --profile "$PROFILE" &>/dev/null; then
    echo -e "${RED}Error: Cannot authenticate with AWS using profile '$PROFILE'.${NC}"
    exit 1
fi

if [[ "$VERBOSE" = true ]]; then
    echo -e "${GREEN}AWS credentials verified for profile '$PROFILE'.${NC}"
fi

# Output file
OUTPUT_FILE="aws_policy_schema_audit_$(date +%Y%m%d_%H%M%S).csv"
echo "Service,Resource,PolicyNameOrID,PolicyVersion,Status" > "$OUTPUT_FILE"

# Generic audit function
audit_policy() {
    local service=$1
    local resource=$2
    local policy_json=$3

    if [[ -z "$policy_json" ]]; then
        STATUS="No Policy"
        # Keep "No Policy" yellow/orange
        echo -e "${YELLOW}[!] $service: $resource has no policy.${NC}"
        echo "$service,$resource,N/A,N/A,$STATUS" >> "$OUTPUT_FILE"
        return
    fi

    VERSION=$(echo "$policy_json" | jq -r '.Version // empty')
    STATUS="Compliant"
    if [[ "$VERSION" != "$LATEST_SCHEMA_VERSION" ]]; then
        STATUS="Outdated"
        # Non-compliant is now red
        echo -e "${RED}[!] $service Policy: $resource uses version $VERSION, expected $LATEST_SCHEMA_VERSION${NC}"
    elif [[ "$VERBOSE" = true ]]; then
        # Compliant stays green
        echo -e "${GREEN}[✓] $service Policy: $resource is compliant.${NC}"
    fi
    echo "$service,$resource,N/A,$VERSION,$STATUS" >> "$OUTPUT_FILE"
}


# =======================
# Audit functions for each service
# =======================

# IAM
audit_iam_policies() {
    echo "Auditing IAM policies..."
    POLICIES=$(aws iam list-policies --scope Local --profile "$PROFILE" | jq -r '.Policies[] | @base64')
    for p in $POLICIES; do
        POLICY=$(echo "$p" | base64 --decode)
        NAME=$(echo "$POLICY" | jq -r '.PolicyName')
        ARN=$(echo "$POLICY" | jq -r '.Arn')
        DEFAULT_VERSION_ID=$(echo "$POLICY" | jq -r '.DefaultVersionId')
        VERSION_JSON=$(aws iam get-policy-version --policy-arn "$ARN" --version-id "$DEFAULT_VERSION_ID" --profile "$PROFILE" | jq -r '.PolicyVersion.Document')
        audit_policy "IAM" "$ARN ($NAME)" "$VERSION_JSON"
    done
}

# S3
audit_s3_policies() {
    echo "Auditing S3 bucket policies..."
    BUCKETS=$(aws s3api list-buckets --profile "$PROFILE" | jq -r '.Buckets[].Name')
    for b in $BUCKETS; do
        POLICY_JSON=""
        if POLICY_RAW=$(aws s3api get-bucket-policy --bucket "$b" --profile "$PROFILE" 2>/dev/null); then
            POLICY_JSON=$(echo "$POLICY_RAW" | jq -r '.Policy // empty')
        fi
        audit_policy "S3" "$b" "$POLICY_JSON"
    done
}

# SNS
audit_sns_policies() {
    echo "Auditing SNS topic policies..."
    TOPICS=$(aws sns list-topics --profile "$PROFILE" | jq -r '.Topics[].TopicArn')
    for t in $TOPICS; do
        POLICY_JSON=""
        if POLICY_RAW=$(aws sns get-topic-attributes --topic-arn "$t" --profile "$PROFILE"); then
            POLICY_JSON=$(echo "$POLICY_RAW" | jq -r '.Attributes.Policy // empty')
        fi
        audit_policy "SNS" "$t" "$POLICY_JSON"
    done
}

# SQS
audit_sqs_policies() {
    echo "Auditing SQS queue policies..."
    QUEUES=$(aws sqs list-queues --profile "$PROFILE" | jq -r '.QueueUrls[]?')
    for q in $QUEUES; do
        POLICY_JSON=""
        if POLICY_RAW=$(aws sqs get-queue-attributes --queue-url "$q" --attribute-names Policy --profile "$PROFILE"); then
            POLICY_JSON=$(echo "$POLICY_RAW" | jq -r '.Attributes.Policy // empty')
        fi
        audit_policy "SQS" "$q" "$POLICY_JSON"
    done
}

# Lambda
audit_lambda_policies() {
    echo "Auditing Lambda function policies..."
    FUNCTIONS=$(aws lambda list-functions --profile "$PROFILE" | jq -r '.Functions[].FunctionName')
    for f in $FUNCTIONS; do
        POLICY_JSON=""
        if POLICY_RAW=$(aws lambda get-policy --function-name "$f" --profile "$PROFILE" 2>/dev/null); then
            POLICY_JSON="$POLICY_RAW"
        fi
        audit_policy "Lambda" "$f" "$POLICY_JSON"
    done
}

# KMS
audit_kms_policies() {
    echo "Auditing KMS key policies..."
    KEYS=$(aws kms list-keys --profile "$PROFILE" | jq -r '.Keys[].KeyId')
    for k in $KEYS; do
        POLICY_JSON=""
        if POLICY_RAW=$(aws kms get-key-policy --key-id "$k" --policy-name default --profile "$PROFILE" 2>/dev/null); then
            POLICY_JSON="$POLICY_RAW"
        fi
        audit_policy "KMS" "$k" "$POLICY_JSON"
    done
}

# Secrets Manager
audit_secrets_policies() {
    echo "Auditing Secrets Manager policies..."
    SECRETS=$(aws secretsmanager list-secrets --profile "$PROFILE" | jq -r '.SecretList[].ARN')
    for s in $SECRETS; do
        POLICY_JSON=""
        if POLICY_RAW=$(aws secretsmanager get-resource-policy --secret-id "$s" --profile "$PROFILE" 2>/dev/null); then
            POLICY_JSON=$(echo "$POLICY_RAW" | jq -r '.ResourcePolicy // empty')
        fi
        audit_policy "SecretsManager" "$s" "$POLICY_JSON"
    done
}

# EventBridge
audit_eventbridge_policies() {
    echo "Auditing EventBridge bus policies..."
    BUSES=$(aws events list-event-buses --profile "$PROFILE" | jq -r '.EventBuses[].Name')
    for b in $BUSES; do
        POLICY_JSON=""
        if POLICY_RAW=$(aws events describe-event-bus --name "$b" --profile "$PROFILE"); then
            POLICY_JSON=$(echo "$POLICY_RAW" | jq -r '.Policy // empty')
        fi
        audit_policy "EventBridge" "$b" "$POLICY_JSON"
    done
}

# API Gateway
audit_apigateway_policies() {
    echo "Auditing API Gateway policies..."
    APIS=$(aws apigateway get-rest-apis --profile "$PROFILE" | jq -r '.items[].id')
    for api in $APIS; do
        POLICY_JSON=""
        if POLICY_RAW=$(aws apigateway get-rest-api --rest-api-id "$api" --profile "$PROFILE"); then
            POLICY_JSON=$(echo "$POLICY_RAW" | jq -r '.policy // empty')
        fi
        audit_policy "APIGateway" "$api" "$POLICY_JSON"
    done
}

# CloudWatch Logs
audit_cwlogs_policies() {
    echo "Auditing CloudWatch Logs resource policies..."
    POLICIES=$(aws logs describe-resource-policies --profile "$PROFILE" | jq -r '.resourcePolicies[]? | @base64')
    for p in $POLICIES; do
        POLICY=$(echo "$p" | base64 --decode)
        NAME=$(echo "$POLICY" | jq -r '.policyName // "Unknown"')
        POLICY_JSON=$(echo "$POLICY" | jq -c '.policyDocument // empty')
        audit_policy "CloudWatchLogs" "$NAME" "$POLICY_JSON"
    done
}

# Step Functions
audit_sfn_policies() {
    echo "Auditing Step Functions state machine policies..."
    SFNS=$(aws stepfunctions list-state-machines --profile "$PROFILE" | jq -r '.stateMachines[].stateMachineArn')
    for sfn in $SFNS; do
        POLICY_JSON=""
        ROLE_ARN=$(aws stepfunctions describe-state-machine --state-machine-arn "$sfn" --profile "$PROFILE" | jq -r '.roleArn // empty')
        if [[ -n "$ROLE_ARN" ]]; then
            ROLE_NAME=$(echo "$ROLE_ARN" | awk -F/ '{print $NF}')
            if ROLE_POLICY_RAW=$(aws iam get-role --role-name "$ROLE_NAME" --profile "$PROFILE" 2>/dev/null); then
                POLICY_JSON=$(echo "$ROLE_POLICY_RAW" | jq -r '.Role.AssumeRolePolicyDocument // empty')
            fi
        fi
        audit_policy "StepFunctions" "$sfn" "$POLICY_JSON"
    done
}

# =======================
# Main execution
# =======================

audit_iam_policies
audit_s3_policies
audit_sns_policies
audit_sqs_policies
audit_lambda_policies
audit_kms_policies
audit_secrets_policies
audit_eventbridge_policies
audit_apigateway_policies
audit_cwlogs_policies
audit_sfn_policies

echo -e "${GREEN}Audit complete. Results saved to $OUTPUT_FILE${NC}"
