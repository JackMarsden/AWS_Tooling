#!/usr/bin/env bash
set -euo pipefail

# ============================
#  Colors
# ============================
RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
NC="\033[0m" # No Color

# ============================
#  Parse arguments
# ============================
PROFILE="default"
LATEST_SCHEMA_VERSION=""
ARGS_PROVIDED=0

while [[ $# -gt 0 ]]; do
  ARGS_PROVIDED=1
  case $1 in
    --profile)
      PROFILE="$2"
      shift 2
      ;;
    --latestSchemaVersion)
      LATEST_SCHEMA_VERSION="$2"
      shift 2
      ;;
    *)
      echo -e "${RED}❌ Unknown option: $1${NC}"
      echo "Usage: $0 --latestSchemaVersion <version> [--profile <aws_profile_name>]"
      exit 1
      ;;
  esac
done

# ============================
#  Check mandatory flag
# ============================
if [[ -z "$LATEST_SCHEMA_VERSION" ]]; then
  echo -e "${RED}⚠️  Mandatory flag --latestSchemaVersion not provided!${NC}"
  echo "Please provide the latest policy schema version in the format: --latestSchemaVersion \"2012-10-17\""
  echo "Optionally, you can use --profile <profile_name> to specify an AWS CLI profile."
  echo "AWS IAM policy versions documentation: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_version.html"
  exit 1
fi

# ============================
#  AWS Auth Check
# ============================
if ! aws sts get-caller-identity --profile "$PROFILE" &>/dev/null; then
  echo -e "${RED}❌ AWS CLI cannot authenticate using profile '$PROFILE'. Please check your credentials.${NC}"
  exit 1
fi

echo -e "${GREEN}✅ AWS authentication check successful for profile '$PROFILE'.${NC}"

# ============================
#  Setup output
# ============================
TS=$(date +"%Y%m%d_%H%M%S")
OUTPUT="aws_policy_schema_audit_${TS}.csv"

echo "🔍 Using AWS profile: [$PROFILE]"
echo "📄 Output file: $OUTPUT"
echo "📌 Latest schema version to check against: $LATEST_SCHEMA_VERSION"
echo "Service,Resource,PolicyNameOrID,PolicyVersion,Status" > "$OUTPUT"

# ============================
#  Helper function
# ============================
check_version() {
  local service="$1"
  local resource="$2"
  local name="$3"
  local policy_json="$4"

  version=$(echo "$policy_json" | jq -r '.Version // empty')
  if [[ -z "$version" ]]; then
    version="(none)"
    status="❌ Missing Version"
    echo -e "${RED}[${service}] ${resource} - Policy version missing!${NC}"
  elif [[ "$version" == "$LATEST_SCHEMA_VERSION" ]]; then
    status="✅ Current"
  else
    status="⚠️ Outdated ($version)"
    echo -e "${YELLOW}[${service}] ${resource} - Outdated policy version: $version (Expected: $LATEST_SCHEMA_VERSION)${NC}"
  fi

  echo "$service,$resource,$name,$version,$status" >> "$OUTPUT"
}

# ============================
#  Start enumeration (services)
# ============================
echo "🚀 Starting AWS Policy Schema Audit..."
echo

# --- IAM Policies ---
echo "→ Checking IAM policies..."
for arn in $(aws iam list-policies --scope All --query "Policies[].Arn" --output text --profile "$PROFILE"); do
  name=$(basename "$arn")
  verid=$(aws iam get-policy --policy-arn "$arn" --query "Policy.DefaultVersionId" --output text --profile "$PROFILE")
  doc=$(aws iam get-policy-version --policy-arn "$arn" --version-id "$verid" --query "PolicyVersion.Document" --output json --profile "$PROFILE" 2>/dev/null || echo "{}")
  check_version "IAM" "$arn" "$name" "$doc"
done

# --- S3 Bucket Policies ---
echo "→ Checking S3 bucket policies..."
for bucket in $(aws s3api list-buckets --query "Buckets[].Name" --output text --profile "$PROFILE"); do
  policy=$(aws s3api get-bucket-policy --bucket "$bucket" --query "Policy" --output text --profile "$PROFILE" 2>/dev/null || echo "{}")
  [[ "$policy" != "{}" ]] && check_version "S3" "$bucket" "$bucket" "$policy"
done

# --- SNS Topic Policies ---
echo "→ Checking SNS topic policies..."
for topic_arn in $(aws sns list-topics --query "Topics[].TopicArn" --output text --profile "$PROFILE"); do
  policy=$(aws sns get-topic-attributes --topic-arn "$topic_arn" --query "Attributes.Policy" --output text --profile "$PROFILE" 2>/dev/null || echo "{}")
  [[ "$policy" != "{}" ]] && check_version "SNS" "$topic_arn" "$topic_arn" "$policy"
done

# --- SQS Queue Policies ---
echo "→ Checking SQS queue policies..."
for queue_url in $(aws sqs list-queues --query "QueueUrls[]" --output text --profile "$PROFILE" 2>/dev/null); do
  policy=$(aws sqs get-queue-attributes --queue-url "$queue_url" --attribute-names Policy --query "Attributes.Policy" --output text --profile "$PROFILE" 2>/dev/null || echo "{}")
  [[ "$policy" != "{}" ]] && check_version "SQS" "$queue_url" "$queue_url" "$policy"
done

# --- Lambda Function Policies ---
echo "→ Checking Lambda function policies..."
for fn in $(aws lambda list-functions --query "Functions[].FunctionName" --output text --profile "$PROFILE" 2>/dev/null); do
  policy=$(aws lambda get-policy --function-name "$fn" --output text --profile "$PROFILE" 2>/dev/null || echo "{}")
  [[ "$policy" != "{}" ]] && check_version "Lambda" "$fn" "$fn" "$policy"
done

# --- KMS Key Policies ---
echo "→ Checking KMS key policies..."
for keyid in $(aws kms list-keys --query "Keys[].KeyId" --output text --profile "$PROFILE" 2>/dev/null); do
  policy=$(aws kms get-key-policy --key-id "$keyid" --policy-name default --output text --profile "$PROFILE" 2>/dev/null || echo "{}")
  [[ "$policy" != "{}" ]] && check_version "KMS" "$keyid "$keyid" "$policy"
done

# --- Secrets Manager Policies ---
echo "→ Checking Secrets Manager resource policies..."
for secret_arn in $(aws secretsmanager list-secrets --query "SecretList[].ARN" --output text --profile "$PROFILE" 2>/dev/null); do
  policy=$(aws secretsmanager get-resource-policy --secret-id "$secret_arn" --query "ResourcePolicy" --output text --profile "$PROFILE" 2>/dev/null || echo "{}")
  [[ "$policy" != "{}" ]] && check_version "SecretsManager" "$secret_arn" "$secret_arn" "$policy"
done

# ============================
#  Finish
# ============================
echo
echo -e "${GREEN}✅ Policy schema audit complete!${NC}"
echo "📊 Results saved to: $OUTPUT"
