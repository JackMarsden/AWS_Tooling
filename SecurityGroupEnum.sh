#!/bin/bash
# Filename: sg-resource-check.sh
#
# Description:
#   This script audits an AWS Security Group (SG) and lists all resources associated with it.
#   It outputs:
#     - SG name, description, VPC
#     - Inbound and outbound rules (nicely formatted tables)
#     - EC2 instances using the SG
#     - Network Interfaces (ENIs) using the SG with subnet/VPC/AZ
#     - Elastic Load Balancers (ALB/NLB) using the SG
#     - RDS instances using the SG
#
# Requirements:
#   - AWS CLI v2 installed and configured
#   - 'jq' installed for parsing JSON
#   - IAM permissions to describe:
#       - Security Groups
#       - EC2 Instances and Network Interfaces
#       - ELBv2 Load Balancers
#       - RDS instances
#
# Flags:
#   --profile <aws-profile>   : (Required) AWS CLI profile to use
#   --group <sg-id>           : (Required) Security Group ID (e.g., sg-0123456789abcdef)
#
# Usage:
#   chmod +x sg-resource-check.sh
#   ./sg-resource-check.sh --profile my-aws-profile --group sg-0123456789abcdef
#
# Output:
#   - Header with SG name, description, VPC
#   - Inbound rules table
#   - Outbound rules table
#   - EC2 instances table
#   - ENIs table
#   - ELBv2 table
#   - RDS table
#
# Notes:
#   - This script only queries configuration; it does NOT inspect traffic or logs.
#   - To see actual traffic using this SG, enable VPC Flow Logs.
#   - Works for resources in the region configured by the AWS CLI profile.

set -e

# -----------------------------
# Parse arguments
# -----------------------------
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --profile) AWS_PROFILE="$2"; shift ;;
        --group) SG_ID="$2"; shift ;;
        *) echo "Unknown parameter passed: $1"; exit 1 ;;
    esac
    shift
done

if [[ -z "$AWS_PROFILE" || -z "$SG_ID" ]]; then
    echo "Usage: $0 --profile <aws-profile> --group <sg-id>"
    exit 1
fi

echo "Checking security group: $SG_ID (profile: $AWS_PROFILE)"
echo "-----------------------------------------"

# -----------------------------
# Verify Security Group exists
# -----------------------------
SG_JSON=$(aws ec2 describe-security-groups \
    --profile "$AWS_PROFILE" \
    --group-ids "$SG_ID" \
    --query "SecurityGroups[0]" \
    --output json 2>/dev/null || echo "")

if [[ -z "$SG_JSON" ]]; then
    echo "Error: Security group $SG_ID does not exist in profile $AWS_PROFILE."
    exit 1
fi

# -----------------------------
# Output SG name & description
# -----------------------------
SG_NAME=$(echo "$SG_JSON" | jq -r '.GroupName')
SG_DESC=$(echo "$SG_JSON" | jq -r '.Description')
VPC_ID=$(echo "$SG_JSON" | jq -r '.VpcId')

echo "Security Group: $SG_ID"
echo "Name: $SG_NAME"
echo "Description: $SG_DESC"
echo "VPC ID: $VPC_ID"
echo "-----------------------------------------"

# -----------------------------
# Format and display inbound rules
# -----------------------------
echo "Inbound Rules:"
printf "%-8s %-8s %-8s %-25s\n" "Protocol" "FromPort" "ToPort" "Source"
echo "---------------------------------------------------------"
echo "$SG_JSON" | jq -r '
  .IpPermissions[] |
    (
      (.IpProtocol // "-") as $proto |
      (.FromPort // "-") as $from |
      (.ToPort // "-") as $to |
      (
        if (.IpRanges | length) > 0 then
          .IpRanges[]?.CidrIp
        else
          "-"
        end
      ) as $source |
      [$proto, $from, $to, $source] | @tsv
    )
' | column -t
echo "---------------------------------------------------------"

# -----------------------------
# Format and display outbound rules
# -----------------------------
echo "Outbound Rules:"
printf "%-8s %-8s %-8s %-25s\n" "Protocol" "FromPort" "ToPort" "Destination"
echo "---------------------------------------------------------"
echo "$SG_JSON" | jq -r '
  .IpPermissionsEgress[] |
    (
      (.IpProtocol // "-") as $proto |
      (.FromPort // "-") as $from |
      (.ToPort // "-") as $to |
      (
        if (.IpRanges | length) > 0 then
          .IpRanges[]?.CidrIp
        else
          "-"
        end
      ) as $dest |
      [$proto, $from, $to, $dest] | @tsv
    )
' | column -t
echo "---------------------------------------------------------"

# -----------------------------
# EC2 Instances
# -----------------------------
echo "EC2 Instances using this SG:"
aws ec2 describe-instances \
    --profile "$AWS_PROFILE" \
    --filters "Name=instance.group-id,Values=$SG_ID" \
    --query "Reservations[*].Instances[*].[InstanceId,PrivateIpAddress,Tags]" \
    --output table

# -----------------------------
# Network Interfaces (ENIs)
# -----------------------------
echo "Network Interfaces (ENIs) using this SG:"
aws ec2 describe-network-interfaces \
    --profile "$AWS_PROFILE" \
    --filters "Name=group-id,Values=$SG_ID" \
    --query "NetworkInterfaces[*].[NetworkInterfaceId,Attachment.InstanceId,PrivateIpAddress,SubnetId,VpcId,AvailabilityZone]" \
    --output table

# -----------------------------
# Load Balancers (ALB/NLB)
# -----------------------------
echo "Elastic Load Balancers (v2) using this SG:"
aws elbv2 describe-load-balancers \
    --profile "$AWS_PROFILE" \
    --query "LoadBalancers[?SecurityGroups[?contains(@,'$SG_ID')]].[LoadBalancerName,DNSName,VpcId]" \
    --output table

# -----------------------------
# RDS Instances
# -----------------------------
echo "RDS Instances using this SG:"
aws rds describe-db-instances \
    --profile "$AWS_PROFILE" \
    --query "DBInstances[?VpcSecurityGroups[?VpcSecurityGroupId=='$SG_ID']].[DBInstanceIdentifier,DBInstanceStatus,Endpoint.Address]" \
    --output table

echo "-----------------------------------------"
echo "Done."
