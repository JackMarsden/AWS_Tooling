#!/bin/bash
# Filename: sg-resource-check.sh
#
# Description:
#   Audits an AWS Security Group (SG) and lists all associated resources.
#   Outputs:
#     - SG info: Name, Description, VPC
#     - Inbound and outbound rules (nicely formatted)
#     - EC2 instances using the SG
#     - Network Interfaces (ENIs) using the SG with subnet/VPC/AZ and actual resource
#     - Elastic Load Balancers (ALB/NLB) using the SG
#     - RDS instances using the SG
#     - ECS Tasks using the SG
#     - EKS Node ENIs using the SG
#
# Requirements:
#   - AWS CLI v2
#   - jq installed
#   - IAM permissions to describe SGs, EC2, ELB, RDS, ECS, Lambda
#
# Flags:
#   --profile <aws-profile> : AWS CLI profile
#   --group <sg-id>         : Security Group ID (sg-xxxxxxxxxxxx)
#
# Usage:
#   chmod +x sg-resource-check.sh
#   ./sg-resource-check.sh --profile my-profile --group sg-xxxxxxxxxxxx

set -e

# -----------------------------
# Colors
# -----------------------------
RED="\033[1;31m"
YELLOW="\033[1;33m"
CYAN="\033[1;36m"
NC="\033[0m"

# -----------------------------
# Parse arguments
# -----------------------------
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --profile) AWS_PROFILE="$2"; shift ;;
        --group) SG_ID="$2"; shift ;;
        *) echo -e "${RED}Unknown parameter: $1${NC}"; exit 1 ;;
    esac
    shift
done

if [[ -z "$AWS_PROFILE" || -z "$SG_ID" ]]; then
    echo -e "${RED}Usage: $0 --profile <aws-profile> --group <sg-id>${NC}"
    exit 1
fi

echo -e "${YELLOW}Checking Security Group: $SG_ID (profile: $AWS_PROFILE)${NC}"
echo "-----------------------------------------"

# -----------------------------
# Verify SG exists
# -----------------------------
SG_JSON=$(aws ec2 describe-security-groups --profile "$AWS_PROFILE" \
          --group-ids "$SG_ID" --query "SecurityGroups[0]" --output json 2>/dev/null || echo "")
if [[ -z "$SG_JSON" ]]; then
    echo -e "${RED}Error: Security Group $SG_ID not found.${NC}"
    exit 1
fi

SG_NAME=$(echo "$SG_JSON" | jq -r '.GroupName')
SG_DESC=$(echo "$SG_JSON" | jq -r '.Description')
VPC_ID=$(echo "$SG_JSON" | jq -r '.VpcId')

echo -e "${CYAN}Security Group: $SG_ID${NC}"
echo -e "${CYAN}Name: $SG_NAME${NC}"
echo -e "${CYAN}Description: $SG_DESC${NC}"
echo -e "${CYAN}VPC ID: $VPC_ID${NC}"
echo "-----------------------------------------"

# -----------------------------
# Inbound Rules
# -----------------------------
echo -e "${YELLOW}Inbound Rules:${NC}"
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
# Outbound Rules
# -----------------------------
echo -e "${YELLOW}Outbound Rules:${NC}"
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
echo -e "${YELLOW}EC2 Instances using this SG:${NC}"
printf "%-15s %-15s %-30s\n" "InstanceId" "PrivateIP" "Tags"
echo "---------------------------------------------------------------"
aws ec2 describe-instances \
    --profile "$AWS_PROFILE" \
    --filters "Name=instance.group-id,Values=$SG_ID" \
    --query "Reservations[*].Instances[*].[InstanceId,PrivateIpAddress,Tags]" \
    --output text | column -t
echo "---------------------------------------------------------------"

# -----------------------------
# ENIs + Resource Mapping
# -----------------------------
echo -e "${YELLOW}ENIs using this SG:${NC}"
printf "%-20s | %-15s | %-15s | %-12s | %-12s | %-10s | %-30s\n" "ENI_ID" "InstanceId" "PrivateIP" "SubnetId" "VPC_ID" "AZ" "Resource"
echo "----------------------------------------------------------------------------------------------------------------------------"
ENIS=$(aws ec2 describe-network-interfaces --profile "$AWS_PROFILE" \
       --filters "Name=group-id,Values=$SG_ID" \
       --query "NetworkInterfaces[*].[NetworkInterfaceId,Attachment.InstanceId,PrivateIpAddress,SubnetId,VpcId,AvailabilityZone,InterfaceType]" \
       --output text)

while read -r ENI_ID INSTANCE_ID PRIVATE_IP SUBNET_ID VPC_ID AZ IF_TYPE; do
    ENI_TRUNC=$(echo "$ENI_ID" | cut -c1-17)
    INSTANCE_TRUNC=$(echo "$INSTANCE_ID" | cut -c1-12)
    SUBNET_TRUNC=$(echo "$SUBNET_ID" | cut -c1-12)
    VPC_TRUNC=$(echo "$VPC_ID" | cut -c1-12)
    AZ_TRUNC=$(echo "$AZ" | cut -c1-10)

    RESOURCE="Unknown"
    case "$IF_TYPE" in
        "interface")
            if [[ "$INSTANCE_ID" != "None" && "$INSTANCE_ID" != "-" ]]; then
                RESOURCE="EC2:$INSTANCE_ID"
            fi
            ;;
        "lambda")
            LAMBDAS=$(aws lambda list-functions --profile "$AWS_PROFILE" \
                --query "Functions[?VpcConfig.SecurityGroupIds && contains(VpcConfig.SecurityGroupIds,'$SG_ID')].[FunctionArn]" \
                --output text)
            if [[ -n "$LAMBDAS" ]]; then
                RESOURCE=$(echo "$LAMBDAS" | cut -c1-30)
            else
                RESOURCE="Lambda"
            fi
            ;;
        "elasticloadbalancing")
            LBS=$(aws elbv2 describe-load-balancers --profile "$AWS_PROFILE" \
                --query "LoadBalancers[?contains(SecurityGroups,'$SG_ID')].[LoadBalancerName]" --output text)
            if [[ -n "$LBS" ]]; then
                RESOURCE=$(echo "$LBS" | cut -c1-30)
            else
                RESOURCE="ELB/ALB/NLB"
            fi
            ;;
        "rds")
            RDS=$(aws rds describe-db-instances --profile "$AWS_PROFILE" \
                --query "DBInstances[?VpcSecurityGroups[?VpcSecurityGroupId=='$SG_ID']].[DBInstanceIdentifier]" \
                --output text)
            if [[ -n "$RDS" ]]; then
                RESOURCE=$(echo "$RDS" | cut -c1-30)
            else
                RESOURCE="RDS"
            fi
            ;;
        *) RESOURCE="Other" ;;
    esac

    printf "%-20s | %-15s | %-15s | %-12s | %-12s | %-10s | %-30s\n" \
        "$ENI_TRUNC" "$INSTANCE_TRUNC" "$PRIVATE_IP" "$SUBNET_TRUNC" "$VPC_TRUNC" "$AZ_TRUNC" "$RESOURCE"

done <<< "$ENIS"
echo "----------------------------------------------------------------------------------------------------------------------------"

# -----------------------------
# ECS Tasks
# -----------------------------
echo -e "${YELLOW}ECS Tasks using this SG:${NC}"
printf "%-35s %-30s %-15s %-15s\n" "Cluster" "TaskARN" "ENI_ID" "PrivateIP"
echo "----------------------------------------------------------------------------------------------"
CLUSTERS=$(aws ecs list-clusters --profile "$AWS_PROFILE" --query "clusterArns[]" --output text)
for CLUSTER in $CLUSTERS; do
    TASKS=$(aws ecs list-tasks --cluster "$CLUSTER" --profile "$AWS_PROFILE" --query "taskArns[]" --output text)
    if [[ -n "$TASKS" ]]; then
        for TASK in $TASKS; do
            ENIS_TASK=$(aws ecs describe-tasks --cluster "$CLUSTER" --tasks "$TASK" --profile "$AWS_PROFILE" \
                --query "tasks[].attachments[].details[?name=='networkInterfaceId'].value" --output text)
            for ENI in $ENIS_TASK; do
                SG_CHECK=$(aws ec2 describe-network-interfaces --network-interface-ids "$ENI" --profile "$AWS_PROFILE" \
                    --query "NetworkInterfaces[?contains(Groups[].GroupId,'$SG_ID')].[NetworkInterfaceId,PrivateIpAddress]" --output text)
                if [[ -n "$SG_CHECK" ]]; then
                    echo -e "$CLUSTER\t$TASK\t$SG_CHECK" | column -t
                fi
            done
        done
    fi
done
echo "----------------------------------------------------------------------------------------------"

# -----------------------------
# EKS Node ENIs
# -----------------------------
echo -e "${YELLOW}EKS Node ENIs using this SG:${NC}"
printf "%-20s %-20s %-15s %-15s %-15s %-15s\n" "ENI_ID" "InstanceId" "PrivateIP" "SubnetId" "VPC_ID" "AZ"
echo "---------------------------------------------------------------------------------------------"
EKS_INSTANCES=$(aws ec2 describe-instances --profile "$AWS_PROFILE" \
    --filters "Name=tag:eks:cluster-name,Values=*" "Name=instance-state-name,Values=running" \
    --query "Reservations[*].Instances[*].InstanceId" --output text)
for INSTANCE in $EKS_INSTANCES; do
    aws ec2 describe-network-interfaces --profile "$AWS_PROFILE" \
        --filters "Name=attachment.instance-id,Values=$INSTANCE" "Name=group-id,Values=$SG_ID" \
        --query "NetworkInterfaces[*].[NetworkInterfaceId,Attachment.InstanceId,PrivateIpAddress,SubnetId,VpcId,AvailabilityZone]" \
        --output text | column -t
done
echo "---------------------------------------------------------------------------------------------"

# -----------------------------
# ALB/NLB Load Balancers
# -----------------------------
echo -e "${YELLOW}Elastic Load Balancers (v2) using this SG:${NC}"
printf "%-25s %-40s %-15s\n" "LoadBalancerName" "DNSName" "VPC_ID"
echo "--------------------------------------------------------------------------"
aws elbv2 describe-load-balancers \
    --profile "$AWS_PROFILE" \
    --query "LoadBalancers[?SecurityGroups && contains(SecurityGroups,'$SG_ID')].[LoadBalancerName,DNSName,VpcId]" \
    --output text | column -t
echo "--------------------------------------------------------------------------"

# -----------------------------
# RDS Instances
# -----------------------------
echo -e "${YELLOW}RDS Instances using this SG:${NC}"
printf "%-25s %-15s %-30s\n" "DBInstanceIdentifier" "Status" "Endpoint"
echo "--------------------------------------------------------------------------"
aws rds describe-db-instances \
    --profile "$AWS_PROFILE" \
    --query "DBInstances[?VpcSecurityGroups[?VpcSecurityGroupId=='$SG_ID']].[DBInstanceIdentifier,DBInstanceStatus,Endpoint.Address]" \
    --output text | column -t
echo "--------------------------------------------------------------------------"

echo "-----------------------------------------"
echo -e "${CYAN}Done.${NC}"
