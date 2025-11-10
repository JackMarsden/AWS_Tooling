#!/bin/bash
# vpcEnum.sh
# Enhanced VPC enumeration across multiple regions
# Usage: ./vpcEnum.sh --profile <aws-profile> --vpc <vpc-id> [--region <region|all>]

set -e

# Colors
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
RED="\033[0;31m"
BLUE="\033[0;34m"
NC="\033[0m"

usage() {
    echo -e "${YELLOW}Usage:${NC} $0 --profile <aws-profile> --vpc <vpc-id> [--region <region|all>]"
    exit 1
}

# Parse arguments
REGION_FLAG=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --profile)
            PROFILE="$2"
            shift 2
            ;;
        --vpc)
            VPC_ID="$2"
            shift 2
            ;;
        --region)
            REGION_FLAG="$2"
            shift 2
            ;;
        *)
            usage
            ;;
    esac
done

if [[ -z "$PROFILE" || -z "$VPC_ID" ]]; then
    usage
fi

# Determine regions
if [[ -n "$REGION_FLAG" && "$REGION_FLAG" != "all" ]]; then
    REGIONS=("$REGION_FLAG")
elif [[ "$REGION_FLAG" == "all" ]]; then
    echo -e "${BLUE}Fetching all AWS regions...${NC}"
    REGIONS=($(aws ec2 describe-regions --query 'Regions[].RegionName' --profile "$PROFILE" --output text))
else
    DEFAULT_REGION=$(aws configure get region --profile "$PROFILE")
    REGIONS=("${DEFAULT_REGION:-ap-southeast-2}")
fi

for REGION in "${REGIONS[@]}"; do
    echo -e "${GREEN}==================== REGION: $REGION ====================${NC}"

    echo -e "${BLUE}VPC Information:${NC}"
    aws ec2 describe-vpcs --vpc-ids "$VPC_ID" --profile "$PROFILE" --region "$REGION" --output table || echo -e "${RED}VPC not found in $REGION${NC}"
    echo

    echo -e "${BLUE}Subnets:${NC}"
    aws ec2 describe-subnets --filters "Name=vpc-id,Values=$VPC_ID" --profile "$PROFILE" --region "$REGION" --output table
    echo

    echo -e "${BLUE}Route Tables:${NC}"
    aws ec2 describe-route-tables --filters "Name=vpc-id,Values=$VPC_ID" --profile "$PROFILE" --region "$REGION" --output table
    echo

    echo -e "${BLUE}Security Groups:${NC}"
    aws ec2 describe-security-groups --filters "Name=vpc-id,Values=$VPC_ID" --profile "$PROFILE" --region "$REGION" --output table
    echo

    echo -e "${BLUE}Network ACLs:${NC}"
    aws ec2 describe-network-acls --filters "Name=vpc-id,Values=$VPC_ID" --profile "$PROFILE" --region "$REGION" --output table
    echo

    echo -e "${BLUE}Internet Gateways:${NC}"
    aws ec2 describe-internet-gateways --filters "Name=attachment.vpc-id,Values=$VPC_ID" --profile "$PROFILE" --region "$REGION" --output table
    echo

    echo -e "${BLUE}NAT Gateways:${NC}"
    aws ec2 describe-nat-gateways --filter "Name=vpc-id,Values=$VPC_ID" --profile "$PROFILE" --region "$REGION" --output table
    echo

    echo -e "${BLUE}VPC Endpoints:${NC}"
    aws ec2 describe-vpc-endpoints --filters "Name=vpc-id,Values=$VPC_ID" --profile "$PROFILE" --region "$REGION" --output table
    echo

    echo -e "${BLUE}Network Interfaces (ENIs):${NC}"
    aws ec2 describe-network-interfaces --filters "Name=vpc-id,Values=$VPC_ID" --profile "$PROFILE" --region "$REGION" --output table
    echo

    echo -e "${BLUE}EC2 Instances:${NC}"
    aws ec2 describe-instances --filters "Name=vpc-id,Values=$VPC_ID" --profile "$PROFILE" --region "$REGION" --output table
    echo

    echo -e "${BLUE}RDS Instances:${NC}"
    aws rds describe-db-instances --query "DBInstances[?DBSubnetGroup.VpcId=='$VPC_ID']" --profile "$PROFILE" --region "$REGION" --output table
    echo

    echo -e "${BLUE}Redshift Clusters:${NC}"
    aws redshift describe-clusters --query "Clusters[?VpcId=='$VPC_ID']" --profile "$PROFILE" --region "$REGION" --output table
    echo

    echo -e "${BLUE}ElastiCache Clusters:${NC}"
    aws elasticache describe-cache-clusters --show-cache-node-info --query "CacheClusters[?CacheSubnetGroup.VpcId=='$VPC_ID']" --profile "$PROFILE" --region "$REGION" --output table
    echo

    echo -e "${BLUE}Lambda Functions in VPC:${NC}"
    aws lambda list-functions --profile "$PROFILE" --region "$REGION" --query "Functions[?VpcConfig.VpcId=='$VPC_ID'].[FunctionName,VpcConfig.SubnetIds,VpcConfig.SecurityGroupIds]" --output table
    echo

    echo -e "${BLUE}Classic Load Balancers:${NC}"
    aws elb describe-load-balancers --query "LoadBalancerDescriptions[?VPCId=='$VPC_ID']" --profile "$PROFILE" --region "$REGION" --output table
    echo

    echo -e "${BLUE}ALB/NLB Load Balancers:${NC}"
    aws elbv2 describe-load-balancers --query "LoadBalancers[?VpcId=='$VPC_ID']" --profile "$PROFILE" --region "$REGION" --output table
    echo

    echo -e "${YELLOW}==================== END REGION: $REGION ====================${NC}"
    echo
done

echo -e "${GREEN}✅ VPC enumeration complete across selected regions.${NC}"
