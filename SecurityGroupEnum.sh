#!/bin/bash
# Filename: sg-resource-check.sh
#
# Description:
#   Audits an AWS Security Group (SG) and lists all associated resources.
#   Outputs:
#     - SG info: Name, Description, VPC
#     - Inbound and outbound rules
#     - EC2 instances using the SG
#     - Network Interfaces (ENIs) with subnet/VPC/AZ and full resource ARNs/names
#     - Elastic Load Balancers (ALB/NLB)
#     - RDS instances
#     - ECS Tasks using the SG
#     - EKS Node ENIs
#
# Requirements:
#   - AWS CLI v2
#   - jq installed
#   - IAM permissions to describe SGs, EC2, ELB, RDS, ECS, Lambda
#
# Flags:
#   --profile <aws-profile> : AWS CLI profile
#   --group <sg-id>         : Security Group ID (sg-xxxxxxxxxxxx)
#   --region <region>       : AWS region (optional, uses profile default)
#
# Usage:
#   chmod +x sg-resource-check.sh
#   ./sg-resource-check.sh --profile my-profile --group sg-xxxxxxxxxxxx [--region us-east-1]

set -e

# -----------------------------
# Colors
# -----------------------------
readonly RED="\033[1;31m"
readonly YELLOW="\033[1;33m"
readonly CYAN="\033[1;36m"
readonly GREEN="\033[0;32m"
readonly BLUE="\033[0;34m"
readonly NC="\033[0m"

# -----------------------------
# Global Variables
# -----------------------------
AWS_PROFILE=""
SG_ID=""
REGION=""

# -----------------------------
# Functions
# -----------------------------

# Display usage information
usage() {
    cat << EOF
${YELLOW}Usage:${NC} $0 --profile <aws-profile> --group <sg-id> [--region <region>]

${YELLOW}Options:${NC}
    --profile    AWS CLI profile to use
    --group      Security Group ID (sg-xxxxxxxxxxxx)
    --region     AWS region (optional, uses profile default)

${YELLOW}Example:${NC}
    $0 --profile prod --group sg-12345678
    $0 --profile dev --group sg-87654321 --region us-east-1
EOF
    exit 1
}

# Parse command line arguments
parse_arguments() {
    while [[ "$#" -gt 0 ]]; do
        case $1 in
            --profile) 
                AWS_PROFILE="$2"
                shift 2
                ;;
            --group) 
                SG_ID="$2"
                shift 2
                ;;
            --region)
                REGION="$2"
                shift 2
                ;;
            -h|--help)
                usage
                ;;
            *) 
                echo -e "${RED}Unknown parameter: $1${NC}"
                usage
                ;;
        esac
    done

    if [[ -z "$AWS_PROFILE" || -z "$SG_ID" ]]; then
        echo -e "${RED}Error: --profile and --group are required${NC}"
        usage
    fi

    # Set region if not provided
    if [[ -z "$REGION" ]]; then
        REGION=$(aws configure get region --profile "$AWS_PROFILE" 2>/dev/null || echo "us-east-1")
    fi
}

# Execute AWS command with error handling
aws_query() {
    local service="$1"
    local command="$2"
    shift 2
    
    aws "$service" "$command" --profile "$AWS_PROFILE" --region "$REGION" "$@" 2>/dev/null || return 1
}

# Print section header
print_header() {
    local title="$1"
    echo -e "${YELLOW}${title}:${NC}"
}

# Print separator line
print_separator() {
    local length="${1:-80}"
    printf '%*s\n' "$length" '' | tr ' ' '-'
}

# Get Security Group information
get_sg_info() {
    local sg_json
    sg_json=$(aws_query ec2 describe-security-groups \
        --group-ids "$SG_ID" \
        --query "SecurityGroups[0]" \
        --output json)
    
    if [[ -z "$sg_json" || "$sg_json" == "null" ]]; then
        echo -e "${RED}Error: Security Group $SG_ID not found in region $REGION.${NC}"
        exit 1
    fi
    
    echo "$sg_json"
}

# Display Security Group basic information
display_sg_info() {
    local sg_json="$1"
    
    local sg_name=$(echo "$sg_json" | jq -r '.GroupName')
    local sg_desc=$(echo "$sg_json" | jq -r '.Description')
    local vpc_id=$(echo "$sg_json" | jq -r '.VpcId')
    
    echo -e "${CYAN}Security Group: $SG_ID${NC}"
    echo -e "${CYAN}Name: $sg_name${NC}"
    echo -e "${CYAN}Description: $sg_desc${NC}"
    echo -e "${CYAN}VPC ID: $vpc_id${NC}"
    echo -e "${CYAN}Region: $REGION${NC}"
    print_separator
}

# Format and display inbound rules
display_inbound_rules() {
    local sg_json="$1"
    
    print_header "Inbound Rules"
    
    local ingress_rules=$(echo "$sg_json" | jq -c '.IpPermissions')
    
    if [[ -z "$ingress_rules" || "$ingress_rules" == "[]" ]]; then
        echo -e "${YELLOW}  No inbound rules${NC}"
        print_separator
        return
    fi
    
    printf "%-12s | %-10s | %-10s | %-45s | %s\n" "Protocol" "From Port" "To Port" "Source" "Description"
    print_separator 120
    
    echo "$sg_json" | jq -r '
    .IpPermissions[] |
    . as $rule |
    (
        if .IpProtocol == "-1" then "All"
        elif .IpProtocol == "tcp" then "TCP"
        elif .IpProtocol == "udp" then "UDP"
        elif .IpProtocol == "icmp" then "ICMP"
        elif .IpProtocol == "icmpv6" then "ICMPv6"
        else .IpProtocol
        end
    ) as $proto |
    (if .FromPort then .FromPort else "All" end) as $from |
    (if .ToPort then .ToPort else "All" end) as $to |
    
    # Process all source types
    if (.IpRanges | length) > 0 then
        .IpRanges[] | 
        [$proto, $from, $to, .CidrIp, (.Description // "")]
    elif (.Ipv6Ranges | length) > 0 then
        .Ipv6Ranges[] |
        [$proto, $from, $to, .CidrIpv6, (.Description // "")]
    elif (.UserIdGroupPairs | length) > 0 then
        .UserIdGroupPairs[] |
        [$proto, $from, $to, ("SG:" + .GroupId), (.Description // "")]
    elif (.PrefixListIds | length) > 0 then
        .PrefixListIds[] |
        [$proto, $from, $to, ("PL:" + .PrefixListId), (.Description // "")]
    else
        [$proto, $from, $to, "Unknown", ""]
    end |
    @tsv
    ' | while IFS=$'\t' read -r proto from to source desc; do
        printf "%-12s | %-10s | %-10s | %-45s | %s\n" "$proto" "$from" "$to" "$source" "$desc"
    done
    
    print_separator 120
}

# Format and display outbound rules
display_outbound_rules() {
    local sg_json="$1"
    
    print_header "Outbound Rules"
    
    local egress_rules=$(echo "$sg_json" | jq -c '.IpPermissionsEgress')
    
    # Check if no egress rules exist (AWS default behavior)
    if [[ -z "$egress_rules" || "$egress_rules" == "[]" ]]; then
        echo -e "${CYAN}  (Default) Allow all outbound traffic${NC}"
        print_separator
        return
    fi
    
    # Check if it's the default allow-all rule
    local is_default=$(echo "$sg_json" | jq -r '
    .IpPermissionsEgress | 
    if length == 1 and 
       .[0].IpProtocol == "-1" and 
       (.[0].IpRanges[0].CidrIp == "0.0.0.0/0" or .[0].Ipv6Ranges[0].CidrIpv6 == "::/0")
    then "true" else "false" end
    ')
    
    if [[ "$is_default" == "true" ]]; then
        echo -e "${CYAN}  (Default) Allow all outbound traffic (0.0.0.0/0)${NC}"
    fi
    
    printf "%-12s | %-10s | %-10s | %-45s | %s\n" "Protocol" "From Port" "To Port" "Destination" "Description"
    print_separator 120
    
    echo "$sg_json" | jq -r '
    .IpPermissionsEgress[] |
    . as $rule |
    (
        if .IpProtocol == "-1" then "All"
        elif .IpProtocol == "tcp" then "TCP"
        elif .IpProtocol == "udp" then "UDP"
        elif .IpProtocol == "icmp" then "ICMP"
        elif .IpProtocol == "icmpv6" then "ICMPv6"
        else .IpProtocol
        end
    ) as $proto |
    (if .FromPort then .FromPort else "All" end) as $from |
    (if .ToPort then .ToPort else "All" end) as $to |
    
    # Process all destination types
    if (.IpRanges | length) > 0 then
        .IpRanges[] | 
        [$proto, $from, $to, .CidrIp, (.Description // "")]
    elif (.Ipv6Ranges | length) > 0 then
        .Ipv6Ranges[] |
        [$proto, $from, $to, .CidrIpv6, (.Description // "")]
    elif (.UserIdGroupPairs | length) > 0 then
        .UserIdGroupPairs[] |
        [$proto, $from, $to, ("SG:" + .GroupId), (.Description // "")]
    elif (.PrefixListIds | length) > 0 then
        .PrefixListIds[] |
        [$proto, $from, $to, ("PL:" + .PrefixListId), (.Description // "")]
    else
        [$proto, $from, $to, "Unknown", ""]
    end |
    @tsv
    ' | while IFS=$'\t' read -r proto from to dest desc; do
        printf "%-12s | %-10s | %-10s | %-45s | %s\n" "$proto" "$from" "$to" "$dest" "$desc"
    done
    
    print_separator 120
}

# Display EC2 instances using this SG
display_ec2_instances() {
    print_header "EC2 Instances using this SG"
    
    local instances
    instances=$(aws_query ec2 describe-instances \
        --filters "Name=instance.group-id,Values=$SG_ID" \
        --query "Reservations[*].Instances[*].[InstanceId,InstanceType,State.Name,PrivateIpAddress,Tags[?Key=='Name'].Value|[0]]" \
        --output json)
    
    if [[ -z "$instances" || "$instances" == "[]" || "$instances" == "[[]]" ]]; then
        echo -e "${YELLOW}  No EC2 instances found${NC}"
        print_separator
        return
    fi
    
    printf "%-20s | %-15s | %-12s | %-16s | %s\n" "InstanceId" "Type" "State" "PrivateIP" "Name"
    print_separator 100
    
    echo "$instances" | jq -r '.[][] | @tsv' | while IFS=$'\t' read -r id type state ip name; do
        printf "%-20s | %-15s | %-12s | %-16s | %s\n" "$id" "$type" "$state" "$ip" "${name:-N/A}"
    done
    
    print_separator 100
}

# Get resource details for an ENI
get_eni_resource_details() {
    local eni_id="$1"
    local if_type="$2"
    local instance_id="$3"
    
    case "$if_type" in
        "interface")
            if [[ "$instance_id" != "None" && "$instance_id" != "-" && "$instance_id" != "null" ]]; then
                echo "EC2: $instance_id"
            else
                echo "Standalone ENI"
            fi
            ;;
        "lambda")
            local lambda_arn
            lambda_arn=$(aws_query ec2 describe-network-interfaces \
                --network-interface-ids "$eni_id" \
                --query 'NetworkInterfaces[0].RequesterId' \
                --output text 2>/dev/null)
            
            if [[ -n "$lambda_arn" && "$lambda_arn" != "None" ]]; then
                echo "Lambda: $lambda_arn"
            else
                echo "Lambda (ENI)"
            fi
            ;;
        "nat_gateway")
            local nat_gw
            nat_gw=$(aws_query ec2 describe-nat-gateways \
                --filter "Name=network-interface-id,Values=$eni_id" \
                --query 'NatGateways[0].NatGatewayId' \
                --output text 2>/dev/null)
            
            if [[ -n "$nat_gw" && "$nat_gw" != "None" ]]; then
                echo "NAT Gateway: $nat_gw"
            else
                echo "NAT Gateway"
            fi
            ;;
        "network_load_balancer"|"gateway_load_balancer"|"gateway_load_balancer_endpoint")
            local lb_arn
            lb_arn=$(aws_query ec2 describe-network-interfaces \
                --network-interface-ids "$eni_id" \
                --query 'NetworkInterfaces[0].Description' \
                --output text 2>/dev/null)
            
            echo "Load Balancer: ${lb_arn:-Unknown}"
            ;;
        "vpc_endpoint")
            local vpc_endpoint
            vpc_endpoint=$(aws_query ec2 describe-vpc-endpoints \
                --filters "Name=network-interface-id,Values=$eni_id" \
                --query 'VpcEndpoints[0].VpcEndpointId' \
                --output text 2>/dev/null)
            
            if [[ -n "$vpc_endpoint" && "$vpc_endpoint" != "None" ]]; then
                echo "VPC Endpoint: $vpc_endpoint"
            else
                echo "VPC Endpoint"
            fi
            ;;
        "efs")
            echo "EFS Mount Target"
            ;;
        "rds")
            local rds_id
            rds_id=$(aws_query rds describe-db-instances \
                --query "DBInstances[?VpcSecurityGroups[?VpcSecurityGroupId=='$SG_ID']].DBInstanceIdentifier" \
                --output text 2>/dev/null | head -n1)
            
            if [[ -n "$rds_id" ]]; then
                echo "RDS: $rds_id"
            else
                echo "RDS Instance"
            fi
            ;;
        *)
            echo "Other: $if_type"
            ;;
    esac
}

# Display ENIs using this SG with improved resource identification
display_enis() {
    print_header "Network Interfaces (ENIs) using this SG"
    
    local enis
    enis=$(aws_query ec2 describe-network-interfaces \
        --filters "Name=group-id,Values=$SG_ID" \
        --output json)
    
    if [[ -z "$enis" || "$enis" == '{"NetworkInterfaces":[]}' ]]; then
        echo -e "${YELLOW}  No ENIs found${NC}"
        print_separator
        return
    fi
    
    printf "%-22s | %-22s | %-16s | %-20s | %-15s | %-15s | %s\n" \
        "ENI ID" "Instance ID" "Private IP" "Subnet ID" "VPC ID" "AZ" "Resource"
    print_separator 160
    
    echo "$enis" | jq -c '.NetworkInterfaces[]' | while read -r eni; do
        local eni_id=$(echo "$eni" | jq -r '.NetworkInterfaceId')
        local instance_id=$(echo "$eni" | jq -r '.Attachment.InstanceId // "N/A"')
        local private_ip=$(echo "$eni" | jq -r '.PrivateIpAddress // "N/A"')
        local subnet_id=$(echo "$eni" | jq -r '.SubnetId // "N/A"')
        local vpc_id=$(echo "$eni" | jq -r '.VpcId // "N/A"')
        local az=$(echo "$eni" | jq -r '.AvailabilityZone // "N/A"')
        local if_type=$(echo "$eni" | jq -r '.InterfaceType // "interface"')
        local description=$(echo "$eni" | jq -r '.Description // ""')
        
        # Get detailed resource information
        local resource=$(get_eni_resource_details "$eni_id" "$if_type" "$instance_id")
        
        # Add description if it provides useful context
        if [[ -n "$description" && "$description" != "null" ]]; then
            resource="$resource ($description)"
        fi
        
        printf "%-22s | %-22s | %-16s | %-20s | %-15s | %-15s | %s\n" \
            "$eni_id" "$instance_id" "$private_ip" "$subnet_id" "$vpc_id" "$az" "$resource"
    done
    
    print_separator 160
}

# Display ECS tasks using this SG
display_ecs_tasks() {
    print_header "ECS Tasks using this SG"
    
    local clusters
    clusters=$(aws_query ecs list-clusters --query "clusterArns[]" --output text)
    
    if [[ -z "$clusters" ]]; then
        echo -e "${YELLOW}  No ECS clusters found${NC}"
        print_separator
        return
    fi
    
    printf "%-40s | %-80s | %-22s | %s\n" "Cluster" "Task ARN" "ENI ID" "Private IP"
    print_separator 180
    
    local found_tasks=false
    
    for cluster in $clusters; do
        local tasks
        tasks=$(aws_query ecs list-tasks --cluster "$cluster" --query "taskArns[]" --output text)
        
        if [[ -n "$tasks" ]]; then
            for task in $tasks; do
                local enis_task
                enis_task=$(aws_query ecs describe-tasks \
                    --cluster "$cluster" \
                    --tasks "$task" \
                    --query "tasks[].attachments[].details[?name=='networkInterfaceId'].value" \
                    --output text)
                
                for eni in $enis_task; do
                    local sg_check
                    sg_check=$(aws_query ec2 describe-network-interfaces \
                        --network-interface-ids "$eni" \
                        --query "NetworkInterfaces[?contains(Groups[].GroupId,'$SG_ID')].[NetworkInterfaceId,PrivateIpAddress]" \
                        --output text)
                    
                    if [[ -n "$sg_check" ]]; then
                        local eni_id=$(echo "$sg_check" | awk '{print $1}')
                        local private_ip=$(echo "$sg_check" | awk '{print $2}')
                        printf "%-40s | %-80s | %-22s | %s\n" \
                            "${cluster##*/}" "${task##*/}" "$eni_id" "$private_ip"
                        found_tasks=true
                    fi
                done
            done
        fi
    done
    
    if [[ "$found_tasks" == false ]]; then
        echo -e "${YELLOW}  No ECS tasks found using this security group${NC}"
    fi
    
    print_separator 180
}

# Display EKS nodes using this SG
display_eks_nodes() {
    print_header "EKS Node ENIs using this SG"
    
    local eks_instances
    eks_instances=$(aws_query ec2 describe-instances \
        --filters "Name=tag:eks:cluster-name,Values=*" "Name=instance-state-name,Values=running" \
        --query "Reservations[*].Instances[*].InstanceId" \
        --output text)
    
    if [[ -z "$eks_instances" ]]; then
        echo -e "${YELLOW}  No EKS nodes found${NC}"
        print_separator
        return
    fi
    
    printf "%-22s | %-22s | %-16s | %-20s | %-15s | %s\n" \
        "ENI ID" "Instance ID" "Private IP" "Subnet ID" "VPC ID" "AZ"
    print_separator 140
    
    local found_eks=false
    
    for instance in $eks_instances; do
        local eks_enis
        eks_enis=$(aws_query ec2 describe-network-interfaces \
            --filters "Name=attachment.instance-id,Values=$instance" "Name=group-id,Values=$SG_ID" \
            --query "NetworkInterfaces[*].[NetworkInterfaceId,Attachment.InstanceId,PrivateIpAddress,SubnetId,VpcId,AvailabilityZone]" \
            --output text)
        
        if [[ -n "$eks_enis" ]]; then
            echo "$eks_enis" | while read -r line; do
                printf "%-22s | %-22s | %-16s | %-20s | %-15s | %s\n" $line
            done
            found_eks=true
        fi
    done
    
    if [[ "$found_eks" == false ]]; then
        echo -e "${YELLOW}  No EKS nodes found using this security group${NC}"
    fi
    
    print_separator 140
}

# Display load balancers using this SG
display_load_balancers() {
    print_header "Elastic Load Balancers (ALB/NLB/GWLB) using this SG"
    
    local lbs
    lbs=$(aws_query elbv2 describe-load-balancers \
        --query "LoadBalancers[?SecurityGroups && contains(SecurityGroups,'$SG_ID')]" \
        --output json)
    
    if [[ -z "$lbs" || "$lbs" == "[]" ]]; then
        echo -e "${YELLOW}  No load balancers found${NC}"
        print_separator
        return
    fi
    
    printf "%-35s | %-12s | %-80s | %s\n" "Load Balancer Name" "Type" "DNS Name" "VPC ID"
    print_separator 160
    
    echo "$lbs" | jq -r '.[] | [.LoadBalancerName, .Type, .DNSName, .VpcId] | @tsv' | \
    while IFS=$'\t' read -r name type dns vpc; do
        printf "%-35s | %-12s | %-80s | %s\n" "$name" "$type" "$dns" "$vpc"
    done
    
    print_separator 160
}

# Display RDS instances using this SG
display_rds_instances() {
    print_header "RDS Instances using this SG"
    
    local rds_instances
    rds_instances=$(aws_query rds describe-db-instances \
        --query "DBInstances[?VpcSecurityGroups[?VpcSecurityGroupId=='$SG_ID']]" \
        --output json)
    
    if [[ -z "$rds_instances" || "$rds_instances" == "[]" ]]; then
        echo -e "${YELLOW}  No RDS instances found${NC}"
        print_separator
        return
    fi
    
    printf "%-30s | %-15s | %-15s | %-12s | %s\n" \
        "DB Instance ID" "Engine" "Class" "Status" "Endpoint"
    print_separator 140
    
    echo "$rds_instances" | jq -r '.[] | 
        [.DBInstanceIdentifier, .Engine, .DBInstanceClass, .DBInstanceStatus, .Endpoint.Address] | @tsv' | \
    while IFS=$'\t' read -r id engine class status endpoint; do
        printf "%-30s | %-15s | %-15s | %-12s | %s\n" "$id" "$engine" "$class" "$status" "${endpoint:-N/A}"
    done
    
    print_separator 140
}

# Display Lambda functions using this SG
display_lambda_functions() {
    print_header "Lambda Functions using this SG"
    
    local functions
    functions=$(aws_query lambda list-functions \
        --query "Functions[?VpcConfig.SecurityGroupIds && contains(VpcConfig.SecurityGroupIds, '$SG_ID')]" \
        --output json)
    
    if [[ -z "$functions" || "$functions" == "[]" ]]; then
        echo -e "${YELLOW}  No Lambda functions found${NC}"
        print_separator
        return
    fi
    
    printf "%-40s | %-15s | %-30s | %s\n" "Function Name" "Runtime" "Last Modified" "VPC ID"
    print_separator 130
    
    echo "$functions" | jq -r '.[] | 
        [.FunctionName, .Runtime, .LastModified, .VpcConfig.VpcId] | @tsv' | \
    while IFS=$'\t' read -r name runtime modified vpc; do
        printf "%-40s | %-15s | %-30s | %s\n" "$name" "$runtime" "$modified" "${vpc:-N/A}"
    done
    
    print_separator 130
}

# Display ElastiCache clusters using this SG
display_elasticache_clusters() {
    print_header "ElastiCache Clusters using this SG"
    
    local clusters
    clusters=$(aws_query elasticache describe-cache-clusters \
        --show-cache-cluster-details \
        --query "CacheClusters[?SecurityGroups[?SecurityGroupId=='$SG_ID']]" \
        --output json 2>/dev/null)
    
    if [[ -z "$clusters" || "$clusters" == "[]" ]]; then
        echo -e "${YELLOW}  No ElastiCache clusters found${NC}"
        print_separator
        return
    fi
    
    printf "%-30s | %-10s | %-15s | %s\n" "Cluster ID" "Engine" "Node Type" "Status"
    print_separator 100
    
    echo "$clusters" | jq -r '.[] | 
        [.CacheClusterId, .Engine, .CacheNodeType, .CacheClusterStatus] | @tsv' | \
    while IFS=$'\t' read -r id engine node_type status; do
        printf "%-30s | %-10s | %-15s | %s\n" "$id" "$engine" "$node_type" "$status"
    done
    
    print_separator 100
}

# Main execution function
main() {
    parse_arguments "$@"
    
    echo -e "${YELLOW}Checking Security Group: $SG_ID${NC}"
    echo -e "${YELLOW}Profile: $AWS_PROFILE | Region: $REGION${NC}"
    print_separator
    echo
    
    # Get and validate security group
    local sg_json
    sg_json=$(get_sg_info)
    
    # Display all information
    display_sg_info "$sg_json"
    echo
    
    display_inbound_rules "$sg_json"
    echo
    
    display_outbound_rules "$sg_json"
    echo
    
    display_ec2_instances
    echo
    
    display_enis
    echo
    
    display_ecs_tasks
    echo
    
    display_eks_nodes
    echo
    
    display_load_balancers
    echo
    
    display_rds_instances
    echo
    
    display_lambda_functions
    echo
    
    display_elasticache_clusters
    echo
    
    print_separator
    echo -e "${GREEN}✅ Security Group audit complete.${NC}"
}

# Run main function
main "$@"
