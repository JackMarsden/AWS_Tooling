#!/bin/bash
# SecurityGroupEnum.sh
# Comprehensive AWS Security Group enumeration and audit tool
# 
# Usage: ./SecurityGroupEnum.sh --profile <aws-profile> --group <sg-id> [--region <region>]

set -euo pipefail

# Colours (Australian English spelling)
readonly RED="\033[1;31m"
readonly YELLOW="\033[1;33m"
readonly CYAN="\033[1;36m"
readonly GREEN="\033[0;32m"
readonly BOLD="\033[1m"
readonly NC="\033[0m"

# Global variables
AWS_PROFILE=""
SG_ID=""
REGION=""
RESOURCE_FOUND=false

# Cleanup temp files on exit
cleanup() {
    rm -f /tmp/sg_check_*_$$ 2>/dev/null || true
}
trap cleanup EXIT

# Display usage
usage() {
    cat << EOF
${YELLOW}Usage:${NC} $0 --profile <aws-profile> --group <sg-id> [--region <region>]

${YELLOW}Options:${NC}
    --profile    AWS CLI profile to use
    --group      Security Group ID (sg-xxxxxxxxxxxx)
    --region     AWS region (optional, uses profile default)
    -h, --help   Show this help message

${YELLOW}Example:${NC}
    $0 --profile prod --group sg-12345678
    $0 --profile dev --group sg-87654321 --region us-east-1
EOF
    exit 1
}

# Parse arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --profile) AWS_PROFILE="$2"; shift 2 ;;
            --group) SG_ID="$2"; shift 2 ;;
            --region) REGION="$2"; shift 2 ;;
            -h|--help) usage ;;
            *) echo -e "${RED}Unknown parameter: $1${NC}"; usage ;;
        esac
    done

    [[ -z "$AWS_PROFILE" || -z "$SG_ID" ]] && { echo -e "${RED}Error: --profile and --group required${NC}"; usage; }
    
    # Validate SG ID format
    if [[ ! "$SG_ID" =~ ^sg-[a-f0-9]{8,17}$ ]]; then
        echo -e "${RED}Error: Invalid Security Group ID format: $SG_ID${NC}"
        echo -e "${YELLOW}Expected format: sg-xxxxxxxx or sg-xxxxxxxxxxxxxxxxx${NC}"
        exit 1
    fi
    
    if [[ -z "$REGION" ]]; then
        REGION=$(aws configure get region --profile "$AWS_PROFILE" 2>/dev/null || echo "us-east-1")
    fi
}

# Execute AWS CLI command
aws_query() {
    aws "$@" --profile "$AWS_PROFILE" --region "$REGION" 2>/dev/null || return 1
}

# Print section header
print_header() {
    echo -e "${YELLOW}$1:${NC}"
}

# Print separator
print_separator() {
    printf '%*s\n' "${1:-100}" '' | tr ' ' '-'
}

# Get Security Group JSON
get_sg_info() {
    local sg_json
    
    if ! sg_json=$(aws_query ec2 describe-security-groups --group-ids "$SG_ID" --query "SecurityGroups[0]" --output json); then
        echo -e "${RED}Error: Failed to retrieve Security Group information${NC}"
        echo -e "${YELLOW}This could be due to:${NC}"
        echo -e "${YELLOW}  - Invalid AWS credentials for profile '$AWS_PROFILE'${NC}"
        echo -e "${YELLOW}  - Insufficient permissions to describe security groups${NC}"
        echo -e "${YELLOW}  - Network connectivity issues${NC}"
        exit 1
    fi
    
    if [[ -z "$sg_json" || "$sg_json" == "null" ]]; then
        echo -e "${RED}Error: Security Group $SG_ID not found in region $REGION${NC}"
        exit 1
    fi
    
    echo "$sg_json"
}

# Check if SG is AWS-managed
is_aws_managed() {
    local sg_json="$1"
    local sg_name=$(echo "$sg_json" | jq -r '.GroupName')
    local sg_desc=$(echo "$sg_json" | jq -r '.Description')
    
    # Check for AWS-managed patterns
    if [[ "$sg_name" =~ ^default$ ]] || \
       [[ "$sg_desc" =~ ^"AWS created security group" ]] || \
       [[ "$sg_desc" =~ ^"Managed by AWS" ]] || \
       [[ "$sg_desc" =~ ^"Security group for AWS" ]] || \
       [[ "$sg_name" =~ ^"aws-" ]] || \
       [[ "$sg_name" =~ ^"AWS-" ]]; then
        echo "AWS-MANAGED"
        return 0
    fi
    
    # Check for GuardDuty
    if [[ "$sg_name" =~ [Gg]uard[Dd]uty ]] || \
       [[ "$sg_desc" =~ [Gg]uard[Dd]uty ]] || \
       [[ "$sg_name" =~ ^"GuardDuty-" ]]; then
        echo "GUARDDUTY"
        return 0
    fi
    
    # Check for other AWS service patterns
    if [[ "$sg_desc" =~ "ECS-Optimized" ]] || \
       [[ "$sg_desc" =~ "EKS created security group" ]] || \
       [[ "$sg_desc" =~ "RDS security group" ]] || \
       [[ "$sg_desc" =~ "ElastiCache security group" ]] || \
       [[ "$sg_desc" =~ "Elastic Beanstalk" ]] || \
       [[ "$sg_desc" =~ "Amazon EMR" ]]; then
        echo "AWS-SERVICE"
        return 0
    fi
    
    echo "USER-MANAGED"
    return 1
}

# Display SG basic info
display_sg_info() {
    local sg_json="$1"
    local sg_name=$(echo "$sg_json" | jq -r '.GroupName')
    local management_type=$(is_aws_managed "$sg_json")
    
    echo -e "${CYAN}${BOLD}Security Group: $SG_ID${NC}"
    echo -e "${CYAN}Name: $sg_name${NC}"
    echo -e "${CYAN}Description: $(echo "$sg_json" | jq -r '.Description')${NC}"
    echo -e "${CYAN}VPC ID: $(echo "$sg_json" | jq -r '.VpcId')${NC}"
    echo -e "${CYAN}Region: $REGION${NC}"
    
    # Display management type
    case "$management_type" in
        "AWS-MANAGED")
            echo -e "${CYAN}Management: ${YELLOW}${BOLD}AWS-Managed${NC}"
            ;;
        "GUARDDUTY")
            echo -e "${CYAN}Management: ${YELLOW}${BOLD}GuardDuty-Managed${NC}"
            ;;
        "AWS-SERVICE")
            echo -e "${CYAN}Management: ${YELLOW}${BOLD}AWS Service-Managed${NC}"
            ;;
        "USER-MANAGED")
            echo -e "${CYAN}Management: ${GREEN}User-Managed${NC}"
            ;;
    esac
    
    # Display tags if present
    local tags=$(echo "$sg_json" | jq -r '.Tags // []')
    if [[ "$tags" != "[]" ]]; then
        echo -e "${CYAN}Tags:${NC}"
        echo "$sg_json" | jq -r '.Tags[]? | "  \(.Key): \(.Value)"'
    fi
    
    print_separator
}

# Display inbound rules
display_inbound_rules() {
    local sg_json="$1"
    print_header "Inbound Rules"
    
    local rules=$(echo "$sg_json" | jq -c '.IpPermissions')
    
    if [[ "$rules" == "[]" ]]; then
        echo -e "${YELLOW}  No inbound rules${NC}"
        print_separator
        return
    fi
    
    printf "%-12s | %-10s | %-10s | %-45s | %s\n" "Protocol" "From" "To" "Source" "Description"
    print_separator 120
    
    echo "$sg_json" | jq -r '
    .IpPermissions[] |
    (if .IpProtocol == "-1" then "All" else .IpProtocol end) as $proto |
    (if .FromPort then .FromPort else "All" end) as $from |
    (if .ToPort then .ToPort else "All" end) as $to |
    
    if (.IpRanges | length) > 0 then
        .IpRanges[] | [$proto, $from, $to, .CidrIp, (.Description // "")]
    elif (.Ipv6Ranges | length) > 0 then
        .Ipv6Ranges[] | [$proto, $from, $to, .CidrIpv6, (.Description // "")]
    elif (.UserIdGroupPairs | length) > 0 then
        .UserIdGroupPairs[] | [$proto, $from, $to, ("SG:" + .GroupId), (.Description // "")]
    elif (.PrefixListIds | length) > 0 then
        .PrefixListIds[] | [$proto, $from, $to, ("PL:" + .PrefixListId), (.Description // "")]
    else [$proto, $from, $to, "Unknown", ""] end | @tsv
    ' | while IFS=$'\t' read -r proto from to source desc; do
        printf "%-12s | %-10s | %-10s | %-45s | %s\n" "$proto" "$from" "$to" "$source" "$desc"
    done
    
    print_separator 120
}

# Display outbound rules
display_outbound_rules() {
    local sg_json="$1"
    print_header "Outbound Rules"
    
    local rules=$(echo "$sg_json" | jq -c '.IpPermissionsEgress')
    
    if [[ "$rules" == "[]" ]]; then
        echo -e "${CYAN}  (Default) Allow all outbound traffic${NC}"
        print_separator
        return
    fi
    
    # Check for default allow-all rule
    local is_default=$(echo "$sg_json" | jq -r '
    .IpPermissionsEgress | 
    if length == 1 and .[0].IpProtocol == "-1" and 
       (.[0].IpRanges[0].CidrIp == "0.0.0.0/0" or .[0].Ipv6Ranges[0].CidrIpv6 == "::/0")
    then "true" else "false" end')
    
    [[ "$is_default" == "true" ]] && echo -e "${CYAN}  (Default) Allow all outbound traffic${NC}"
    
    printf "%-12s | %-10s | %-10s | %-45s | %s\n" "Protocol" "From" "To" "Destination" "Description"
    print_separator 120
    
    echo "$sg_json" | jq -r '
    .IpPermissionsEgress[] |
    (if .IpProtocol == "-1" then "All" else .IpProtocol end) as $proto |
    (if .FromPort then .FromPort else "All" end) as $from |
    (if .ToPort then .ToPort else "All" end) as $to |
    
    if (.IpRanges | length) > 0 then
        .IpRanges[] | [$proto, $from, $to, .CidrIp, (.Description // "")]
    elif (.Ipv6Ranges | length) > 0 then
        .Ipv6Ranges[] | [$proto, $from, $to, .CidrIpv6, (.Description // "")]
    elif (.UserIdGroupPairs | length) > 0 then
        .UserIdGroupPairs[] | [$proto, $from, $to, ("SG:" + .GroupId), (.Description // "")]
    elif (.PrefixListIds | length) > 0 then
        .PrefixListIds[] | [$proto, $from, $to, ("PL:" + .PrefixListId), (.Description // "")]
    else [$proto, $from, $to, "Unknown", ""] end | @tsv
    ' | while IFS=$'\t' read -r proto from to dest desc; do
        printf "%-12s | %-10s | %-10s | %-45s | %s\n" "$proto" "$from" "$to" "$dest" "$desc"
    done
    
    print_separator 120
}

# Generic function to check and display resources
check_simple_resource() {
    local header="$1"
    local service="$2"
    local command="$3"
    local query="$4"
    local column_headers="$5"
    local column_widths="$6"
    local no_results_msg="${7:-No resources found}"
    
    print_header "$header"
    
    local data
    if ! data=$(aws_query "$service" "$command" --query "$query" --output json); then
        echo -e "${YELLOW}  Unable to query $service (may lack permissions or service unavailable)${NC}"
        print_separator
        return
    fi
    
    if [[ -z "$data" || "$data" == "[]" || "$data" == "null" ]]; then
        echo -e "${YELLOW}  $no_results_msg${NC}"
        print_separator
        return
    fi
    
    # Check if array has elements
    local count=$(echo "$data" | jq 'if type == "array" then length else 0 end')
    if [[ "$count" -eq 0 ]]; then
        echo -e "${YELLOW}  $no_results_msg${NC}"
        print_separator
        return
    fi
    
    RESOURCE_FOUND=true
    
    # Print headers
    IFS='|' read -ra headers <<< "$column_headers"
    IFS='|' read -ra widths <<< "$column_widths"
    
    local format=""
    local sep_length=0
    for i in "${!headers[@]}"; do
        if [[ $i -gt 0 ]]; then
            format+=" | "
            sep_length=$((sep_length + 3))
        fi
        format+="%-${widths[$i]}s"
        sep_length=$((sep_length + widths[$i]))
    done
    format+="\n"
    
    printf "$format" "${headers[@]}"
    print_separator "$sep_length"
    
    # Print data - FIX: Handle multi-column data properly
    echo "$data" | jq -r '.[] | @tsv' | while IFS=$'\t' read -r -a values; do
        printf "$format" "${values[@]}"
    done
    
    print_separator "$sep_length"
}

# Check EC2 instances
check_ec2_instances() {
    print_header "EC2 Instances"
    
    local instances
    if ! instances=$(aws_query ec2 describe-instances \
        --filters "Name=instance.group-id,Values=$SG_ID" "Name=instance-state-name,Values=pending,running,stopping,stopped" \
        --query "Reservations[*].Instances[*].[InstanceId,InstanceType,State.Name,PrivateIpAddress,Tags[?Key=='Name'].Value|[0]||'N/A']" \
        --output json); then
        echo -e "${YELLOW}  Unable to query EC2 instances${NC}"
        print_separator
        return
    fi
    
    # Flatten the nested array structure
    local flattened=$(echo "$instances" | jq -c 'flatten(1)')
    local count=$(echo "$flattened" | jq 'length')
    
    if [[ "$count" -eq 0 ]]; then
        echo -e "${YELLOW}  No EC2 instances found${NC}"
        print_separator
        return
    fi
    
    RESOURCE_FOUND=true
    
    printf "%-20s | %-15s | %-12s | %-16s | %s\n" "Instance ID" "Type" "State" "Private IP" "Name"
    print_separator 100
    
    echo "$flattened" | jq -r '.[] | @tsv' | while IFS=$'\t' read -r inst_id type state ip name; do
        printf "%-20s | %-15s | %-12s | %-16s | %s\n" "$inst_id" "$type" "$state" "$ip" "$name"
    done
    
    print_separator 100
}

# Check ENIs
check_enis() {
    print_header "Network Interfaces (ENIs)"
    
    local enis
    if ! enis=$(aws_query ec2 describe-network-interfaces \
        --filters "Name=group-id,Values=$SG_ID" \
        --output json); then
        echo -e "${YELLOW}  Unable to query network interfaces${NC}"
        print_separator
        return
    fi
    
    local count=$(echo "$enis" | jq '.NetworkInterfaces | length')
    if [[ "$count" -eq 0 ]]; then
        echo -e "${YELLOW}  No ENIs found${NC}"
        print_separator
        return
    fi
    
    RESOURCE_FOUND=true
    printf "%-22s | %-22s | %-16s | %-20s | %s\n" "ENI ID" "Instance ID" "Private IP" "Subnet ID" "Description"
    print_separator 120
    
    echo "$enis" | jq -r '.NetworkInterfaces[] | 
        [.NetworkInterfaceId, (.Attachment.InstanceId // "N/A"), (.PrivateIpAddress // "N/A"), 
         (.SubnetId // "N/A"), ((.Description // "N/A") | .[0:50])] | @tsv' | \
    while IFS=$'\t' read -r eni_id inst_id ip subnet desc; do
        printf "%-22s | %-22s | %-16s | %-20s | %s\n" "$eni_id" "$inst_id" "$ip" "$subnet" "$desc"
    done
    print_separator 120
}

# Check referencing security groups
check_referencing_sgs() {
    print_header "Security Groups Referencing This SG"
    
    local all_sgs
    if ! all_sgs=$(aws_query ec2 describe-security-groups --output json); then
        echo -e "${YELLOW}  Unable to query security groups${NC}"
        print_separator
        return
    fi
    
    local temp_file="/tmp/sg_check_refs_$$"
    > "$temp_file"
    
    # Check both ingress and egress rules for references to our SG
    echo "$all_sgs" | jq -r --arg sg_id "$SG_ID" '
    .SecurityGroups[] | 
    select(
        (.IpPermissions[]?.UserIdGroupPairs[]?.GroupId == $sg_id) or
        (.IpPermissionsEgress[]?.UserIdGroupPairs[]?.GroupId == $sg_id)
    ) | 
    [.GroupId, .GroupName, .VpcId] | @tsv' > "$temp_file"
    
    if [[ ! -s "$temp_file" ]]; then
        echo -e "${YELLOW}  No security groups referencing this SG${NC}"
        print_separator
        return
    fi
    
    RESOURCE_FOUND=true
    printf "%-25s | %-40s | %s\n" "Security Group ID" "Name" "VPC ID"
    print_separator 90
    
    while IFS=$'\t' read -r sg_id name vpc_id; do
        printf "%-25s | %-40s | %s\n" "$sg_id" "$name" "$vpc_id"
    done < "$temp_file"
    
    print_separator 90
}

# Check ECS tasks
check_ecs_tasks() {
    print_header "ECS Tasks"
    
    local clusters
    if ! clusters=$(aws_query ecs list-clusters --query "clusterArns[]" --output text); then
        echo -e "${YELLOW}  Unable to query ECS clusters${NC}"
        print_separator
        return
    fi
    
    if [[ -z "$clusters" ]]; then
        echo -e "${YELLOW}  No ECS clusters found${NC}"
        print_separator
        return
    fi
    
    local temp_file="/tmp/sg_check_ecs_$$"
    > "$temp_file"
    
    for cluster in $clusters; do
        local tasks
        if ! tasks=$(aws_query ecs list-tasks --cluster "$cluster" --query "taskArns[]" --output text); then
            continue
        fi
        [[ -z "$tasks" ]] && continue
        
        for task in $tasks; do
            local enis
            if ! enis=$(aws_query ecs describe-tasks --cluster "$cluster" --tasks "$task" \
                --query "tasks[].attachments[].details[?name=='networkInterfaceId'].value" --output text); then
                continue
            fi
            
            for eni in $enis; do
                if aws_query ec2 describe-network-interfaces --network-interface-ids "$eni" \
                    --query "NetworkInterfaces[?Groups[?GroupId=='$SG_ID']].NetworkInterfaceId" \
                    --output text 2>/dev/null | grep -q .; then
                    echo "${cluster##*/}|${task##*/}|$eni" >> "$temp_file"
                fi
            done
        done
    done
    
    if [[ ! -s "$temp_file" ]]; then
        echo -e "${YELLOW}  No ECS tasks using this SG${NC}"
        print_separator
        return
    fi
    
    RESOURCE_FOUND=true
    printf "%-40s | %-80s | %s\n" "Cluster" "Task" "ENI ID"
    print_separator 140
    
    while IFS='|' read -r cluster task eni; do
        printf "%-40s | %-80s | %s\n" "$cluster" "$task" "$eni"
    done < "$temp_file"
    
    print_separator 140
}

# Check EKS nodes
check_eks_nodes() {
    print_header "EKS Node ENIs"
    
    local instances
    if ! instances=$(aws_query ec2 describe-instances \
        --filters "Name=tag:eks:cluster-name,Values=*" "Name=instance-state-name,Values=running" \
        --query "Reservations[*].Instances[*].InstanceId" --output text); then
        echo -e "${YELLOW}  Unable to query EKS nodes${NC}"
        print_separator
        return
    fi
    
    if [[ -z "$instances" ]]; then
        echo -e "${YELLOW}  No EKS nodes found${NC}"
        print_separator
        return
    fi
    
    local temp_file="/tmp/sg_check_eks_$$"
    > "$temp_file"
    
    for instance in $instances; do
        local enis
        if ! enis=$(aws_query ec2 describe-network-interfaces \
            --filters "Name=attachment.instance-id,Values=$instance" "Name=group-id,Values=$SG_ID" \
            --query "NetworkInterfaces[*].[NetworkInterfaceId,Attachment.InstanceId,PrivateIpAddress,SubnetId]" \
            --output text); then
            continue
        fi
        
        [[ -n "$enis" ]] && echo "$enis" >> "$temp_file"
    done
    
    if [[ ! -s "$temp_file" ]]; then
        echo -e "${YELLOW}  No EKS nodes using this SG${NC}"
        print_separator
        return
    fi
    
    RESOURCE_FOUND=true
    printf "%-22s | %-22s | %-16s | %s\n" "ENI ID" "Instance ID" "Private IP" "Subnet ID"
    print_separator 100
    
    while read -r line; do
        printf "%-22s | %-22s | %-16s | %s\n" $line
    done < "$temp_file"
    
    print_separator 100
}

# Check load balancers
check_load_balancers() {
    check_simple_resource \
        "Load Balancers (ALB/NLB/GWLB)" \
        "elbv2" \
        "describe-load-balancers" \
        "LoadBalancers[?SecurityGroups && contains(SecurityGroups,'$SG_ID')].[LoadBalancerName,Type,DNSName]" \
        "Name|Type|DNS Name" \
        "35|12|70" \
        "No load balancers found"
}

# Check Classic Load Balancers (ELB v1)
check_classic_load_balancers() {
    print_header "Classic Load Balancers (ELB)"
    
    local elbs
    if ! elbs=$(aws_query elb describe-load-balancers --output json); then
        echo -e "${YELLOW}  Unable to query Classic Load Balancers${NC}"
        print_separator
        return
    fi
    
    local filtered=$(echo "$elbs" | jq -r --arg sg_id "$SG_ID" '
    .LoadBalancerDescriptions[] | 
    select(.SecurityGroups[] == $sg_id) | 
    [.LoadBalancerName, .DNSName, .Scheme] | @tsv')
    
    if [[ -z "$filtered" ]]; then
        echo -e "${YELLOW}  No Classic Load Balancers found${NC}"
        print_separator
        return
    fi
    
    RESOURCE_FOUND=true
    printf "%-40s | %-60s | %s\n" "Name" "DNS Name" "Scheme"
    print_separator 120
    
    echo "$filtered" | while IFS=$'\t' read -r name dns scheme; do
        printf "%-40s | %-60s | %s\n" "$name" "$dns" "$scheme"
    done
    
    print_separator 120
}

# Check RDS instances
check_rds_instances() {
    check_simple_resource \
        "RDS Instances" \
        "rds" \
        "describe-db-instances" \
        "DBInstances[?VpcSecurityGroups[?VpcSecurityGroupId=='$SG_ID']].[DBInstanceIdentifier,Engine,DBInstanceClass,DBInstanceStatus]" \
        "DB Identifier|Engine|Class|Status" \
        "30|15|15|15" \
        "No RDS instances found"
}

# Check RDS Clusters
check_rds_clusters() {
    check_simple_resource \
        "RDS Clusters (Aurora)" \
        "rds" \
        "describe-db-clusters" \
        "DBClusters[?VpcSecurityGroups[?VpcSecurityGroupId=='$SG_ID']].[DBClusterIdentifier,Engine,Status]" \
        "Cluster Identifier|Engine|Status" \
        "40|15|15" \
        "No RDS clusters found"
}

# Check Lambda functions
check_lambda_functions() {
    print_header "Lambda Functions"
    
    local functions
    if ! functions=$(aws_query lambda list-functions --output json); then
        echo -e "${YELLOW}  Unable to query Lambda functions${NC}"
        print_separator
        return
    fi
    
    local filtered=$(echo "$functions" | jq -r --arg sg_id "$SG_ID" '
    .Functions[] | 
    select(.VpcConfig.SecurityGroupIds[]? == $sg_id) | 
    [.FunctionName, .Runtime, .LastModified] | @tsv')
    
    if [[ -z "$filtered" ]]; then
        echo -e "${YELLOW}  No Lambda functions found${NC}"
        print_separator
        return
    fi
    
    RESOURCE_FOUND=true
    printf "%-40s | %-20s | %s\n" "Function Name" "Runtime" "Last Modified"
    print_separator 100
    
    echo "$filtered" | while IFS=$'\t' read -r name runtime modified; do
        printf "%-40s | %-20s | %s\n" "$name" "$runtime" "$modified"
    done
    
    print_separator 100
}

# Check ElastiCache clusters
check_elasticache() {
    check_simple_resource \
        "ElastiCache Clusters" \
        "elasticache" \
        "describe-cache-clusters" \
        "CacheClusters[?SecurityGroups[?SecurityGroupId=='$SG_ID']].[CacheClusterId,Engine,CacheNodeType,CacheClusterStatus]" \
        "Cluster ID|Engine|Node Type|Status" \
        "30|10|15|15" \
        "No ElastiCache clusters found"
}

# Check Redshift clusters
check_redshift() {
    check_simple_resource \
        "Redshift Clusters" \
        "redshift" \
        "describe-clusters" \
        "Clusters[?VpcSecurityGroups[?VpcSecurityGroupId=='$SG_ID']].[ClusterIdentifier,NodeType,ClusterStatus]" \
        "Cluster ID|Node Type|Status" \
        "30|15|15" \
        "No Redshift clusters found"
}

# Check DocumentDB clusters
check_documentdb() {
    check_simple_resource \
        "DocumentDB Clusters" \
        "docdb" \
        "describe-db-clusters" \
        "DBClusters[?VpcSecurityGroups[?VpcSecurityGroupId=='$SG_ID']].[DBClusterIdentifier,Engine,Status]" \
        "Cluster ID|Engine|Status" \
        "35|15|15" \
        "No DocumentDB clusters found"
}

# Check Neptune clusters
check_neptune() {
    check_simple_resource \
        "Neptune Clusters" \
        "neptune" \
        "describe-db-clusters" \
        "DBClusters[?VpcSecurityGroups[?VpcSecurityGroupId=='$SG_ID']].[DBClusterIdentifier,Engine,Status]" \
        "Cluster ID|Engine|Status" \
        "35|15|15" \
        "No Neptune clusters found"
}

# Check VPC Endpoints
check_vpc_endpoints() {
    check_simple_resource \
        "VPC Endpoints (Interface)" \
        "ec2" \
        "describe-vpc-endpoints" \
        "VpcEndpoints[?VpcEndpointType=='Interface' && Groups[?GroupId=='$SG_ID']].[VpcEndpointId,ServiceName,State]" \
        "Endpoint ID|Service Name|State" \
        "30|50|15" \
        "No VPC endpoints found"
}

# Check Launch Templates
check_launch_templates() {
    print_header "Launch Templates"
    
    local templates
    if ! templates=$(aws_query ec2 describe-launch-templates --query "LaunchTemplates[*].LaunchTemplateId" --output text); then
        echo -e "${YELLOW}  Unable to query launch templates${NC}"
        print_separator
        return
    fi
    
    if [[ -z "$templates" ]]; then
        echo -e "${YELLOW}  No launch templates found${NC}"
        print_separator
        return
    fi
    
    local temp_file="/tmp/sg_check_lt_$$"
    > "$temp_file"
    
    for template_id in $templates; do
        local data
        if ! data=$(aws_query ec2 describe-launch-template-versions \
            --launch-template-id "$template_id" --versions '$Latest' --output json); then
            continue
        fi
        
        if echo "$data" | jq -e ".LaunchTemplateVersions[0].LaunchTemplateData.SecurityGroupIds[]? | select(. == \"$SG_ID\")" &>/dev/null || \
           echo "$data" | jq -e ".LaunchTemplateVersions[0].LaunchTemplateData.NetworkInterfaces[]?.Groups[]? | select(. == \"$SG_ID\")" &>/dev/null; then
            
            local name=$(echo "$data" | jq -r '.LaunchTemplateVersions[0].LaunchTemplateName')
            local version=$(echo "$data" | jq -r '.LaunchTemplateVersions[0].VersionNumber')
            
            echo "$template_id|$name|$version" >> "$temp_file"
        fi
    done
    
    if [[ ! -s "$temp_file" ]]; then
        echo -e "${YELLOW}  No launch templates using this SG${NC}"
        print_separator
        return
    fi
    
    RESOURCE_FOUND=true
    printf "%-25s | %-40s | %s\n" "Template ID" "Name" "Latest Version"
    print_separator 100
    
    while IFS='|' read -r template_id name version; do
        printf "%-25s | %-40s | %s\n" "$template_id" "$name" "$version"
    done < "$temp_file"
    
    print_separator 100
}

# Check Auto Scaling Groups
check_autoscaling_groups() {
    print_header "Auto Scaling Groups"
    
    local asgs
    if ! asgs=$(aws_query autoscaling describe-auto-scaling-groups --output json); then
        echo -e "${YELLOW}  Unable to query Auto Scaling Groups${NC}"
        print_separator
        return
    fi
    
    local temp_file="/tmp/sg_check_asg_$$"
    > "$temp_file"
    
    # Check ASGs via their running instances' security groups
    echo "$asgs" | jq -r --arg sg_id "$SG_ID" '
    .AutoScalingGroups[] | 
    select(.Instances[].SecurityGroups[]? == $sg_id) | 
    [.AutoScalingGroupName, (.DesiredCapacity // 0), (.MinSize // 0), (.MaxSize // 0)] | @tsv' > "$temp_file"
    
    if [[ ! -s "$temp_file" ]]; then
        echo -e "${YELLOW}  No Auto Scaling Groups found${NC}"
        print_separator
        return
    fi
    
    RESOURCE_FOUND=true
    printf "%-50s | %-10s | %-10s | %s\n" "ASG Name" "Desired" "Min" "Max"
    print_separator 100
    
    while IFS=$'\t' read -r name desired min max; do
        printf "%-50s | %-10s | %-10s | %s\n" "$name" "$desired" "$min" "$max"
    done < "$temp_file"
    
    print_separator 100
}

# Check EFS Mount Targets
check_efs() {
    print_header "EFS Mount Targets"
    
    local filesystems
    if ! filesystems=$(aws_query efs describe-file-systems --query "FileSystems[*].FileSystemId" --output text); then
        echo -e "${YELLOW}  Unable to query EFS filesystems${NC}"
        print_separator
        return
    fi
    
    if [[ -z "$filesystems" ]]; then
        echo -e "${YELLOW}  No EFS filesystems found${NC}"
        print_separator
        return
    fi
    
    local temp_file="/tmp/sg_check_efs_$$"
    > "$temp_file"
    
    for fs_id in $filesystems; do
        local targets
        if ! targets=$(aws_query efs describe-mount-targets --file-system-id "$fs_id" --output json); then
            continue
        fi
        
        echo "$targets" | jq -c '.MountTargets[]?' 2>/dev/null | while read -r mt; do
            local mt_id=$(echo "$mt" | jq -r '.MountTargetId')
            local sgs
            if ! sgs=$(aws_query efs describe-mount-target-security-groups --mount-target-id "$mt_id" \
                --query "SecurityGroups[]" --output text 2>/dev/null); then
                continue
            fi
            
            if echo "$sgs" | grep -q "$SG_ID"; then
                local subnet=$(echo "$mt" | jq -r '.SubnetId')
                local ip=$(echo "$mt" | jq -r '.IpAddress')
                
                echo "$fs_id|$mt_id|$subnet|$ip" >> "$temp_file"
            fi
        done
    done
    
    if [[ ! -s "$temp_file" ]]; then
        echo -e "${YELLOW}  No EFS mount targets using this SG${NC}"
        print_separator
        return
    fi
    
    RESOURCE_FOUND=true
    printf "%-25s | %-30s | %-20s | %s\n" "FileSystem ID" "Mount Target ID" "Subnet ID" "IP Address"
    print_separator 120
    
    while IFS='|' read -r fs_id mt_id subnet ip; do
        printf "%-25s | %-30s | %-20s | %s\n" "$fs_id" "$mt_id" "$subnet" "$ip"
    done < "$temp_file"
    
    print_separator 120
}

# Check AWS Batch
check_batch() {
    check_simple_resource \
        "AWS Batch Compute Environments" \
        "batch" \
        "describe-compute-environments" \
        "computeEnvironments[?computeResources.securityGroupIds && contains(computeResources.securityGroupIds, '$SG_ID')].[computeEnvironmentName,type,state]" \
        "Environment Name|Type|State" \
        "40|20|15" \
        "No Batch environments found"
}

# Check WorkSpaces
check_workspaces() {
    print_header "WorkSpaces"
    
    local workspaces
    if ! workspaces=$(aws_query workspaces describe-workspaces --output json); then
        echo -e "${YELLOW}  Unable to query WorkSpaces${NC}"
        print_separator
        return
    fi
    
    # Note: WorkSpaces SG detection is limited - they use Directory Service SGs
    echo -e "${YELLOW}  Note: WorkSpaces use Directory Service security groups${NC}"
    print_separator
}

# Check Directory Services
check_directory_service() {
    print_header "AWS Directory Service"
    
    local directories
    if ! directories=$(aws_query ds describe-directories --output json); then
        echo -e "${YELLOW}  Unable to query Directory Service${NC}"
        print_separator
        return
    fi
    
    local filtered=$(echo "$directories" | jq -r --arg sg_id "$SG_ID" '
    .DirectoryDescriptions[] | 
    select(.VpcSettings.SecurityGroupId == $sg_id) | 
    [.DirectoryId, .Name, .Type, .Stage] | @tsv')
    
    if [[ -z "$filtered" ]]; then
        echo -e "${YELLOW}  No directories found${NC}"
        print_separator
        return
    fi
    
    RESOURCE_FOUND=true
    printf "%-25s | %-40s | %-20s | %s\n" "Directory ID" "Name" "Type" "Stage"
    print_separator 120
    
    echo "$filtered" | while IFS=$'\t' read -r dir_id name type stage; do
        printf "%-25s | %-40s | %-20s | %s\n" "$dir_id" "$name" "$type" "$stage"
    done
    
    print_separator 120
}

# Check SageMaker
check_sagemaker() {
    print_header "SageMaker Resources"
    
    # Check notebook instances
    local notebooks
    if notebooks=$(aws_query sagemaker list-notebook-instances --output json 2>/dev/null); then
        local count=0
        for nb in $(echo "$notebooks" | jq -r '.NotebookInstances[]?.NotebookInstanceName'); do
            local details
            if details=$(aws_query sagemaker describe-notebook-instance --notebook-instance-name "$nb" --output json 2>/dev/null); then
                if echo "$details" | jq -e --arg sg_id "$SG_ID" '.SecurityGroups[]? | select(. == $sg_id)' &>/dev/null; then
                    if [[ $count -eq 0 ]]; then
                        RESOURCE_FOUND=true
                        echo -e "${GREEN}  SageMaker Notebook Instances:${NC}"
                    fi
                    echo "    - $nb"
                    ((count++))
                fi
            fi
        done
        
        if [[ $count -eq 0 ]]; then
            echo -e "${YELLOW}  No SageMaker notebook instances found${NC}"
        fi
    else
        echo -e "${YELLOW}  Unable to query SageMaker${NC}"
    fi
    
    print_separator
}

# Check DAX Clusters
check_dax() {
    print_header "DynamoDB Accelerator (DAX) Clusters"
    
    local clusters
    if ! clusters=$(aws_query dax describe-clusters --output json 2>/dev/null); then
        echo -e "${YELLOW}  Unable to query DAX (may not be available in this region)${NC}"
        print_separator
        return
    fi
    
    local filtered=$(echo "$clusters" | jq -r --arg sg_id "$SG_ID" '
    .Clusters[]? | 
    select(.SecurityGroups[]?.SecurityGroupIdentifier == $sg_id) | 
    [.ClusterName, .Status, .NodeType] | @tsv')
    
    if [[ -z "$filtered" ]]; then
        echo -e "${YELLOW}  No DAX clusters found${NC}"
        print_separator
        return
    fi
    
    RESOURCE_FOUND=true
    printf "%-40s | %-15s | %s\n" "Cluster Name" "Status" "Node Type"
    print_separator 80
    
    echo "$filtered" | while IFS=$'\t' read -r name status node_type; do
        printf "%-40s | %-15s | %s\n" "$name" "$status" "$node_type"
    done
    
    print_separator 80
}

# Check MSK (Managed Streaming for Kafka)
check_msk() {
    print_header "MSK (Kafka) Clusters"
    
    local clusters
    if ! clusters=$(aws_query kafka list-clusters --output json 2>/dev/null); then
        echo -e "${YELLOW}  Unable to query MSK${NC}"
        print_separator
        return
    fi
    
    local temp_file="/tmp/sg_check_msk_$$"
    > "$temp_file"
    
    echo "$clusters" | jq -r '.ClusterInfoList[]?.ClusterArn' | while read -r cluster_arn; do
        local details
        if ! details=$(aws_query kafka describe-cluster --cluster-arn "$cluster_arn" --output json 2>/dev/null); then
            continue
        fi
        
        if echo "$details" | jq -e --arg sg_id "$SG_ID" '.ClusterInfo.BrokerNodeGroupInfo.SecurityGroups[]? | select(. == $sg_id)' &>/dev/null; then
            local name=$(echo "$details" | jq -r '.ClusterInfo.ClusterName')
            local state=$(echo "$details" | jq -r '.ClusterInfo.State')
            echo "$name|$state|$cluster_arn" >> "$temp_file"
        fi
    done
    
    if [[ ! -s "$temp_file" ]]; then
        echo -e "${YELLOW}  No MSK clusters found${NC}"
        print_separator
        return
    fi
    
    RESOURCE_FOUND=true
    printf "%-40s | %-15s\n" "Cluster Name" "State"
    print_separator 80
    
    while IFS='|' read -r name state arn; do
        printf "%-40s | %-15s\n" "$name" "$state"
    done < "$temp_file"
    
    print_separator 80
}

# Main execution
main() {
    parse_arguments "$@"
    
    # Check dependencies
    for cmd in aws jq; do
        if ! command -v "$cmd" &>/dev/null; then
            echo -e "${RED}Error: Required command '$cmd' not found${NC}"
            echo -e "${YELLOW}Please install $cmd and try again${NC}"
            exit 1
        fi
    done
    
    echo -e "${YELLOW}${BOLD}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}${BOLD}     AWS Security Group Enumeration Tool${NC}"
    echo -e "${YELLOW}${BOLD}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}Profile: ${BOLD}$AWS_PROFILE${NC} | ${CYAN}Region: ${BOLD}$REGION${NC}"
    print_separator
    echo
    
    # Verify AWS credentials
    if ! aws_query sts get-caller-identity &>/dev/null; then
        echo -e "${RED}Error: Unable to authenticate with AWS${NC}"
        echo -e "${YELLOW}Please check your AWS credentials for profile '$AWS_PROFILE'${NC}"
        exit 1
    fi
    
    local sg_json=$(get_sg_info)
    
    display_sg_info "$sg_json"
    echo
    
    display_inbound_rules "$sg_json"
    echo
    
    display_outbound_rules "$sg_json"
    echo
    
    echo -e "${YELLOW}${BOLD}Scanning for resources using this Security Group...${NC}"
    echo
    
    # Core compute services
    check_ec2_instances
    echo
    
    check_enis
    echo
    
    check_autoscaling_groups
    echo
    
    check_launch_templates
    echo
    
    # Container services
    check_ecs_tasks
    echo
    
    check_eks_nodes
    echo
    
    # Load balancers
    check_load_balancers
    echo
    
    check_classic_load_balancers
    echo
    
    # Databases
    check_rds_instances
    echo
    
    check_rds_clusters
    echo
    
    check_elasticache
    echo
    
    check_redshift
    echo
    
    check_documentdb
    echo
    
    check_neptune
    echo
    
    check_dax
    echo
    
    # Serverless and functions
    check_lambda_functions
    echo
    
    check_batch
    echo
    
    # Storage and file systems
    check_efs
    echo
    
    # Networking
    check_vpc_endpoints
    echo
    
    check_referencing_sgs
    echo
    
    # Streaming and messaging
    check_msk
    echo
    
    # Machine learning
    check_sagemaker
    echo
    
    # Directory and workspace services
    check_directory_service
    echo
    
    check_workspaces
    echo
    
    # Final summary
    print_separator
    echo
    
    # Get management type for final summary
    local management_type=$(is_aws_managed "$sg_json")
    
    if [[ "$RESOURCE_FOUND" == false ]]; then
        echo -e "${RED}⚠️  WARNING: This Security Group is NOT being used by any detectable resources!${NC}"
        echo
        
        # Provide specific guidance based on management type
        case "$management_type" in
            "AWS-MANAGED")
                echo -e "${YELLOW}   ${BOLD}Management Type:${NC}${YELLOW} This is an ${BOLD}AWS-MANAGED${NC}${YELLOW} security group.${NC}"
                echo -e "${YELLOW}   AWS-managed security groups are created and maintained by AWS services.${NC}"
                echo -e "${RED}   ${BOLD}DO NOT DELETE${NC}${RED} - This SG is likely used by AWS internal services.${NC}"
                ;;
            "GUARDDUTY")
                echo -e "${YELLOW}   ${BOLD}Management Type:${NC}${YELLOW} This is a ${BOLD}GuardDuty-MANAGED${NC}${YELLOW} security group.${NC}"
                echo -e "${YELLOW}   GuardDuty-managed security groups are used by Amazon GuardDuty.${NC}"
                echo -e "${RED}   ${BOLD}DO NOT DELETE${NC}${RED} - This SG is managed by GuardDuty service.${NC}"
                ;;
            "AWS-SERVICE")
                echo -e "${YELLOW}   ${BOLD}Management Type:${NC}${YELLOW} This is an ${BOLD}AWS SERVICE-MANAGED${NC}${YELLOW} security group.${NC}"
                echo -e "${YELLOW}   This SG is likely managed by an AWS service (ECS, EKS, RDS, etc.).${NC}"
                echo -e "${RED}   ${BOLD}CAUTION:${NC}${RED} Verify the owning service before deletion.${NC}"
                ;;
            "USER-MANAGED")
                echo -e "${YELLOW}   ${BOLD}Management Type:${NC}${YELLOW} This is a ${BOLD}USER-MANAGED${NC}${YELLOW} security group.${NC}"
                echo -e "${YELLOW}   This SG was created by a user or automated deployment.${NC}"
                echo -e "${YELLOW}   This SG may be safe to delete if it's truly unused.${NC}"
                echo -e "${YELLOW}   ${BOLD}Recommendation:${NC}${YELLOW} Verify carefully before deletion!${NC}"
                ;;
        esac
        
        echo
        echo -e "${YELLOW}   Note: Some AWS services may use security groups in ways not visible${NC}"
        echo -e "${YELLOW}   through standard API calls. Always verify before deletion.${NC}"
    else
        echo -e "${GREEN}✅ Security Group audit complete - Active resources found.${NC}"
        echo -e "${GREEN}   This Security Group is ${BOLD}IN USE${NC}${GREEN} and should NOT be deleted.${NC}"
        
        # Still show management type for informational purposes
        case "$management_type" in
            "AWS-MANAGED"|"GUARDDUTY"|"AWS-SERVICE")
                echo -e "${GREEN}   Management: ${BOLD}AWS/Service-Managed${NC}"
                ;;
            "USER-MANAGED")
                echo -e "${GREEN}   Management: ${BOLD}User-Managed${NC}"
                ;;
        esac
    fi
    echo
    print_separator
}

main "$@"
