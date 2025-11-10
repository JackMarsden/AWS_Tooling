# -----------------------------
# ENIs + Attached Resource Mapping (Enhanced)
# -----------------------------
echo -e "${YELLOW}ENIs using this SG and their resources:${NC}"
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
            # Get Lambda function using this ENI
            LAMBDAS=$(aws lambda list-functions --profile "$AWS_PROFILE" \
                --query "Functions[?VpcConfig.SecurityGroupIds && contains(VpcConfig.SecurityGroupIds,'$SG_ID')].[FunctionArn]" --output text)
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
                --query "DBInstances[?VpcSecurityGroups[?VpcSecurityGroupId=='$SG_ID']].[DBInstanceIdentifier]" --output text)
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
