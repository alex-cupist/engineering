#!/bin/bash
REGION="ap-northeast-2"

echo "=========================================================="
echo " 🔍 Step 1) Redshift Cluster 목록 조회"
echo "=========================================================="

CLUSTERS=$(aws redshift describe-clusters \
    --region $REGION \
    --query "Clusters[].ClusterIdentifier" \
    --output text)

if [[ -z "$CLUSTERS" ]]; then
  echo "⚠️ Redshift 클러스터 없음 (점검 종료)"
  exit 0
fi

for CL in $CLUSTERS; do
  echo
  echo "=========================================================="
  echo " 🎯 Cluster 분석: $CL"
  echo "=========================================================="

  INFO=$(aws redshift describe-clusters \
      --region $REGION \
      --cluster-identifier $CL \
      --output json)

  PORT=$(echo "$INFO" | jq -r '.Clusters[0].Endpoint.Port')
  SG_LIST=$(echo "$INFO" | jq -r '.Clusters[0].VpcSecurityGroups[].VpcSecurityGroupId')

  echo "📌 Cluster Port: $PORT"
  echo "📌 연결된 Security Groups:"
  echo "$SG_LIST" | sed 's/^/   - /'

  echo
  echo "=========================================================="
  echo " 🔍 Step 2) SG Inbound Rule 중 0.0.0.0/0 분석"
  echo "=========================================================="

  printf "| %-15s | %-18s | %-6s | %-15s | %-6s |\n" "Cluster" "SG ID" "Port" "CIDR" "Risk"
  printf "|-----------------|--------------------|--------|-----------------|--------|\n"

  for SG in $SG_LIST; do

    RULES=$(aws ec2 describe-security-groups \
        --region $REGION \
        --group-ids $SG \
        --query "SecurityGroups[].IpPermissions[]" \
        --output json)

    echo "$RULES" | jq -c '.[]' | while read -r rule; do
      FROM_PORT=$(echo $rule | jq -r '.FromPort // "ALL"')
      CIDR_LIST=$(echo $rule | jq -r '.IpRanges[].CidrIp // empty')

      for CIDR in $CIDR_LIST; do
        
        RISK="LOW"
        if [[ "$CIDR" == "0.0.0.0/0" ]]; then
          RISK="HIGH"
        fi

        printf "| %-15s | %-18s | %-6s | %-15s | %-6s |\n" \
            "$CL" "$SG" "$FROM_PORT" "$CIDR" "$RISK"
      done
    done
  done
done

echo "=========================================================="
echo " 🎉 Redshift 보안 점검 완료"
echo "=========================================================="
