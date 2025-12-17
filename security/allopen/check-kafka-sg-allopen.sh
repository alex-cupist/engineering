#!/bin/bash
# AWS_PROFILE → 기본 REGION 자동 지정
CURRENT_PROFILE="${AWS_PROFILE:-default}"

if [ "$CURRENT_PROFILE" = "dotdotdot" ]; then
  REGION="us-west-2"   # 오레곤
else
  REGION="ap-northeast-2"  # 서울
fi

# CLI 인자 우선 적용
REGION="${1:-$REGION}"

echo "🔧 AWS_PROFILE=$CURRENT_PROFILE → REGION=$REGION"

echo "=========================================================="
echo " 🔍 Step 1) MSK Cluster 목록 조회"
echo "=========================================================="

CLUSTERS=$(aws kafka list-clusters \
    --region $REGION \
    --query "ClusterInfoList[].ClusterName" \
    --output text)

if [[ -z "$CLUSTERS" ]]; then
  echo "⚠️ MSK 클러스터 없음 (점검 종료)"
  exit 0
fi

for CL in $CLUSTERS; do
  echo
  echo "=========================================================="
  echo " 🎯 MSK Cluster 분석: $CL"
  echo "=========================================================="

  INFO=$(aws kafka list-clusters --region $REGION --output json)
  ARN=$(echo "$INFO" | jq -r ".ClusterInfoList[] | select(.ClusterName==\"$CL\") | .ClusterArn")

  DETAILS=$(aws kafka describe-cluster \
      --region $REGION \
      --cluster-arn "$ARN" \
      --output json)

  SG_LIST=$(echo "$DETAILS" | jq -r '.ClusterInfo.BrokerNodeGroupInfo.SecurityGroups[]')
  PORT=$(echo "$DETAILS" | jq -r '.ClusterInfo.BrokerNodeGroupInfo.BrokerPort')

  echo "📌 Broker Port: $PORT"
  echo "📌 연결된 Security Groups:"
  echo "$SG_LIST" | sed 's/^/   - /'

  echo
  echo "=========================================================="
  echo " 🔍 Step 2) SG Inbound Rule 중 0.0.0.0/0 분석"
  echo "=========================================================="

  printf "| %-20s | %-18s | %-6s | %-15s | %-6s |\n" "Cluster" "SG ID" "Port" "CIDR" "Risk"
  printf "|----------------------|--------------------|--------|-----------------|--------|\n"

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

        printf "| %-20s | %-18s | %-6s | %-15s | %-6s |\n" \
            "$CL" "$SG" "$FROM_PORT" "$CIDR" "$RISK"
      done
    done
  done
done

echo "=========================================================="
echo " 🎉 MSK 보안 점검 완료"
echo "=========================================================="
