#!/bin/bash
set -e

REGION="ap-northeast-2"

echo "=========================================================="
echo " 🔍 Step 1) ElastiCache 클러스터 SG 조회"
echo "=========================================================="

CLUSTERS=$(aws elasticache describe-cache-clusters \
    --region $REGION \
    --show-cache-node-info \
    --query "CacheClusters[].{ID:CacheClusterId, SG:SecurityGroups[].SecurityGroupId}" \
    --output json)

SG_LIST=$(echo "$CLUSTERS" | jq -r '.[].SG[]' | sort -u)

echo
printf "📌 점검 대상 SG (%d개)\n" $(echo "$SG_LIST" | wc -l)
echo "$SG_LIST" | sed 's/^/   - /'
echo
echo "=========================================================="
echo " 🔍 Step 2) SG Inbound Rule 중 0.0.0.0/0 검사"
echo "=========================================================="

# 표 헤더
printf "| %-20s | %-18s | %-6s | %-15s | %-6s |\n" "Cluster" "SG ID" "Port" "CIDR" "Risk"
printf "|----------------------|--------------------|--------|-----------------|--------|\n"

for SG in $SG_LIST; do

  # SG 사용 클러스터 (여러 개여도 1개만 표시)
  CLUSTER_NAME=$(echo "$CLUSTERS" \
        | jq -r ".[] | select(.SG[]? == \"$SG\") | .ID" \
        | head -n 1)

  # 너무 길면 뒤에 ...
  CLUSTER_SHORT=$(echo "$CLUSTER_NAME" | cut -c1-20)

  RULES=$(aws ec2 describe-security-groups \
      --region $REGION \
      --group-ids $SG \
      --query "SecurityGroups[].IpPermissions[]" \
      --output json)

  echo "$RULES" | jq -c '.[]' | while read -r rule; do
    PORT_FROM=$(echo $rule | jq -r '.FromPort // "ALL"')
    CIDR_LIST=$(echo $rule | jq -r '.IpRanges[].CidrIp // empty')

    for CIDR in $CIDR_LIST; do

      # 길이 제한
      CIDR_SHORT=$(echo "$CIDR" | cut -c1-15)

      # 위험도 판정
      RISK="LOW"
      if [[ "$CIDR" == "0.0.0.0/0" ]]; then
        if [[ "$PORT_FROM" == "6379" ]]; then
          RISK="CRITICAL"
        else
          RISK="HIGH"
        fi
      fi

      printf "| %-20s | %-18s | %-6s | %-15s | %-6s |\n" \
        "$CLUSTER_SHORT" "$SG" "$PORT_FROM" "$CIDR_SHORT" "$RISK"

    done
  done
done

echo "=========================================================="
echo " 🎉 분석 완료"
echo "=========================================================="
