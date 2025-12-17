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
echo " 🔍 Step 1) OpenSearch Domain 목록 조회"
echo "=========================================================="

DOMAINS=$(aws opensearch list-domain-names \
    --region $REGION \
    --query "DomainNames[].DomainName" \
    --output text)

if [[ -z "$DOMAINS" ]]; then
  echo "⚠️ OpenSearch Domain 없음 (점검 종료)"
  exit 0
fi

for DOMAIN in $DOMAINS; do
  echo
  echo "=========================================================="
  echo " 🎯 Domain 분석: $DOMAIN"
  echo "=========================================================="

  INFO=$(aws opensearch describe-domain \
      --region $REGION \
      --domain-name $DOMAIN \
      --output json)

  ENDPOINT=$(echo "$INFO" | jq -r '.DomainStatus.Endpoint // "N/A"')
  PUBLIC_ACCESS=$(echo "$INFO" | jq -r '.DomainStatus.DomainEndpointOptions.EnforceHTTPS')

  VPC_ENABLED=$(echo "$INFO" | jq -r '.DomainStatus.VPCOptions.VPCId // empty')

  echo "📌 Endpoint: $ENDPOINT"
  echo "📌 HTTPS Enforced: $PUBLIC_ACCESS"

  if [[ -z "$VPC_ENABLED" ]]; then
    echo "⚠️ 도메인이 VPC에 속해 있지 않음 → 인터넷 공개 위험 HIGH"
    SG_LIST="N/A"
  else
    SG_LIST=$(echo "$INFO" | jq -r '.DomainStatus.VPCOptions.SecurityGroupIds[]?')
  fi

  echo
  echo "📌 연결된 Security Groups:"
  echo "$SG_LIST" | sed 's/^/   - /'

  echo
  echo "=========================================================="
  echo " 🔍 Step 2) SG Inbound Rule 중 0.0.0.0/0 분석"
  echo "=========================================================="

  # 표 Header
  printf "| %-20s | %-18s | %-6s | %-15s | %-6s |\n" "Domain" "SG ID" "Port" "CIDR" "Risk"
  printf "|----------------------|--------------------|--------|-----------------|--------|\n"

  for SG in $SG_LIST; do

    RULES=$(aws ec2 describe-security-groups \
        --region $REGION \
        --group-ids $SG \
        --query "SecurityGroups[].IpPermissions[]" \
        --output json)

    echo "$RULES" | jq -c '.[]' | while read -r rule; do
      PORT_FROM=$(echo $rule | jq -r '.FromPort // "ALL"')
      CIDR_LIST=$(echo $rule | jq -r '.IpRanges[].CidrIp // empty')

      for CIDR in $CIDR_LIST; do

        RISK="LOW"
        if [[ "$CIDR" == "0.0.0.0/0" ]]; then
          RISK="HIGH"
        fi

        printf "| %-20s | %-18s | %-6s | %-15s | %-6s |\n" \
          "$DOMAIN" "$SG" "$PORT_FROM" "$CIDR" "$RISK"
      done
    done
  done
done

echo "=========================================================="
echo " 🎉 OpenSearch 보안 점검 완료"
echo "=========================================================="
