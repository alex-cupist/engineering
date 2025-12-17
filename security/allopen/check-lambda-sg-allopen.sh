#!/bin/bash

# 사용법: ./check-lambda-sg-allopen.sh ap-northeast-2
REGION="${1:-ap-northeast-2}"

echo "=========================================================="
echo " 🔍 Lambda (VPC Attached) → SG all open 점검"
echo "    REGION = $REGION"
echo "=========================================================="

# 1) VPC에 붙어있는 Lambda 함수 목록 조회
LAMBDAS=$(aws lambda list-functions \
  --region "$REGION" \
  --query "Functions[?VpcConfig.VpcId!=null].FunctionName" \
  --output text)

if [ -z "$LAMBDAS" ]; then
  echo "⚪ VPC Attached Lambda 함수가 없습니다."
  exit 0
fi

echo ""
echo "📌 VPC Attached Lambda 함수 목록:"
for fn in $LAMBDAS; do
  echo "   - $fn"
done

# 결과 테이블 헤더 (Markdown 스타일)
TABLE="| Lambda Function | SG ID | SG Name | Inbound (0.0.0.0/0 or ALL) | Risk | Action |\n"
TABLE+="|----------------|------|--------|-------------------------------|------|--------|\n"

echo ""
echo "=========================================================="
echo " 🔍 Step 2) Lambda → Security Group 매핑 + all open 검사"
echo "=========================================================="

for fn in $LAMBDAS; do
  # Lambda에 설정된 SG ID들 조회
  SG_IDS=$(aws lambda get-function-configuration \
    --region "$REGION" \
    --function-name "$fn" \
    --query "VpcConfig.SecurityGroupIds" \
    --output text)

  if [ -z "$SG_IDS" ]; then
    echo "ℹ️  Lambda: $fn → 연결된 SG 없음 (Skip)"
    continue
  fi

  echo ""
  echo "🎯 Lambda: $fn"
  echo "   ▸ Attached SGs: $SG_IDS"

  for SG in $SG_IDS; do
    # SG 이름 조회
    SG_NAME=$(aws ec2 describe-security-groups \
      --region "$REGION" \
      --group-ids "$SG" \
      --query "SecurityGroups[0].GroupName" \
      --output text 2>/dev/null)

    echo ""
    echo "   🔎 SG 분석 → $SG ($SG_NAME)"

    # Inbound CIDR 목록 조회 (IPv4)
    IN_CIDRS_V4=$(aws ec2 describe-security-groups \
      --region "$REGION" \
      --group-ids "$SG" \
      --query "SecurityGroups[0].IpPermissions[].IpRanges[].CidrIp" \
      --output text 2>/dev/null)

    # Inbound CIDR 목록 조회 (IPv6)
    IN_CIDRS_V6=$(aws ec2 describe-security-groups \
      --region "$REGION" \
      --group-ids "$SG" \
      --query "SecurityGroups[0].IpPermissions[].Ipv6Ranges[].CidrIpv6" \
      --output text 2>/dev/null)

    # 프로토콜/포트 정보도 같이 출력 (사람 눈으로 검토용)
    aws ec2 describe-security-groups \
      --region "$REGION" \
      --group-ids "$SG" \
      --query "SecurityGroups[0].IpPermissions[].{Protocol:IpProtocol,FromPort:FromPort,ToPort:ToPort,Cidrs:IpRanges[].CidrIp,Ipv6Cidrs:Ipv6Ranges[].CidrIpv6}" \
      --output table

    OPEN_FLAG="NO"
    RISK="LOW"
    ACTION="OK"
    INBOUND_SUMMARY="None"

    # ALL traffic(-1) + 0.0.0.0/0 조합을 강한 위험으로 간주
    ALL_TRAFFIC=$(aws ec2 describe-security-groups \
      --region "$REGION" \
      --group-ids "$SG" \
      --query "SecurityGroups[0].IpPermissions[?IpProtocol=='-1'].IpProtocol" \
      --output text 2>/dev/null)

    HAS_V4_ALL=$(echo "$IN_CIDRS_V4" | tr '\t' '\n' | grep -E "0.0.0.0/0" || true)
    HAS_V6_ALL=$(echo "$IN_CIDRS_V6" | tr '\t' '\n' | grep -E "::/0" || true)

    if [ -n "$ALL_TRAFFIC" ] || [ -n "$HAS_V4_ALL" ] || [ -n "$HAS_V6_ALL" ]; then
      OPEN_FLAG="YES"
      RISK="HIGH"
      ACTION="FIX"

      INBOUND_SUMMARY=""
      if [ -n "$ALL_TRAFFIC" ]; then
        INBOUND_SUMMARY+="ALL traffic "
      fi
      if [ -n "$HAS_V4_ALL" ]; then
        INBOUND_SUMMARY+="0.0.0.0/0 "
      fi
      if [ -n "$HAS_V6_ALL" ]; then
        INBOUND_SUMMARY+="::/0 "
      fi

      echo "   🚨 위험: Lambda ENI SG에 broad Inbound 허용됨 → ($INBOUND_SUMMARY)"
    else
      echo "   ✅ Inbound all open 없음"
    fi

    # 테이블에 한 줄 추가
    TABLE+="| $fn | $SG | $SG_NAME | $INBOUND_SUMMARY | $RISK | $ACTION |\n"

  done
done

echo ""
echo "=========================================================="
echo " 🎉 Lambda SG all open 분석 완료 — 요약 표"
echo "=========================================================="
echo -e "$TABLE"
