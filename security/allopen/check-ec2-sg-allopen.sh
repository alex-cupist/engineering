#!/usr/bin/env bash
set -euo pipefail

############################################
# AWS_PROFILE → 기본 REGION 자동 지정
############################################
CURRENT_PROFILE="${AWS_PROFILE:-default}"

if [ "$CURRENT_PROFILE" = "dotdotdot" ]; then
  REGION="us-west-2"   # 오레곤
else
  REGION="ap-northeast-2"  # 서울
fi

# CLI 인자 우선 적용
REGION="${1:-$REGION}"

echo "🔧 AWS_PROFILE=$CURRENT_PROFILE → REGION=$REGION"
echo
echo "=================================================================================="
echo "🔍 EC2 Security Group Exposure Check (World-Open SGs Attached to EC2 Instances Only)"
echo "=================================================================================="
echo
echo "This script reports only Security Groups that:"
echo "  1) Are attached to EC2 instances, and"
echo "  2) Allow inbound traffic from 0.0.0.0/0 (IPv4) or ::/0 (IPv6)."
echo
echo "Security Groups that are open to the world but NOT attached to any EC2 instance"
echo "WILL NOT appear in this output."
echo "=================================================================================="
echo

echo "🔧 AWS_PROFILE=$CURRENT_PROFILE → REGION=$REGION"
echo "🔎 Checking EC2 SecurityGroups with open access (IPv4/IPv6) in $REGION"
echo


############################################
# 함수: SG의 인바운드 규칙을 검사하여
#       열려있는 Port | CIDR | Risk 출력
############################################
extract_sg_rules() {
  local sg_id="$1"

  aws ec2 describe-security-groups \
    --region "$REGION" \
    --group-ids "$sg_id" \
    --output json |
  jq -r '
    .SecurityGroups[].IpPermissions[]? as $p
    | (
        if ($p.FromPort == null and $p.ToPort == null) then "ALL"
        elif ($p.FromPort == $p.ToPort) then ($p.FromPort|tostring)
        else ($p.FromPort|tostring) + "-" + ($p.ToPort|tostring)
      ) as $port
    | (
        (.IpRanges[]?.CidrIp // empty),
        (.Ipv6Ranges[]?.CidrIpv6 // empty)
      ) as $cidr
    | select($cidr=="0.0.0.0/0" or $cidr=="::/0")
    | $port + "|" + $cidr + "|" +
      ( if $cidr=="0.0.0.0/0" or $cidr=="::/0" then "HIGH" else "LOW" end )
  '
}

############################################
# 1) IPv4에서 0.0.0.0/0 열린 SG 조회
############################################
OPEN_SG_V4="$(
  aws ec2 describe-security-groups \
    --region "$REGION" \
    --filters Name=ip-permission.cidr,Values=0.0.0.0/0 \
    --query 'SecurityGroups[].{Id:GroupId,Name:GroupName}' \
    --output text \
    || true
)"

OPEN_SG_V4="$(printf '%s\n' "$OPEN_SG_V4" | sed '/^[[:space:]]*$/d' | sort -u)"

############################################
# 2) IPv6에서 ::/0 열린 SG 조회
############################################
OPEN_SG_V6="$(
  aws ec2 describe-security-groups \
    --region "$REGION" \
    --filters Name=ip-permission.ipv6-cidr,Values=::/0 \
    --query 'SecurityGroups[].{Id:GroupId,Name:GroupName}' \
    --output text \
    || true
)"

OPEN_SG_V6="$(printf '%s\n' "$OPEN_SG_V6" | sed '/^[[:space:]]*$/d' | sort -u)"

if [ -z "$OPEN_SG_V4$OPEN_SG_V6" ]; then
  echo "✅ 0.0.0.0/0 또는 ::/0이 열린 EC2 보안그룹이 없습니다."
  exit 0
fi

# SG 이름 조회용 통합 리스트
OPEN_SG_INFO="$(printf '%s\n%s\n' "$OPEN_SG_V4" "$OPEN_SG_V6" | sed '/^[[:space:]]*$/d' | sort -u)"

############################################
# 3) 모든 EC2 인스턴스 → SG 매핑 정보 가져오기
############################################
EC2_SG_MAP="$(
  aws ec2 describe-instances \
    --region "$REGION" \
    --query 'Reservations[].Instances[].{InstanceId:InstanceId,SG:SecurityGroups[].GroupId}' \
    --output text
)"

############################################
# 4) 열린 SG와 연결된 EC2 식별 + Port/CIDR/Risk 출력
############################################
ROWS=""

while read -r INSTANCE_ID SG_ID; do
  [ -z "${INSTANCE_ID:-}" ] && continue
  [ -z "${SG_ID:-}" ] && continue

  ############################
  # IPv4 열린 SG인지 체크
  ############################
  HAS_V4=1
  if awk -v id="$SG_ID" '$1==id {exit 0} END {exit 1}' <<< "$OPEN_SG_V4"; then
    HAS_V4=0
  fi

  ############################
  # IPv6 열린 SG인지 체크
  ############################
  HAS_V6=1
  if awk -v id="$SG_ID" '$1==id {exit 0} END {exit 1}' <<< "$OPEN_SG_V6"; then
    HAS_V6=0
  fi

  # 둘 다 아니라면 스킵
  if [ $HAS_V4 -ne 0 ] && [ $HAS_V6 -ne 0 ]; then
    continue
  fi

  ############################
  # OPEN_BY 문자열 생성
  ############################
  if [ $HAS_V4 -eq 0 ] && [ $HAS_V6 -eq 0 ]; then
    OPEN_BY="IPv4,IPv6"
  elif [ $HAS_V4 -eq 0 ]; then
    OPEN_BY="IPv4"
  else
    OPEN_BY="IPv6"
  fi

  ############################
  # SG 이름 조회
  ############################
  SG_NAME=$(awk -v id="$SG_ID" '$1==id {print $2; exit}' <<< "$OPEN_SG_INFO")

  ############################
  # SG 인바운드 규칙 분석 (Port / CIDR / Risk)
  ############################
  RULE_LINES=$(extract_sg_rules "$SG_ID")

  if [ -z "$RULE_LINES" ]; then
    continue
  fi

  while IFS='|' read -r PORT CIDR RISK; do
    ROWS="${ROWS}\n${INSTANCE_ID}\t${SG_ID}\t${SG_NAME}\t${OPEN_BY}\t${PORT}\t${CIDR}\t${RISK}"
  done <<< "$RULE_LINES"

done <<EOF
$EC2_SG_MAP
EOF

############################################
# 5) 출력
############################################
{
  echo -e "InstanceId\tSecurityGroupId\tSecurityGroupName\tOpenBy\tPort\tCIDR\tRisk"
  printf '%b\n' "$ROWS" | sed '/^[[:space:]]*$/d' | sort -u
} | column -t

echo
echo "🎉 EC2 SG Open Port 점검 완료"
