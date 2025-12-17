#!/usr/bin/env bash
set -euo pipefail

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

echo "🔎 Checking open (IPv4 / IPv6) ECS Service SecurityGroups in region: $REGION" >&2

########################################
# 1) IPv4 0.0.0.0/0 열린 SG 조회
########################################
OPEN_SG_V4="$(
  aws ec2 describe-security-groups \
    --region "$REGION" \
    --filters Name=ip-permission.cidr,Values=0.0.0.0/0 \
    --query 'SecurityGroups[].{Id:GroupId,Name:GroupName}' \
    --output text 2>/dev/null || true
)"
OPEN_SG_V4="$(printf '%s\n' "$OPEN_SG_V4" | sed '/^[[:space:]]*$/d' | sort -u)"

########################################
# 2) IPv6 ::/0 열린 SG 조회
########################################
OPEN_SG_V6="$(
  aws ec2 describe-security-groups \
    --region "$REGION" \
    --filters Name=ip-permission.ipv6-cidr,Values=::/0 \
    --query 'SecurityGroups[].{Id:GroupId,Name:GroupName}' \
    --output text 2>/dev/null || true
)"
OPEN_SG_V6="$(printf '%s\n' "$OPEN_SG_V6" | sed '/^[[:space:]]*$/d' | sort -u)"

# 아무 것도 없으면 종료
if [ -z "$OPEN_SG_V4$OPEN_SG_V6" ]; then
  echo "✅ No ECS Security Groups are publicly exposed (0.0.0.0/0 or ::/0)"
  exit 0
fi

OPEN_SG_INFO="$(printf '%s\n%s\n' "$OPEN_SG_V4" "$OPEN_SG_V6" | sed '/^[[:space:]]*$/d' | sort -u)"

########################################
# Helper: SG 상세 규칙 분석 (Port, CIDR, Summary, Risk)
########################################
describe_sg_rules() {
  local sg_id="$1"

  aws ec2 describe-security-groups \
    --region "$REGION" \
    --group-ids "$sg_id" \
    --output json | jq -r '
      .SecurityGroups[].IpPermissions[]? as $p
      | ($p.IpRanges // [])[]? as $r
      | $r.CidrIp as $cidr
      | select($cidr == "0.0.0.0/0")
      | (
          if ($p.FromPort == null and $p.ToPort == null) then "ALL"
          elif ($p.FromPort == $p.ToPort) then ($p.FromPort|tostring)
          else ($p.FromPort|tostring + "-" + ($p.ToPort|tostring))
        end
        ) as $port
      | "\($port)|\($cidr)|Inbound allowed from 0.0.0.0/0|HIGH"
    '
}

########################################
# 3) 모든 ECS 서비스의 SG 매핑 (Chunk 10개)
########################################
CLUSTERS="$(aws ecs list-clusters --region "$REGION" --query 'clusterArns[]' --output text)"

if [ -z "$CLUSTERS" ]; then
  echo "ℹ️ No ECS clusters found."
  exit 0
fi

SVC_SG_MAP=""

for CL in $CLUSTERS; do
  SERVICES="$(aws ecs list-services \
      --cluster "$CL" \
      --region "$REGION" \
      --query 'serviceArns[]' \
      --output text)"

  [ -z "$SERVICES" ] && continue

  CHUNK=()
  COUNT=0

  for SVC in $SERVICES; do
    CHUNK+=("$SVC")
    COUNT=$((COUNT + 1))

    if [ $COUNT -ge 10 ]; then
      PART=$(aws ecs describe-services \
          --cluster "$CL" \
          --region "$REGION" \
          --services "${CHUNK[@]}" \
          --query 'services[].{Cluster:clusterArn,Name:serviceName,SG:networkConfiguration.awsvpcConfiguration.securityGroups}' \
          --output text)

      SVC_SG_MAP="$SVC_SG_MAP"$'\n'"$PART"
      CHUNK=()
      COUNT=0
    fi
  done

  if [ ${#CHUNK[@]} -gt 0 ]; then
    PART=$(aws ecs describe-services \
        --cluster "$CL" \
        --region "$REGION" \
        --services "${CHUNK[@]}" \
        --query 'services[].{Cluster:clusterArn,Name:serviceName,SG:networkConfiguration.awsvpcConfiguration.securityGroups}' \
        --output text)

    SVC_SG_MAP="$SVC_SG_MAP"$'\n'"$PART"
  fi
done

SVC_SG_MAP="$(printf '%s\n' "$SVC_SG_MAP" | sed '/^[[:space:]]*$/d')"

########################################
# 4) 열린 SG만 필터링 + Port, CIDR, Summary, Risk 포함
########################################

RESULT_ROWS=""

while read -r CL_ARN SVC_NAME SG; do
  [ -z "$SG" ] && continue
  [ "$SG" = "None" ] && continue

  SG_ID="$SG"

  HAS_V4=1
  if awk -v id="$SG_ID" '$1==id{print "yes"}' <<< "$OPEN_SG_V4" | grep -q yes; then
    HAS_V4=0
  fi

  HAS_V6=1
  if awk -v id="$SG_ID" '$1==id{print "yes"}' <<< "$OPEN_SG_V6" | grep -q yes; then
    HAS_V6=0
  fi

  [ $HAS_V4 -ne 0 ] && [ $HAS_V6 -ne 0 ] && continue

  if [ $HAS_V4 -eq 0 ] && [ $HAS_V6 -eq 0 ]; then
    OPEN_BY="IPv4,IPv6"
  elif [ $HAS_V4 -eq 0 ]; then
    OPEN_BY="IPv4"
  else
    OPEN_BY="IPv6"
  fi

  SG_NAME=$(awk -v id="$SG_ID" '$1==id{print $2; exit}' <<< "$OPEN_SG_INFO")

  SG_RULES=$(describe_sg_rules "$SG_ID")
  CL_NAME=$(echo "$CL_ARN" | awk -F'/' '{print $NF}')

  while IFS='|' read -r PORT CIDR SUMMARY RISK; do
    RESULT_ROWS="${RESULT_ROWS}\n${CL_NAME}\t${SVC_NAME}\t${SG_ID}\t${SG_NAME}\t${OPEN_BY}\t${PORT}\t${CIDR}\t${SUMMARY}\t${RISK}"
  done <<< "$SG_RULES"

done <<< "$SVC_SG_MAP"

########################################
# 5) 출력
########################################
{
  echo -e "Cluster\tServiceName\tSecurityGroupId\tSecurityGroupName\tOpenBy\tPort\tCIDR\tInboundSummary\tRisk"
  printf '%b\n' "$RESULT_ROWS" | sed '/^[[:space:]]*$/d' | sort -u
} | column -t
