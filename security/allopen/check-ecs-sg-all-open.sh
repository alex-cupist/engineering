#!/usr/bin/env bash
set -euo pipefail

REGION=${REGION:-ap-northeast-2}

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
  echo "✅ ECS 공개 보안그룹 없음"
  exit 0
fi

OPEN_SG_INFO="$(printf '%s\n%s\n' "$OPEN_SG_V4" "$OPEN_SG_V6" | sed '/^[[:space:]]*$/d' | sort -u)"

########################################
# 3) 모든 ECS 서비스의 SG 매핑 수집
########################################
CLUSTERS="$(aws ecs list-clusters --region "$REGION" --query 'clusterArns[]' --output text 2>/dev/null || true)"

if [ -z "$CLUSTERS" ]; then
  echo "ℹ️ ECS 클러스터 없음"
  exit 0
fi

SVC_SG_MAP=""

for CL in $CLUSTERS; do
  SERVICES="$(aws ecs list-services --cluster "$CL" --region "$REGION" --query 'serviceArns[]' --output text 2>/dev/null || true)"
  [ -z "$SERVICES" ] && continue

  CHUNK=()   # 배열 초기화
  COUNT=0

  for SVC in $SERVICES; do
    CHUNK+=("$SVC")
    COUNT=$((COUNT+1))

    if [ $COUNT -ge 10 ]; then
      PART="$(
        aws ecs describe-services \
          --cluster "$CL" \
          --region "$REGION" \
          --services "${CHUNK[@]}" \
          --query 'services[].{Cluster:clusterArn,Name:serviceName,SG:networkConfiguration.awsvpcConfiguration.securityGroups}' \
          --output text 2>/dev/null || true
      )"
      SVC_SG_MAP="$SVC_SG_MAP"$'\n'"$PART"
      CHUNK=()
      COUNT=0
    fi
  done

  # 남은 chunk 처리
  if [ ${#CHUNK[@]} -gt 0 ]; then
    PART="$(
      aws ecs describe-services \
        --cluster "$CL" \
        --region "$REGION" \
        --services "${CHUNK[@]}" \
        --query 'services[].{Cluster:clusterArn,Name:serviceName,SG:networkConfiguration.awsvpcConfiguration.securityGroups}' \
        --output text 2>/dev/null || true
    )"
    SVC_SG_MAP="$SVC_SG_MAP"$'\n'"$PART"
  fi
done

SVC_SG_MAP="$(printf '%s\n' "$SVC_SG_MAP" | sed '/^[[:space:]]*$/d')"

########################################
# 4) 열린 SG만 필터링
########################################
ROWS=""

while read -r CL_ARN SVC_NAME SG_ID; do
  [ -z "${CL_ARN:-}" ] && continue
  [ -z "${SG_ID:-}" ] && continue

  # IPv4/IPv6 판별
  HAS_V4=1
  if awk -v id="$SG_ID" '$1==id {print "yes"; exit}' <<< "$OPEN_SG_V4" >/dev/null; then
    HAS_V4=0
  fi

  HAS_V6=1
  if awk -v id="$SG_ID" '$1==id {print "yes"; exit}' <<< "$OPEN_SG_V6" >/dev/null; then
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

  SG_NAME=$(awk -v id="$SG_ID" '$1==id {print $2; exit}' <<< "$OPEN_SG_INFO")
  CL_NAME=$(echo "$CL_ARN" | awk -F'/' '{print $NF}')

  ROWS="${ROWS}\n${CL_NAME}\t${SVC_NAME}\t${SG_ID}\t${SG_NAME}\t${OPEN_BY}"
done <<< "$SVC_SG_MAP"

{
  echo -e "Cluster\tServiceName\tSecurityGroupId\tSecurityGroupName\tOpenBy"
  printf '%b\n' "$ROWS" | sed '/^[[:space:]]*$/d' | sort -u
} | column -t
