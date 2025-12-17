#!/bin/bash
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

echo "=========================================================="
echo " 🔐 Risk Classification Policy (Report 기준)"
echo "=========================================================="
echo "[기준]"
echo "1) ALL traffic from 0.0.0.0/0 또는 ::/0                 -> CRITICAL / FIX"
echo "2) ALL traffic from CIDR(사설대역 10/8,172.16/12,192.168/16) -> HIGH / FIX"
echo "3) ALL traffic from SG only                              -> MEDIUM / IMPROVE(권장 개선)"
echo "4) 0.0.0.0/0 on non-80/443                                -> HIGH / FIX (상황에 따라 CRITICAL)"
echo "5) 0.0.0.0/0 on 80/443 + internet-facing                 -> LOW / ACCEPT"
echo "----------------------------------------------------------"
echo "※ internal LB에서 0.0.0.0/0 탐지 시: 기본 HIGH / FIX"
echo "=========================================================="
echo ""

if ! command -v jq >/dev/null 2>&1; then
  echo "❌ jq가 필요합니다. (예: brew install jq / apt-get install jq)"
  exit 1
fi

echo "=========================================================="
echo " 🔍 Step 1) ELBv2 Load Balancer 목록 조회 (ALB/NLB/GWLB 포함)"
echo "=========================================================="

LBS=$(aws elbv2 describe-load-balancers \
  --region "$REGION" \
  --query "LoadBalancers[].LoadBalancerArn" \
  --output text)

TABLE="| LB Name | Type | Scheme | SG ID | SG Name | Listener Ports | Inbound Summary | Risk | Action |\n"
TABLE+="|--------|------|--------|------|---------|----------------|---------------|------|--------|\n"

join_commas() { echo "$*" | tr ' ' ','; }

ALLOWED_PUBLIC_PORTS=("80" "443")

is_private_ipv4_cidr() {
  local cidr="$1"
  [[ "$cidr" =~ ^10\. ]] && return 0
  [[ "$cidr" =~ ^192\.168\. ]] && return 0
  [[ "$cidr" =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\. ]] && return 0
  return 1
}

# ✅ bash 3.2 + nounset 안전: jq filter로 결과를 배열에 넣기
# 사용: load_array_from_inbound ALL_IPV4_CIDRS '.jq-filter...'
load_array_from_inbound() {
  local arr_name="$1"
  local jq_filter="$2"
  local line

  # 배열 "선언 + 초기화" (unset 방지)
  eval "declare -a ${arr_name}"
  eval "${arr_name}=()"

  # jq 결과를 한 줄씩 읽어 배열에 push
  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    eval "${arr_name}+=(\"\$line\")"
  done < <(printf '%s' "$INBOUND_RULES" | jq -r "$jq_filter" 2>/dev/null || true)
}

for LB_ARN in $LBS; do
  echo ""
  echo "=========================================================="
  echo " 🎯 LB 분석: $LB_ARN"
  echo "=========================================================="

  LB_JSON=$(aws elbv2 describe-load-balancers --load-balancer-arns "$LB_ARN" --output json)

  LB_NAME=$(echo "$LB_JSON" | jq -r '.LoadBalancers[0].LoadBalancerName // "(unknown)"')
  LB_TYPE=$(echo "$LB_JSON" | jq -r '.LoadBalancers[0].Type // "(unknown)"')
  LB_SCHEME=$(echo "$LB_JSON" | jq -r '.LoadBalancers[0].Scheme // "(unknown)"')

  SG_IDS=$(echo "$LB_JSON" | jq -r '.LoadBalancers[0].SecurityGroups // [] | .[]' | xargs || true)
  if [[ -z "${SG_IDS// }" ]]; then
    SG_IDS="None"
  fi

  echo "📌 LB Name : $LB_NAME"
  echo "📌 Type    : $LB_TYPE"
  echo "📌 Scheme  : $LB_SCHEME"

  echo ""
  echo "=========================================================="
  echo " 🔍 Step 2) 리스너 포트 자동 수집"
  echo "=========================================================="

  LISTENER_PORTS="$(aws elbv2 describe-listeners \
    --region "$REGION" \
    --load-balancer-arn "$LB_ARN" \
    --query "Listeners[].Port" \
    --output text 2>/dev/null || true)"

  if [[ -z "${LISTENER_PORTS// }" ]]; then
    LISTENER_PORTS="(none)"
  fi

  echo "📌 Listener Ports: $(join_commas $LISTENER_PORTS)"

  echo ""
  echo "=========================================================="
  echo " 🔍 Step 3) SG inbound 분석"
  echo "=========================================================="

  if [[ "$SG_IDS" == "None" ]]; then
    echo "⚠️ Security Group이 없습니다. (NLB이거나 SG 미지원 구성) → SG 분석 스킵"
    TABLE+="| $LB_NAME | $LB_TYPE | $LB_SCHEME | - | - | $(join_commas $LISTENER_PORTS) | None (No SG) | INFO | SKIP |\n"
    continue
  fi

  for SG in $SG_IDS; do
    [[ "$SG" == "None" || -z "${SG// }" ]] && continue

    SG_JSON=$(aws ec2 describe-security-groups --region "$REGION" --group-ids "$SG" --output json)
    SG_NAME=$(echo "$SG_JSON" | jq -r '.SecurityGroups[0].GroupName // "(unknown)"')
    INBOUND_RULES=$(echo "$SG_JSON" | jq -c '.SecurityGroups[0].IpPermissions // []')

    echo ""
    echo "🎯 Security Group 분석 → $SG"
    echo "   ▸ Name: $SG_NAME"

    # ✅ 배열들 매번 선언/초기화 (nounset 안전)
    declare -a ALL_IPV4_CIDRS ALL_IPV6_CIDRS ALL_SG_SOURCES ALL_PREFIXLIST_SOURCES
    ALL_IPV4_CIDRS=(); ALL_IPV6_CIDRS=(); ALL_SG_SOURCES=(); ALL_PREFIXLIST_SOURCES=()

    load_array_from_inbound ALL_IPV4_CIDRS '.[] | select(.IpProtocol=="-1") | (.IpRanges // [])[]?.CidrIp // empty'
    load_array_from_inbound ALL_IPV6_CIDRS '.[] | select(.IpProtocol=="-1") | (.Ipv6Ranges // [])[]?.CidrIpv6 // empty'
    load_array_from_inbound ALL_SG_SOURCES  '.[] | select(.IpProtocol=="-1") | (.UserIdGroupPairs // [])[]?.GroupId // empty'
    load_array_from_inbound ALL_PREFIXLIST_SOURCES '.[] | select(.IpProtocol=="-1") | (.PrefixListIds // [])[]?.PrefixListId // empty'

    INBOUND_SUMMARY_PARTS=()

    # ALL traffic sources 합치기
    ALL_TRAFFIC_SOURCES=()
    for x in "${ALL_IPV4_CIDRS[@]:-}"; do [[ -n "$x" ]] && ALL_TRAFFIC_SOURCES+=("$x"); done
    for x in "${ALL_IPV6_CIDRS[@]:-}"; do [[ -n "$x" ]] && ALL_TRAFFIC_SOURCES+=("$x"); done
    for x in "${ALL_SG_SOURCES[@]:-}"; do [[ -n "$x" ]] && ALL_TRAFFIC_SOURCES+=("$x"); done
    for x in "${ALL_PREFIXLIST_SOURCES[@]:-}"; do [[ -n "$x" ]] && ALL_TRAFFIC_SOURCES+=("$x"); done

    HAS_ALL_TRAFFIC=0
    if ((${#ALL_TRAFFIC_SOURCES[@]} > 0)); then
      HAS_ALL_TRAFFIC=1
      INBOUND_SUMMARY_PARTS+=("ALL traffic from ${ALL_TRAFFIC_SOURCES[*]}")
    fi

    # 0.0.0.0/0 open ports 수집
    OPEN_PORT_RANGES=$(printf '%s' "$INBOUND_RULES" | jq -r '
      .[] |
      select((.IpRanges // []) | map(.CidrIp) | index("0.0.0.0/0")) |
      "\(.IpProtocol)\t\(.FromPort // "null")\t\(.ToPort // "null")"
    ' 2>/dev/null || true)

    HAS_PUBLIC_IPV4_OPEN=0
    OPEN_HAS_NON_80_443=0
    OPEN_DESC=()

    if [[ -n "${OPEN_PORT_RANGES// }" ]]; then
      HAS_PUBLIC_IPV4_OPEN=1

      while IFS=$'\t' read -r proto fp tp; do
        if [[ "$proto" == "-1" || "$fp" == "null" || "$tp" == "null" ]]; then
          OPEN_DESC+=("${proto}:ALL")
          OPEN_HAS_NON_80_443=1
          continue
        fi

        if [[ "$fp" != "$tp" ]]; then
          OPEN_DESC+=("${proto}:${fp}-${tp}")
          OPEN_HAS_NON_80_443=1
          continue
        fi

        OPEN_DESC+=("${proto}:${fp}")

        allowed_match=0
        for ap in "${ALLOWED_PUBLIC_PORTS[@]}"; do
          [[ "$fp" == "$ap" ]] && allowed_match=1
        done
        if [[ "$allowed_match" -eq 0 ]]; then
          OPEN_HAS_NON_80_443=1
        fi
      done <<< "$OPEN_PORT_RANGES"

      INBOUND_SUMMARY_PARTS+=("0.0.0.0/0 on ${OPEN_DESC[*]}")
    fi

    # Risk / Action 산정
    RISK="LOW"
    ACTION="OK"

    # (1) ALL traffic 기준
    if [[ "$HAS_ALL_TRAFFIC" -eq 1 ]]; then
      all_has_public=0
      for c in "${ALL_IPV4_CIDRS[@]:-}"; do [[ "$c" == "0.0.0.0/0" ]] && all_has_public=1; done
      for c in "${ALL_IPV6_CIDRS[@]:-}"; do [[ "$c" == "::/0" ]] && all_has_public=1; done

      if [[ "$all_has_public" -eq 1 ]]; then
        RISK="CRITICAL"; ACTION="FIX"
      else
        all_has_private_cidr=0
        for c in "${ALL_IPV4_CIDRS[@]:-}"; do
          if is_private_ipv4_cidr "$c"; then all_has_private_cidr=1; fi
        done

        if [[ "$all_has_private_cidr" -eq 1 ]]; then
          RISK="HIGH"; ACTION="FIX"
        else
          # SG only
          if ((${#ALL_IPV4_CIDRS[@]} == 0)) && ((${#ALL_IPV6_CIDRS[@]} == 0)) && ((${#ALL_SG_SOURCES[@]} > 0)); then
            RISK="MEDIUM"; ACTION="IMPROVE"
          else
            RISK="HIGH"; ACTION="FIX"
          fi
        fi
      fi
    fi

    # (2) 0.0.0.0/0 open port 기준 (더 위험하면 끌어올림)
    if [[ "$HAS_PUBLIC_IPV4_OPEN" -eq 1 ]]; then
      if [[ "$LB_SCHEME" == "internal" ]]; then
        [[ "$RISK" != "CRITICAL" ]] && { RISK="HIGH"; ACTION="FIX"; }
      else
        if [[ "$OPEN_HAS_NON_80_443" -eq 1 ]]; then
          [[ "$RISK" != "CRITICAL" ]] && { RISK="HIGH"; ACTION="FIX"; }
        else
          if [[ "$RISK" == "LOW" ]]; then
            RISK="LOW"; ACTION="ACCEPT"
          fi
        fi
      fi
    fi

    # Summary 결합
    if ((${#INBOUND_SUMMARY_PARTS[@]} == 0)); then
      INBOUND_SUMMARY="None"
    else
      INBOUND_SUMMARY=$(IFS=" + "; echo "${INBOUND_SUMMARY_PARTS[*]}")
    fi

    TABLE+="| $LB_NAME | $LB_TYPE | $LB_SCHEME | $SG | $SG_NAME | $(join_commas $LISTENER_PORTS) | $INBOUND_SUMMARY | $RISK | $ACTION |\n"
  done
done

echo ""
echo "=========================================================="
echo " 🎉 분석 완료 — 표 형태 요약 출력"
echo "=========================================================="
echo -e "$TABLE"
