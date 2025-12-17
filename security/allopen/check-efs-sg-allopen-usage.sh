#!/usr/bin/env bash
# EFS 보안 + 사용 여부 점검 (FAST VERSION)
# ECS는 Service 기준으로만 EFS 사용 여부 분석
# macOS bash 3.x compatible

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

command -v aws >/dev/null || { echo "❌ aws cli 필요"; exit 1; }
command -v jq  >/dev/null || { echo "❌ jq 필요 (brew install jq)"; exit 1; }
command -v column >/dev/null || { echo "❌ column 필요"; exit 1; }

echo "=========================================================="
echo " 🔍 Step 1) EFS 파일 시스템 목록 조회 (region=$REGION)"
echo "=========================================================="

EFS_IDS=$(aws efs describe-file-systems \
  --region "$REGION" \
  --query 'FileSystems[].FileSystemId' \
  --output text)

[ -z "$EFS_IDS" ] && { echo "EFS 없음"; exit 0; }

echo "$EFS_IDS" | tr '\t' '\n' | sed 's/^/   - /'
echo

SECURITY_TMP=$(mktemp)
USAGE_TMP=$(mktemp)

echo "FileSystemId|MountTargetId|SubnetId|SecurityGroupId|Port|CIDR|Risk" > "$SECURITY_TMP"
echo "FileSystemId|UsageType|ResourceId|Detail" > "$USAGE_TMP"

echo "=========================================================="
echo " 🔍 Step 2) EFS MountTarget + SG 보안 점검"
echo "=========================================================="
echo "| FileSystemId | MountTargetId | SubnetId | SG ID | Port | CIDR | Risk |"
echo "|-------------|---------------|----------|-------|------|------|------|"

for FSID in $EFS_IDS; do
  MT_IDS=$(aws efs describe-mount-targets \
    --region "$REGION" \
    --file-system-id "$FSID" \
    --query 'MountTargets[].MountTargetId' \
    --output text 2>/dev/null || echo "")

  [ -z "$MT_IDS" ] && continue

  for MTID in $MT_IDS; do
    SUBNET_ID=$(aws efs describe-mount-targets \
      --region "$REGION" \
      --mount-target-id "$MTID" \
      --query 'MountTargets[0].SubnetId' \
      --output text 2>/dev/null || echo "-")

    SG_IDS=$(aws efs describe-mount-target-security-groups \
      --region "$REGION" \
      --mount-target-id "$MTID" \
      --query 'SecurityGroups[]' \
      --output text 2>/dev/null || echo "")

    if [ -z "$SG_IDS" ]; then
      echo "| $FSID | $MTID | $SUBNET_ID | NONE | - | - | LOW |"
      continue
    fi

    for SG in $SG_IDS; do
      # ✅ 여기서 --query 쓰지 말고 "풀 JSON" 받는 게 핵심
      SG_JSON=$(aws ec2 describe-security-groups \
        --region "$REGION" \
        --group-ids "$SG" \
        --output json 2>/dev/null || echo "")

      if [ -z "$SG_JSON" ]; then
        echo "| $FSID | $MTID | $SUBNET_ID | $SG | - | - | LOW |"
        continue
      fi

      # ✅ IpPermissions / IpRanges 둘 다 안전 접근
      OPEN_LINES=$(echo "$SG_JSON" | jq -r \
        --arg fs "$FSID" \
        --arg mt "$MTID" \
        --arg sn "$SUBNET_ID" \
        --arg sg "$SG" '
        .SecurityGroups[]?.IpPermissions[]? as $p
        | ($p.IpRanges // [])[]? as $r
        | $r.CidrIp as $cidr
        | (
            if ($p.FromPort? == null and $p.ToPort? == null) then "0-65535"
            elif ($p.FromPort == $p.ToPort) then ($p.FromPort|tostring)
            else (($p.FromPort|tostring) + "-" + ($p.ToPort|tostring))
          end
          ) as $port
        | (
            if $cidr == "0.0.0.0/0" then
              if ($port == "0-65535" or $port == "2049") then "HIGH"
              else "MEDIUM"
              end
            else "LOW"
            end
          ) as $risk
        | "| \($fs) | \($mt) | \($sn) | \($sg) | \($port) | \($cidr) | \($risk) |"
      ')

      if [ -n "$OPEN_LINES" ]; then
        echo "$OPEN_LINES"
      else
        echo "| $FSID | $MTID | $SUBNET_ID | $SG | - | - | LOW |"
      fi
    done
  done
done


#############################################
# Step 3) EFS 사용 여부 (FAST: ECS Service 기준)
#############################################
echo "=========================================================="
echo " 🔍 Step 3) EFS 사용 여부 분석 (ECS Service 기준)"
echo "=========================================================="

CLUSTERS=$(aws ecs list-clusters \
  --region "$REGION" \
  --query 'clusterArns[]' \
  --output text)

for CLUSTER in $CLUSTERS; do
  echo "📌 Cluster: $CLUSTER"

  SERVICES=$(aws ecs list-services \
    --region "$REGION" \
    --cluster "$CLUSTER" \
    --query 'serviceArns[]' \
    --output text)

  for SVC in $SERVICES; do
    TD=$(aws ecs describe-services \
      --region "$REGION" \
      --cluster "$CLUSTER" \
      --services "$SVC" \
      --query 'services[0].taskDefinition' \
      --output text)

    [ "$TD" = "None" ] && continue

    TD_JSON=$(aws ecs describe-task-definition \
      --region "$REGION" \
      --task-definition "$TD" \
      --output json)

    FS_USED=$(echo "$TD_JSON" | jq -r '
      .taskDefinition.volumes[]? 
      | select(.efsVolumeConfiguration!=null)
      | .efsVolumeConfiguration.fileSystemId
    ')

    if [ -n "$FS_USED" ]; then
      FAMILY=$(echo "$TD_JSON" | jq -r '.taskDefinition.family')
      for FSID in $FS_USED; do
        echo "$FSID|ECS_SERVICE|$FAMILY|Service uses EFS volume" >> "$USAGE_TMP"
      done
    fi
  done
done

#############################################
# Step 4) Lambda (유지)
#############################################
echo "📌 Lambda 기반 EFS 사용 분석..."

LAMBDA_LIST=$(aws lambda list-functions \
  --region "$REGION" \
  --query 'Functions[].FunctionName' \
  --output text)

for FN in $LAMBDA_LIST; do
  CFG=$(aws lambda get-function-configuration \
    --region "$REGION" \
    --function-name "$FN" \
    --output json)

  echo "$CFG" | jq -r '
    .FileSystemConfigs[]? |
    .Arn |
    capture("fs-(?<id>[a-z0-9]+)") |
    "fs-\(.id)|LAMBDA|'$FN'|Lambda uses EFS"
  ' >> "$USAGE_TMP"
done

echo
echo "=========================================================="
echo " 📊 EFS 사용 위치 요약"
echo "=========================================================="

if [ "$(wc -l < "$USAGE_TMP")" -le 1 ]; then
  echo "⚠️  EFS 사용 리소스 없음"
else
  sort -u "$USAGE_TMP" | column -t -s '|'
fi

rm -f "$SECURITY_TMP" "$USAGE_TMP"

echo
echo "=========================================================="
echo " 🎉 FAST EFS 보안 + 사용 점검 완료"
echo "=========================================================="
