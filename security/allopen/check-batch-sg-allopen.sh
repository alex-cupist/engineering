#!/usr/bin/env bash
# AWS Batch (EC2 Compute Environment) - SG All Open 점검
# macOS 기준: aws cli, jq 필요

set -euo pipefail

REGION="${1:-ap-northeast-2}"

command -v aws >/dev/null 2>&1 || { echo "❌ aws cli 필요"; exit 1; }
command -v jq  >/dev/null 2>&1 || { echo "❌ jq 필요"; exit 1; }

echo "=========================================================="
echo " 🔍 Step 1) AWS Batch Compute Environment 조회 (region=$REGION)"
echo "=========================================================="

CE_ARNS=$(aws batch describe-compute-environments \
  --region "$REGION" \
  --query 'computeEnvironments[].computeEnvironmentArn' \
  --output text)

if [ -z "$CE_ARNS" ]; then
  echo "⚠️  Compute Environment 없음"
  exit 0
fi

echo
echo "=========================================================="
echo " 🔍 Step 2) EC2 기반 Compute Environment 분석"
echo "=========================================================="

echo "| ComputeEnv | SG ID | Port | CIDR | Risk | Action |"
echo "|------------|-------|------|------|------|--------|"

for CE_ARN in $CE_ARNS; do
  CE_JSON=$(aws batch describe-compute-environments \
    --region "$REGION" \
    --compute-environments "$CE_ARN")

  CE_NAME=$(echo "$CE_JSON" | jq -r '.computeEnvironments[0].computeEnvironmentName')
  CE_TYPE=$(echo "$CE_JSON" | jq -r '.computeEnvironments[0].computeResources.type')

  # FARGATE 계열은 제외
  if [[ "$CE_TYPE" == "FARGATE"* ]]; then
    continue
  fi

  # SG 직접 지정 or Launch Template 경유
  SG_IDS=$(echo "$CE_JSON" | jq -r '
    .computeEnvironments[0].computeResources.securityGroupIds[]?')

  if [ -z "$SG_IDS" ]; then
    echo "| $CE_NAME | NONE | - | - | LOW | OK |"
    continue
  fi

  for SG in $SG_IDS; do
    SG_JSON=$(aws ec2 describe-security-groups \
      --region "$REGION" \
      --group-ids "$SG")

    FOUND=0

    echo "$SG_JSON" | jq -r '
      .SecurityGroups[]?.IpPermissions[]? as $p
      | ($p.IpRanges[]?.CidrIp // empty)
      | select(. == "0.0.0.0/0")
      | (
          if ($p.FromPort? == null and $p.ToPort? == null) then "ALL"
          elif ($p.FromPort == $p.ToPort) then ($p.FromPort|tostring)
          else (($p.FromPort|tostring) + "-" + ($p.ToPort|tostring))
          end
        ) as $port
      | "\($port)|\(. )"
    ' | while IFS='|' read -r PORT CIDR; do
      FOUND=1
      echo "| $CE_NAME | $SG | $PORT | 0.0.0.0/0 | HIGH | FIX |"
    done

    if [ "$FOUND" -eq 0 ]; then
      echo "| $CE_NAME | $SG | - | - | LOW | OK |"
    fi
  done
done

echo "=========================================================="
echo " 🎉 AWS Batch (EC2) SG All-Open 점검 완료"
echo "=========================================================="
