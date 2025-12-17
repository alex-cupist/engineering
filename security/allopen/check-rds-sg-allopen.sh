#!/usr/bin/env bash
# RDS 보안취약점 점검: Inbound 0.0.0.0/0 확인 스크립트
# macOS bash 3.x 기준

set -euo pipefail

# AWS_PROFILE 에 따라 기본 REGION 자동 설정
CURRENT_PROFILE="${AWS_PROFILE:-default}"

if [ "$CURRENT_PROFILE" = "dotdotdot" ]; then
  REGION="us-west-2"   # 오레곤 (Oregon)
else
  REGION="ap-northeast-2"  # 서울
fi

# CLI 인자로 REGION 을 덮어쓰기 가능
REGION="${1:-$REGION}"

echo "🔧 AWS_PROFILE=$CURRENT_PROFILE → REGION=$REGION"

if ! command -v aws >/dev/null; then
  echo "❌ aws CLI 가 설치되어 있지 않습니다." >&2
  exit 1
fi
if ! command -v jq >/dev/null; then
  echo "❌ jq 가 필요합니다. (brew install jq)" >&2
  exit 1
fi
if ! command -v column >/dev/null; then
  echo "❌ column 명령이 없습니다. (brew install util-linux)" >&2
  exit 1
fi

echo "=========================================================="
echo " 🔍 Step 1) RDS 인스턴스 / 클러스터 목록 조회 (region=$REGION)"
echo "=========================================================="

DB_INSTANCES=$(aws rds describe-db-instances \
  --region "$REGION" \
  --query 'DBInstances[].DBInstanceIdentifier' \
  --output text)

DB_CLUSTERS=$(aws rds describe-db-clusters \
  --region "$REGION" \
  --query 'DBClusters[].DBClusterIdentifier' \
  --output text)

if [ -z "$DB_INSTANCES" ] && [ -z "$DB_CLUSTERS" ]; then
  echo "⚠️  RDS 리소스를 찾지 못했습니다."
  exit 0
fi

for db in $DB_INSTANCES; do echo " - Instance: $db"; done
for db in $DB_CLUSTERS; do echo " - Cluster : $db"; done
echo

# 결과 저장용
TMP_RESULT=$(mktemp)
echo "ResourceType|ResourceId|SG_ID|Port|CIDR|Risk" > "$TMP_RESULT"

#######################################################
# 함수: SG inbound rule 분석 → 0.0.0.0/0 여부
#######################################################
check_sg_risk() {
  local sg_id="$1"
  local resource_type="$2"
  local resource_id="$3"

  SG_JSON=$(aws ec2 describe-security-groups \
    --group-ids "$sg_id" \
    --region "$REGION" \
    --output json)

  echo "$SG_JSON" | jq -r --arg rt "$resource_type" --arg id "$resource_id" --arg sg "$sg_id" '
    .SecurityGroups[]?.IpPermissions[]? as $p
    | ($p.IpRanges // [] )[]? as $r
    | $r.CidrIp as $cidr
    | (
        if ($p.FromPort == null and $p.ToPort == null) then "ALL"
        elif ($p.FromPort == $p.ToPort) then ($p.FromPort|tostring)
        else (($p.FromPort|tostring) + "-" + ($p.ToPort|tostring))
        end
      ) as $port
    | select($cidr == "0.0.0.0/0")
    | "\($rt)|\($id)|\($sg)|\($port)|0.0.0.0/0|HIGH"
  '
}

#######################################################
# Step 2) RDS Instance SG 분석
#######################################################
echo "=========================================================="
echo " 🔍 Step 2) RDS Instance 보안 그룹 분석"
echo "=========================================================="

for DB in $DB_INSTANCES; do
  INFO=$(aws rds describe-db-instances \
    --db-instance-identifier "$DB" \
    --region "$REGION")

  SG_LIST=$(echo "$INFO" | jq -r '.DBInstances[].VpcSecurityGroups[].VpcSecurityGroupId')

  for SG in $SG_LIST; do
    RESULT=$(check_sg_risk "$SG" "RDS_INSTANCE" "$DB")
    if [ -n "$RESULT" ]; then
      echo "$RESULT" >> "$TMP_RESULT"
    fi
  done
done

#######################################################
# Step 3) RDS Cluster SG 분석 (Aurora 포함)
#######################################################
echo "=========================================================="
echo " 🔍 Step 3) RDS Cluster 보안 그룹 분석"
echo "=========================================================="

for CL in $DB_CLUSTERS; do
  INFO=$(aws rds describe-db-clusters \
    --db-cluster-identifier "$CL" \
    --region "$REGION")

  SG_LIST=$(echo "$INFO" | jq -r '.DBClusters[].VpcSecurityGroups[].VpcSecurityGroupId')

  for SG in $SG_LIST; do
    RESULT=$(check_sg_risk "$SG" "RDS_CLUSTER" "$CL")
    if [ -n "$RESULT" ]; then
      echo "$RESULT" >> "$TMP_RESULT"
    fi
  done
done

#######################################################
# Step 4) 결과 출력
#######################################################
echo
echo "=========================================================="
echo " 🛡 RDS 보안 취약점 요약 (0.0.0.0/0)"
echo "=========================================================="

if [ "$(wc -l < "$TMP_RESULT")" -le 1 ]; then
  echo "🎉 매우 안전함 — 0.0.0.0/0 인바운드 노출 없음!"
else
  column -t -s '|' "$TMP_RESULT"
fi

echo
echo "=========================================================="
echo " 🎉 RDS 보안 점검 완료"
echo "=========================================================="

rm -f "$TMP_RESULT"

