#!/bin/bash
set -e

echo "🔍 Scanning for unused IAM Roles..."

# 90일 전 날짜 계산 (macOS BSD date)
CUTOFF_DATE=$(date -v -90d +%Y-%m-%dT%H:%M:%S)

aws iam list-roles --output json | jq -r '.Roles[] | .RoleName' | while read -r ROLE; do
    LAST_USED=$(aws iam get-role --role-name "$ROLE" \
        --query "Role.RoleLastUsed.LastUsedDate" --output text 2>/dev/null)

    if [[ "$LAST_USED" == "None" ]]; then
        echo "⚠️ UNUSED (never used): $ROLE"
        continue
    fi

    # Compare dates only if LastUsed exists
    LAST_USED_DATE=$(date -j -f "%Y-%m-%dT%H:%M:%SZ" "$LAST_USED" +%Y-%m-%dT%H:%M:%S 2>/dev/null)

    if [[ "$LAST_USED_DATE" < "$CUTOFF_DATE" ]]; then
        echo "⚠️ UNUSED (no use in last 90 days): $ROLE (last used: $LAST_USED_DATE)"
    fi
done

echo "✅ Done."

