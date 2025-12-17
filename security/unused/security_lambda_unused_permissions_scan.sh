#!/bin/bash
set -e

echo "🔍 Scanning Lambda Functions for unused permissions..."

FUNCTIONS=$(aws lambda list-functions --query "Functions[].FunctionName" --output text)

for FN in $FUNCTIONS; do
    ROLE=$(aws lambda get-function --function-name "$FN" \
        --query "Configuration.Role" --output text)

    ROLE_NAME=$(basename "$ROLE")

    echo "🔧 Checking Lambda: $FN (Role: $ROLE_NAME)"

    # Inline policies
    INLINE=$(aws iam list-role-policies --role-name "$ROLE_NAME" \
        --query "PolicyNames[]" --output json)

    echo "   ▶ Inline Policies: $INLINE"

    # Managed policies
    MANAGED=$(aws iam list-attached-role-policies --role-name "$ROLE_NAME" \
        --query "AttachedPolicies[].PolicyName" --output json)

    echo "   ▶ Managed Policies: $MANAGED"

    echo "   ⚠️ NOTE: To fully validate 'unused', CloudTrail access log review is required."
done

echo "✅ Done."

