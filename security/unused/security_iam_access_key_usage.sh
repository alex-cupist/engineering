CUTOFF=$(date -v -6m +%Y-%m-%d)

aws iam list-users --query "Users[*].UserName" --output text | tr '\t' '\n' |
while read USER; do
  echo "=== $USER ==="

  KEYS=$(aws iam list-access-keys --user-name "$USER" \
        --query "AccessKeyMetadata[*].AccessKeyId" --output text)

  for KEY in $KEYS; do
    LASTUSED=$(aws iam get-access-key-last-used \
               --access-key-id "$KEY" \
               --query "AccessKeyLastUsed.LastUsedDate" \
               --output text)

    if [[ "$LASTUSED" != "None" && "$LASTUSED" < "$CUTOFF" ]]; then
      echo "⚠️  $USER - $KEY 마지막 사용일: $LASTUSED (6개월 이상 미사용)"
    fi
  done
done
