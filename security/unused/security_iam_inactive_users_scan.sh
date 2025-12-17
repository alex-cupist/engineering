# 1) 6개월 전 날짜 계산 (macOS BSD date)
CUTOFF=$(date -v -6m +%Y-%m-%d)

echo "🔎 기준 날짜(Cutoff): $CUTOFF"

# 2) Credential Report 생성
aws iam generate-credential-report > /dev/null

# 3) Credential Report 다운로드
aws iam get-credential-report \
  --query 'Content' \
  --output text \
  | base64 --decode > credential_report.csv

echo "✅ credential_report.csv 생성됨"

# 4) 6개월 이상 미사용 IAM 사용자 출력
echo "📌 6개월 이상 로그인하지 않은 계정 목록:"
echo "-----------------------------------------------------"
echo "User,PasswordLastUsed,AccessKey1LastUsed,AccessKey2LastUsed"

while IFS=',' read -r user arn created passUsed passChanged passNext accessKey1 active1 last1 region1 last2 region2; do
    if [[ "$user" == "user" ]]; then
        continue  # 헤더 스킵
    fi

    # password last used 비교
    if [[ "$passUsed" != "N/A" && "$passUsed" < "$CUTOFF" ]]; then
        echo "$user,$passUsed"
        continue
    fi

    # 액세스키 #1 비교
    if [[ "$last1" != "N/A" && "$last1" < "$CUTOFF" ]]; then
        echo "$user,$last1"
        continue
    fi

    # 액세스키 #2 비교
    if [[ "$last2" != "N/A" && "$last2" < "$CUTOFF" ]]; then
        echo "$user,$last2"
        continue
    fi
done < credential_report.csv
