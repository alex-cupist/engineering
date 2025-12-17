#!/bin/zsh

# 1) Credential Report 생성
aws iam generate-credential-report > /dev/null

# 2) Report 다운로드 및 CSV 저장
REPORT_FILE="credential_report.csv"
FILTERED_FILE="credential_report_inactive.csv"

aws iam get-credential-report \
  --query Content \
  --output text \
  | base64 --decode > "$REPORT_FILE"

echo "📄 Credential Report 저장됨 → $REPORT_FILE"


# 3) inactive 또는 N/A 필터링하여 파일 저장 & 화면 출력
echo "🔎 inactive / N/A 계정 필터링 결과:"
echo "----------------------------------------------------"

grep -E "inactive|N/A" "$REPORT_FILE" | tee "$FILTERED_FILE"

echo "📄 필터링 결과 저장됨 → $FILTERED_FILE"

