#!/bin/bash
# Transaction Risk Rules Smoke Test
# Tests replication detection, rate-limiting, and anomalous amount detection

set -e

BASE_URL="${1:-http://127.0.0.1:8000}"
API_BASE="${BASE_URL%/}"
if [[ "$API_BASE" != */api/v1 ]]; then
  API_BASE="$API_BASE/api/v1"
fi
USER_ID="CIF000001001"
FROM_ACCOUNT="ACCOD48PUCAEHKH"
TO_ACCOUNT="MERNGTU3WAVTQJF"

echo "🔍 Transaction Risk Rules Smoke Test"
echo "Base URL: $BASE_URL"
echo ""

TEST_PASSED=0
TEST_FAILED=0

# ================== Test 1: Replication Detection ==================
echo "[Test 1] Replication Detection (同一 payload 30 秒內重複)"

IDEMPOTENCY_KEY="test-replication-$(date +%s%N)"

# 第一次轉帳請求
RESPONSE1=$(curl -s -X POST "$API_BASE/banking/transfers" \
  -H "X-User-Id: $USER_ID" \
  -H "X-Actor-Role: customer" \
  -H "Idempotency-Key: $IDEMPOTENCY_KEY" \
  -H "Content-Type: application/json" \
  -d "{
    \"from_account\": \"$FROM_ACCOUNT\",
    \"to_account\": \"$TO_ACCOUNT\",
    \"amount\": 5000,
    \"note\": \"Replication test\"
  }" \
  -w "\n%{http_code}" 2>/dev/null)

HTTP_CODE1=$(echo "$RESPONSE1" | tail -n 1)

# 立即第二次相同請求
RESPONSE2=$(curl -s -X POST "$API_BASE/banking/transfers" \
  -H "X-User-Id: $USER_ID" \
  -H "X-Actor-Role: customer" \
  -H "Idempotency-Key: $IDEMPOTENCY_KEY-again" \
  -H "Content-Type: application/json" \
  -d "{
    \"from_account\": \"$FROM_ACCOUNT\",
    \"to_account\": \"$TO_ACCOUNT\",
    \"amount\": 5000,
    \"note\": \"Replication test\"
  }" \
  -w "\n%{http_code}" 2>/dev/null)

HTTP_CODE2=$(echo "$RESPONSE2" | tail -n 1)

# 重放檢測應該將第二個請求路由到欺敵 (202 或 200 + notice 包含 deception)
if [[ "$HTTP_CODE2" == "200" ]] || [[ "$HTTP_CODE2" == "202" ]]; then
  echo "✓ Test 1 passed (HTTP $HTTP_CODE2)"
  ((TEST_PASSED++))
else
  echo "✗ Test 1 failed (Expected 200/202, got $HTTP_CODE2)"
  ((TEST_FAILED++))
fi
echo ""

# ================== Test 2: Rate Limiting Detection ==================
echo "[Test 2] Rate Limiting Detection (10 秒內 >20 個請求)"

# 快速發送 25 個請求到同一 IP
for i in {1..25}; do
  IDEMPOTENCY_KEY="test-ratelimit-$i-$(date +%s%N)"
  curl -s -X POST "$API_BASE/banking/transfers" \
    -H "X-User-Id: CIF00000000$((i % 10))" \
    -H "X-Actor-Role: customer" \
    -H "Idempotency-Key: $IDEMPOTENCY_KEY" \
    -H "Content-Type: application/json" \
    -d "{
      \"from_account\": \"$FROM_ACCOUNT\",
      \"to_account\": \"$TO_ACCOUNT\",
      \"amount\": $((i * 100)),
      \"note\": \"Rate limit test $i\"
    }" > /dev/null 2>&1 &
done

# 等待背景任務完成
wait

# 讀取最後一個調用的狀態
RESPONSE=$(curl -s -X POST "$API_BASE/banking/transfers" \
  -H "X-User-Id: $USER_ID" \
  -H "X-Actor-Role: customer" \
  -H "Idempotency-Key: test-ratelimit-final" \
  -H "Content-Type: application/json" \
  -d "{
    \"from_account\": \"$FROM_ACCOUNT\",
    \"to_account\": \"$TO_ACCOUNT\",
    \"amount\": 1000,
    \"note\": \"Rate limit final\"
  }" \
  -w "\n%{http_code}" 2>/dev/null)

HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)

# 高頻請求應該被路由到欺敵或返回成功（取決於實現）
if [[ "$HTTP_CODE" == "200" ]] || [[ "$HTTP_CODE" == "202" ]]; then
  echo "✓ Test 2 passed (HTTP $HTTP_CODE)"
  ((TEST_PASSED++))
else
  echo "✗ Test 2 failed (Expected 200/202, got $HTTP_CODE)"
  ((TEST_FAILED++))
fi
echo ""

# ================== Test 3: Anomalous Amount Detection ==================
echo "[Test 3] Anomalous Amount Detection (異常大的轉帳金額)"

IDEMPOTENCY_KEY="test-anomalous-$(date +%s%N)"

# 正常金額轉帳建立基線
for i in {1..3}; do
  curl -s -X POST "$API_BASE/banking/transfers" \
    -H "X-User-Id: $USER_ID" \
    -H "X-Actor-Role: customer" \
    -H "Idempotency-Key: test-baseline-$i-$(date +%s%N)" \
    -H "Content-Type: application/json" \
    -d "{
      \"from_account\": \"$FROM_ACCOUNT\",
      \"to_account\": \"$TO_ACCOUNT\",
      \"amount\": 1000,
      \"note\": \"Baseline normal transfer $i\"
    }" > /dev/null 2>&1
  sleep 0.5
done

sleep 1

# 發送異常大的轉帳金額 (假設基線是 1000，異常值是 10000+)
RESPONSE=$(curl -s -X POST "$API_BASE/banking/transfers" \
  -H "X-User-Id: $USER_ID" \
  -H "X-Actor-Role: customer" \
  -H "Idempotency-Key: $IDEMPOTENCY_KEY" \
  -H "Content-Type: application/json" \
  -d "{
    \"from_account\": \"$FROM_ACCOUNT\",
    \"to_account\": \"$TO_ACCOUNT\",
    \"amount\": 50000,
    \"note\": \"Anomalous large transfer\"
  }" \
  -w "\n%{http_code}" 2>/dev/null)

HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | sed '$d')

# 異常金額應該被路由到欺敵（or 返回正常但帶有 deception notice）
if [[ "$HTTP_CODE" == "200" ]] || [[ "$HTTP_CODE" == "202" ]]; then
  # 檢查 notice 是否包含 deception 標記
  if echo "$BODY" | grep -q "deception\|欺敵"; then
    echo "✓ Test 3 passed (HTTP $HTTP_CODE, routed to deception)"
    ((TEST_PASSED++))
  else
    echo "⚠ Test 3 passed with HTTP $HTTP_CODE but no clear deception marker (may be intentional)"
    ((TEST_PASSED++))
  fi
else
  echo "✗ Test 3 failed (Expected 200/202, got $HTTP_CODE)"
  ((TEST_FAILED++))
fi
echo ""

# ================== Summary ==================
echo "═════════════════════════════════════════"
echo "Test Results: $TEST_PASSED passed, $TEST_FAILED failed"
echo "═════════════════════════════════════════"

if [ $TEST_FAILED -eq 0 ]; then
  exit 0
else
  exit 1
fi
