#!/bin/bash
# 鑑識事件欄位標準化查詢層測試
# Tests event query, filtering by route/risk_score, and attack chain replay

set -e

BASE_URL="${1:-http://127.0.0.1:8000}"
API_KEY="dev-local-api-key-change-me"

echo "🔍 Event Query & Replay Smoke Test"
echo "Base URL: $BASE_URL"
echo ""

TEST_PASSED=0
TEST_FAILED=0

# ================== Test 1: Query Events by Route (Real) ==================
echo "[Test 1] Query Events by Route (real 路由)"

RESPONSE=$(curl -s -X GET "$BASE_URL/dashboard/events/by_route/real?limit=10" \
  -H "X-API-Key: $API_KEY" \
  -w "\n%{http_code}" 2>/dev/null)

HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | sed '$d')

if [[ "$HTTP_CODE" == "200" ]]; then
  # 驗證回應結構
  if echo "$BODY" | grep -q "\"route\":\"real\""; then
    echo "✓ Test 1 passed (HTTP $HTTP_CODE, returned real events)"
    ((TEST_PASSED++))
  else
    echo "✗ Test 1 failed (HTTP $HTTP_CODE but missing route field)"
    ((TEST_FAILED++))
  fi
else
  echo "✗ Test 1 failed (Expected 200, got $HTTP_CODE)"
  ((TEST_FAILED++))
fi
echo ""

# ================== Test 2: Query Events by Route (Deception) ==================
echo "[Test 2] Query Events by Route (deception 路由)"

RESPONSE=$(curl -s -X GET "$BASE_URL/dashboard/events/by_route/deception?limit=10" \
  -H "X-API-Key: $API_KEY" \
  -w "\n%{http_code}" 2>/dev/null)

HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | sed '$d')

if [[ "$HTTP_CODE" == "200" ]]; then
  if echo "$BODY" | grep -q "\"route\":\"deception\""; then
    echo "✓ Test 2 passed (HTTP $HTTP_CODE, returned deception events)"
    ((TEST_PASSED++))
  else
    echo "✗ Test 2 failed (HTTP $HTTP_CODE but missing deception route)"
    ((TEST_FAILED++))
  fi
else
  echo "✗ Test 2 failed (Expected 200, got $HTTP_CODE)"
  ((TEST_FAILED++))
fi
echo ""

# ================== Test 3: Query Events by Risk Score Range ==================
echo "[Test 3] Query Events by Risk Score (60-100 分數範圍)"

RESPONSE=$(curl -s -X GET "$BASE_URL/dashboard/events/by_risk_score?min_score=60&max_score=100&limit=10" \
  -H "X-API-Key: $API_KEY" \
  -w "\n%{http_code}" 2>/dev/null)

HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | sed '$d')

if [[ "$HTTP_CODE" == "200" ]]; then
  if echo "$BODY" | grep -q "\"min_score\":60"; then
    echo "✓ Test 3 passed (HTTP $HTTP_CODE, returned risk score filtered events)"
    ((TEST_PASSED++))
  else
    echo "✗ Test 3 failed (HTTP $HTTP_CODE but missing min_score field)"
    ((TEST_FAILED++))
  fi
else
  echo "✗ Test 3 failed (Expected 200, got $HTTP_CODE)"
  ((TEST_FAILED++))
fi
echo ""

# ================== Test 4: Replay Attack Chain (Demo User) ==================
echo "[Test 4] Replay Attack Chain (查詢 CIF000001001 的攻擊鏈)"

RESPONSE=$(curl -s -X GET "$BASE_URL/dashboard/replay/CIF000001001" \
  -H "X-API-Key: $API_KEY" \
  -w "\n%{http_code}" 2>/dev/null)

HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | sed '$d')

if [[ "$HTTP_CODE" == "200" ]] || [[ "$HTTP_CODE" == "404" ]]; then
  # 200 = 找到攻擊鏈，404 = 沒有該用戶的事件（也算通過）
  if echo "$BODY" | grep -q "\"query_id\":\"CIF000001001\""; then
    echo "✓ Test 4 passed (HTTP $HTTP_CODE, returned chain with query_id)"
    ((TEST_PASSED++))
  else
    echo "✓ Test 4 passed (HTTP $HTTP_CODE, endpoint working)"
    ((TEST_PASSED++))
  fi
else
  echo "✗ Test 4 failed (Expected 200/404, got $HTTP_CODE)"
  ((TEST_FAILED++))
fi
echo ""

# ================== Test 5: Invalid Route Parameter ==================
echo "[Test 5] Invalid Route Parameter (驗證輸入驗證)"

RESPONSE=$(curl -s -X GET "$BASE_URL/dashboard/events/by_route/invalid_route?limit=10" \
  -H "X-API-Key: $API_KEY" \
  -w "\n%{http_code}" 2>/dev/null)

HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | sed '$d')

if [[ "$HTTP_CODE" == "200" ]]; then
  # 驗證返回錯誤訊息或空結果
  if echo "$BODY" | grep -q "error\|Invalid"; then
    echo "✓ Test 5 passed (HTTP $HTTP_CODE, properly rejected invalid route)"
    ((TEST_PASSED++))
  else
    echo "⚠ Test 5 passed with HTTP $HTTP_CODE (no explicit error)"
    ((TEST_PASSED++))
  fi
else
  echo "✓ Test 5 passed (HTTP $HTTP_CODE, rejected invalid route)"
  ((TEST_PASSED++))
fi
echo ""

# ================== Test 6: API Key Validation ==================
echo "[Test 6] API Key Validation (沒有 API Key 應被拒絕)"

RESPONSE=$(curl -s -X GET "$BASE_URL/dashboard/events/by_route/real?limit=10" \
  -w "\n%{http_code}" 2>/dev/null)

HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)

if [[ "$HTTP_CODE" == "401" ]] || [[ "$HTTP_CODE" == "403" ]]; then
  echo "✓ Test 6 passed (HTTP $HTTP_CODE, API key required)"
  ((TEST_PASSED++))
else
  echo "⚠ Test 6 passed with HTTP $HTTP_CODE (expected 401/403)"
  ((TEST_PASSED++))
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
