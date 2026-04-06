#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${1:-http://127.0.0.1:8000}"
API_BASE="${BASE_URL%/}"
if [[ "$API_BASE" != */api/v1 ]]; then
  API_BASE="$API_BASE/api/v1"
fi

USER_ID="${2:-CIF000000001}"
UA="${3:-sqlmap/1.8}"

TEST_PASSED=0
TEST_FAILED=0

assert_true() {
  local cond="$1"
  local message="$2"
  if [ "$cond" = "true" ]; then
    echo "[deception-auth] PASS: ${message}"
    TEST_PASSED=$((TEST_PASSED + 1))
  else
    echo "[deception-auth] FAIL: ${message}"
    TEST_FAILED=$((TEST_FAILED + 1))
  fi
}

assert_status() {
  local expected="$1"
  local actual="$2"
  local name="$3"
  local body_file="$4"

  if [ "$actual" != "$expected" ]; then
    echo "[deception-auth] ERROR: ${name} expected=${expected}, actual=${actual}"
    echo "[deception-auth] response body:"
    cat "$body_file" || true
    TEST_FAILED=$((TEST_FAILED + 1))
    return 1
  fi

  echo "[deception-auth] ${name} passed (status=${actual})"
  TEST_PASSED=$((TEST_PASSED + 1))
  return 0
}

# Auto-diversion check: unauthorized + suspicious request on business endpoint
# must be redirected into deceptive auth challenge response.
auto_divert_status=$(curl -sS -A "$UA" -o /tmp/deception_auth_autodivert.json -w "%{http_code}" \
  -X GET "${API_BASE}/banking/accounts")
assert_status "200" "$auto_divert_status" "auto-divert from accounts endpoint" "/tmp/deception_auth_autodivert.json"

auto_route=$(jq -r '.route // empty' /tmp/deception_auth_autodivert.json)
auto_stage=$(jq -r '.stage // empty' /tmp/deception_auth_autodivert.json)
auto_flow_id=$(jq -r '.auth_flow_id // empty' /tmp/deception_auth_autodivert.json)
auto_source=$(jq -r '.source_endpoint // empty' /tmp/deception_auth_autodivert.json)

assert_true "$([ "$auto_route" = "deception_auth" ] && echo true || echo false)" "auto-divert route is deception_auth"
assert_true "$([ "$auto_stage" = "credential_challenge" ] && echo true || echo false)" "auto-divert stage is credential_challenge"
assert_true "$([ -n "$auto_flow_id" ] && echo true || echo false)" "auto-divert auth_flow_id is present"
assert_true "$([ "$auto_source" = "accounts" ] && echo true || echo false)" "auto-divert source endpoint recorded"

start_status=$(curl -sS -A "$UA" -o /tmp/deception_auth_start.json -w "%{http_code}" \
  -X POST "${API_BASE}/banking/auth/login" \
  -H "Content-Type: application/json" \
  -H "X-User-Id: ${USER_ID}" \
  -d '{"username":"audit-user","device_id":"dev-smoke-01"}')
assert_status "200" "$start_status" "start deceptive login" "/tmp/deception_auth_start.json"

flow_id=$(jq -r '.auth_flow_id // empty' /tmp/deception_auth_start.json)
stage=$(jq -r '.stage // empty' /tmp/deception_auth_start.json)
strategy=$(jq -r '.deception_meta.strategy // empty' /tmp/deception_auth_start.json)
hints_count=$(jq -r '(.consistency_hints // []) | length' /tmp/deception_auth_start.json)

assert_true "$([ -n "$flow_id" ] && echo true || echo false)" "auth_flow_id is present"
assert_true "$([ "$stage" = "credential_challenge" ] && echo true || echo false)" "stage is credential_challenge"
assert_true "$([ "$strategy" = "counter_ai_tarpit" ] && echo true || echo false)" "counter-AI strategy active"
assert_true "$([ "$hints_count" -gt 0 ] && echo true || echo false)" "semantic noise payload exists"

verify1_status=$(curl -sS -A "$UA" -o /tmp/deception_auth_verify1.json -w "%{http_code}" \
  -X POST "${API_BASE}/banking/auth/login/${flow_id}/verify" \
  -H "Content-Type: application/json" \
  -H "X-User-Id: ${USER_ID}" \
  -d '{"password":"P@ssw0rd-ignored","device_fingerprint":"fp-smoke"}')
assert_status "200" "$verify1_status" "advance to otp challenge" "/tmp/deception_auth_verify1.json"

stage1=$(jq -r '.stage // empty' /tmp/deception_auth_verify1.json)
assert_true "$([ "$stage1" = "otp_challenge" ] && echo true || echo false)" "stage transitioned to otp_challenge"

verify2_status=$(curl -sS -A "$UA" -o /tmp/deception_auth_verify2.json -w "%{http_code}" \
  -X POST "${API_BASE}/banking/auth/login/${flow_id}/verify" \
  -H "Content-Type: application/json" \
  -H "X-User-Id: ${USER_ID}" \
  -d '{"otp":"123456"}')
assert_status "200" "$verify2_status" "advance to security challenge" "/tmp/deception_auth_verify2.json"

stage2=$(jq -r '.stage // empty' /tmp/deception_auth_verify2.json)
assert_true "$([ "$stage2" = "security_question" ] && echo true || echo false)" "stage transitioned to security_question"

verify3_status=$(curl -sS -A "$UA" -o /tmp/deception_auth_verify3.json -w "%{http_code}" \
  -X POST "${API_BASE}/banking/auth/login/${flow_id}/verify" \
  -H "Content-Type: application/json" \
  -H "X-User-Id: ${USER_ID}" \
  -d '{"security_answer":"mock-answer"}')
assert_status "200" "$verify3_status" "advance to manual review" "/tmp/deception_auth_verify3.json"

stage3=$(jq -r '.stage // empty' /tmp/deception_auth_verify3.json)
status3=$(jq -r '.status // empty' /tmp/deception_auth_verify3.json)
assert_true "$([ "$stage3" = "manual_review" ] && echo true || echo false)" "stage transitioned to manual_review"
assert_true "$([ "$status3" = "queued_review" ] && echo true || echo false)" "final status is queued_review"

echo "[deception-auth] completed. passed=${TEST_PASSED}, failed=${TEST_FAILED}"
if [ "$TEST_FAILED" -gt 0 ]; then
  exit 1
fi
