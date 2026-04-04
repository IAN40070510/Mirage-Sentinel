#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${1:-http://127.0.0.1:8000}"
API_BASE="${BASE_URL%/}"
if [[ "$API_BASE" != */api/v1 ]]; then
  API_BASE="$API_BASE/api/v1"
fi
USER_ID="CIF000000001"
FROM_ACCOUNT="ACC000000000001"
UNAUTHORIZED_TO_ACCOUNT="ACC999999999999"

assert_status() {
  local expected="$1"
  local actual="$2"
  local name="$3"
  local body_file="$4"

  if [ "$actual" != "$expected" ]; then
    echo "[authz] ERROR: ${name} expected=${expected}, actual=${actual}"
    echo "[authz] response body:"
    cat "$body_file" || true
    exit 1
  fi

  echo "[authz] ${name} passed (status=${actual})"
}

# Ensure endpoint is reachable with a valid role.
status_ok=$(curl -sS -A "Mozilla/5.0" -o /tmp/authz_beneficiaries_ok.json -w "%{http_code}" \
  -H "X-User-Id: ${USER_ID}" \
  -H "X-Actor-Role: customer" \
  "${API_BASE}/banking/beneficiaries")
assert_status "200" "$status_ok" "beneficiaries customer role" "/tmp/authz_beneficiaries_ok.json"

# Admin role should also pass role gate.
status_admin_ok=$(curl -sS -A "Mozilla/5.0" -o /tmp/authz_beneficiaries_admin_ok.json -w "%{http_code}" \
  -H "X-User-Id: ${USER_ID}" \
  -H "X-Actor-Role: admin" \
  "${API_BASE}/banking/beneficiaries")
assert_status "200" "$status_admin_ok" "beneficiaries admin role" "/tmp/authz_beneficiaries_admin_ok.json"

# Missing role should fall back to default customer role.
status_default_role=$(curl -sS -A "Mozilla/5.0" -o /tmp/authz_beneficiaries_default_role.json -w "%{http_code}" \
  -H "X-User-Id: ${USER_ID}" \
  "${API_BASE}/banking/beneficiaries")
assert_status "200" "$status_default_role" "beneficiaries default role" "/tmp/authz_beneficiaries_default_role.json"

# Role gate must reject SOC role for customer banking operations.
status_forbidden=$(curl -sS -A "Mozilla/5.0" -o /tmp/authz_beneficiaries_forbidden.json -w "%{http_code}" \
  -H "X-User-Id: ${USER_ID}" \
  -H "X-Actor-Role: soc" \
  "${API_BASE}/banking/beneficiaries")
assert_status "403" "$status_forbidden" "beneficiaries role gate" "/tmp/authz_beneficiaries_forbidden.json"

# Role format should be strictly validated.
status_invalid_role=$(curl -sS -A "Mozilla/5.0" -o /tmp/authz_invalid_role.json -w "%{http_code}" \
  -H "X-User-Id: ${USER_ID}" \
  -H "X-Actor-Role: hacker" \
  "${API_BASE}/banking/beneficiaries")
assert_status "422" "$status_invalid_role" "beneficiaries invalid role" "/tmp/authz_invalid_role.json"

# Transfer destination must be authorized (owned account or beneficiary).
status_transfer_forbidden=$(curl -sS -A "Mozilla/5.0" -o /tmp/authz_transfer_forbidden.json -w "%{http_code}" \
  -X POST "${API_BASE}/banking/transfers" \
  -H "Content-Type: application/json" \
  -H "X-User-Id: ${USER_ID}" \
  -H "X-Actor-Role: customer" \
  -H "Idempotency-Key: authz-smoke-001" \
  -d "{\"from_account\":\"${FROM_ACCOUNT}\",\"to_account\":\"${UNAUTHORIZED_TO_ACCOUNT}\",\"amount\":100,\"note\":\"authz-smoke\"}")
assert_status "403" "$status_transfer_forbidden" "transfer object-level authorization" "/tmp/authz_transfer_forbidden.json"

echo "[authz] authorization smoke checks completed successfully"
