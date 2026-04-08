#!/usr/bin/env bash
set -euo pipefail

health_urls=()
openapi_url=""
banking_url=""
user_id="000000001"
banking_allow="200"
retries=30
sleep_seconds=3
compose_cmd=""
compose_file=""
log_services=""

usage() {
  echo "Usage: $0 --health-url URL [--health-url URL] --openapi-url URL [--banking-url URL] [options]"
  echo "Options:"
  echo "  --user-id VALUE"
  echo "  --banking-allow CSV_STATUS_CODES (default: 200)"
  echo "  --retries N (default: 30)"
  echo "  --sleep N (default: 3)"
  echo "  --compose-cmd CMD"
  echo "  --compose-file FILE"
  echo "  --log-services \"svc1 svc2\""
}

fail() {
  local msg="$1"
  echo "[smoke] ERROR: ${msg}"
  if [ -n "${compose_cmd}" ] && [ -n "${compose_file}" ]; then
    ${compose_cmd} -f "${compose_file}" ps || true
    if [ -n "${log_services}" ]; then
      ${compose_cmd} -f "${compose_file}" logs --tail=200 ${log_services} || true
    fi
  fi
  exit 1
}

contains_code() {
  local code="$1"
  local list="${banking_allow},"
  case "${list}" in
    *"${code},"*) return 0 ;;
    *) return 1 ;;
  esac
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --health-url)
      health_urls+=("$2")
      shift 2
      ;;
    --openapi-url)
      openapi_url="$2"
      shift 2
      ;;
    --banking-url)
      banking_url="$2"
      shift 2
      ;;
    --user-id)
      user_id="$2"
      shift 2
      ;;
    --banking-allow)
      banking_allow="$2"
      shift 2
      ;;
    --retries)
      retries="$2"
      shift 2
      ;;
    --sleep)
      sleep_seconds="$2"
      shift 2
      ;;
    --compose-cmd)
      compose_cmd="$2"
      shift 2
      ;;
    --compose-file)
      compose_file="$2"
      shift 2
      ;;
    --log-services)
      log_services="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage
      fail "unknown argument: $1"
      ;;
  esac
done

if [ "${#health_urls[@]}" -eq 0 ] || [ -z "${openapi_url}" ]; then
  usage
  fail "missing required arguments"
fi

if [ -n "${banking_url}" ] && ! [[ "${user_id}" =~ ^CIF[0-9]{9}$ ]]; then
  echo "[smoke] WARN: --user-id '${user_id}' is not in CIF format (expected CIF + 9 digits)."
  echo "[smoke] WARN: Banking endpoint may auto-divert to deception_auth and skew smoke expectations."
fi

for i in $(seq 1 "${retries}"); do
  all_ok=1
  for health_url in "${health_urls[@]}"; do
    if ! curl -fsS "${health_url}" >/dev/null 2>&1; then
      all_ok=0
      break
    fi
  done

  if [ "${all_ok}" -eq 1 ]; then
    echo "[smoke] health checks passed"
    break
  fi

  if [ "${i}" -eq "${retries}" ]; then
    fail "health checks failed after ${retries} attempts"
  fi

  sleep "${sleep_seconds}"
done

openapi_code=$(curl -sS -o /tmp/openapi.json -w "%{http_code}" "${openapi_url}" || true)
if [ "${openapi_code}" != "200" ]; then
  fail "openapi returned status ${openapi_code}"
fi
python3 -m json.tool /tmp/openapi.json >/dev/null 2>&1 || fail "openapi.json is not valid JSON"
test -s /tmp/openapi.json || fail "openapi.json is empty"
echo "[smoke] openapi check passed"

if [ -n "${banking_url}" ]; then
  banking_code=$(curl -sS -o /tmp/banking_accounts.json -w "%{http_code}" -H "X-User-Id: ${user_id}" "${banking_url}" || true)
  if ! contains_code "${banking_code}"; then
    echo "[smoke] banking response body:"
    cat /tmp/banking_accounts.json || true
    fail "banking returned unexpected status ${banking_code}; allow=${banking_allow}"
  fi
  python3 -m json.tool /tmp/banking_accounts.json >/dev/null 2>&1 || fail "banking response is not valid JSON"
  echo "[smoke] banking check passed (status=${banking_code})"
else
  echo "[smoke] banking check skipped (no --banking-url provided)"
fi

echo "[smoke] smoke checks completed successfully"
