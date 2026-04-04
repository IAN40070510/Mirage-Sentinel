#!/usr/bin/env bash
set -euo pipefail

cleanup() {
  docker compose down -v --remove-orphans || true
}
trap cleanup EXIT

docker compose up -d --build

bash scripts/ci/smoke.sh \
  --health-url http://127.0.0.1:8000/healthz \
  --openapi-url http://127.0.0.1:8000/openapi.json \
  --banking-url http://127.0.0.1:8000/api/v1/banking/accounts \
  --user-id 000000001 \
  --banking-allow 200,401,403,503 \
  --retries 60 \
  --sleep 2 \
  --compose-cmd "docker compose" \
  --compose-file docker-compose.yml \
  --log-services "app sandbox postgres"
