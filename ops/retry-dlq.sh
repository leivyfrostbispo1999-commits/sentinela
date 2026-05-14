#!/usr/bin/env bash
set -euo pipefail
API_URL="${API_URL:-http://127.0.0.1:5000}"
LIMIT="${1:-10}"
IDS="${2:-}"

payload="{\"limit\": ${LIMIT}}"
if [ -n "$IDS" ]; then
  payload="{\"limit\": ${LIMIT}, \"ids\": [${IDS}]}"
fi

curl -fsS -H 'Content-Type: application/json' -X POST "$API_URL/events/dlq/retry" -d "$payload"
echo
