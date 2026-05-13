#!/usr/bin/env bash
set -euo pipefail

api_url="${SENTINELA_API_READY_URL:-http://127.0.0.1/ready}"
web_url="${SENTINELA_WEB_HEALTH_URL:-http://127.0.0.1/health}"

if ! curl -fsS --max-time 5 "$api_url" >/dev/null; then
  echo "$(date -u --iso-8601=seconds) restarting sentinela-api-lite"
  docker restart sentinela-api-lite >/dev/null
fi

if ! curl -fsS --max-time 5 "$web_url" >/dev/null; then
  echo "$(date -u --iso-8601=seconds) restarting sentinela-web-lite"
  docker restart sentinela-web-lite >/dev/null
fi
