#!/usr/bin/env bash
set -euo pipefail
API_URL="${API_URL:-http://127.0.0.1:5000}"
curl -fsS "$API_URL/events/stats"
echo
