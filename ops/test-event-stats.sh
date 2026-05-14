#!/usr/bin/env bash
set -euo pipefail
API_URL="${API_URL:-http://127.0.0.1:5000}"
OUT="$(curl -fsS "$API_URL/events/stats")"
echo "$OUT"
python3 - <<'PY' "$OUT"
import json, sys
payload = json.loads(sys.argv[1])
required = [
    "total_accepted", "total_duplicates", "total_rejected", "dlq_pending",
    "dlq_failed", "dlq_resolved", "by_source", "by_event_type",
]
missing = [key for key in required if key not in payload]
if missing:
    raise SystemExit(f"missing keys: {missing}")
if not isinstance(payload["by_source"], dict) or not isinstance(payload["by_event_type"], dict):
    raise SystemExit("by_source/by_event_type must be objects")
for key in required[:6]:
    if not isinstance(payload[key], int):
        raise SystemExit(f"{key} must be int")
print("event stats smoke ok")
PY
