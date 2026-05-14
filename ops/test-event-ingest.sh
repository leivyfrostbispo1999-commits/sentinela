#!/usr/bin/env bash
set -euo pipefail
API_URL="${API_URL:-http://127.0.0.1:5000}"
IDEMPOTENCY_KEY="ops-smoke-$(date +%Y%m%d%H%M%S)"
EVENT_ID="$(python3 - <<'PY'
import uuid
print(uuid.uuid4())
PY
)"

post_event() {
  local payload="$1"
  curl -fsS -H 'Content-Type: application/json' -X POST "$API_URL/events" -d "$payload"
}

valid_payload="$(cat <<JSON
{
  "schema_version": "sentinela.event.v1",
  "source": "ops_smoke_test",
  "idempotency_key": "$IDEMPOTENCY_KEY",
  "event": {
    "event_id": "$EVENT_ID",
    "event_type": "PORT_SCAN",
    "source_ip": "203.0.113.77",
    "score": 55,
    "service": "ssh",
    "port": 22,
    "target_host": "sentinela-smoke",
    "target_service": "ssh",
    "reasons": ["ops smoke test"]
  }
}
JSON
)"

first="$(post_event "$valid_payload")"
echo "first=$first"
echo "$first" | grep -q '"status":"accepted"\|"status": "accepted"'

second="$(post_event "$valid_payload")"
echo "second=$second"
echo "$second" | grep -q '"status":"duplicate"\|"status": "duplicate"'

invalid_payload='{"schema_version":"sentinela.event.v1","source":"ops_smoke_test","event":{"source_ip":"203.0.113.77"}}'
status_code="$(curl -sS -o /tmp/sentinela-invalid-event.json -w '%{http_code}' -H 'Content-Type: application/json' -X POST "$API_URL/events" -d "$invalid_payload")"
cat /tmp/sentinela-invalid-event.json
[ "$status_code" = "400" ]
grep -q '"dlq_id"' /tmp/sentinela-invalid-event.json
DLQ_ID="$(python3 - <<'PYJSON'
import json
with open('/tmp/sentinela-invalid-event.json', 'r', encoding='utf-8') as fh:
    print(json.load(fh).get('dlq_id', ''))
PYJSON
)"

if [ "${CLEANUP:-1}" = "1" ] && command -v docker >/dev/null 2>&1; then
  docker exec sentinela-db-lite psql -U postgres -d postgres -v ON_ERROR_STOP=1     -c "DELETE FROM alertas WHERE idempotency_key = '$IDEMPOTENCY_KEY';"     -c "UPDATE event_dlq SET status = 'resolved', updated_at = NOW() WHERE id = $DLQ_ID;" >/dev/null
fi

echo "event ingest smoke ok"
