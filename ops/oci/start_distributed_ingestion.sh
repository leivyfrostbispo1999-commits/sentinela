#!/usr/bin/env bash
set -euo pipefail

cd "${SENTINELA_ROOT_DIR:-/home/ubuntu/sentinela}"

if [ ! -f .env ]; then
  secret="$(python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(32))
PY
)"
  printf 'SENTINELA_JWT_SECRET=%s\nSENTINELA_API_TOKEN=%s\n' "$secret" "$secret" > .env
fi

if ! grep -q '^SENTINELA_API_TOKEN=' .env; then
  token="$(python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(32))
PY
)"
  printf '\nSENTINELA_API_TOKEN=%s\n' "$token" >> .env
  echo "Added SENTINELA_API_TOKEN to .env. Restart the core API before enabling detection delivery."
fi

docker network inspect sentinela-event-net >/dev/null 2>&1 || docker network create sentinela-event-net >/dev/null

docker compose -f docker-compose.eventbus.yml up -d
docker compose -f docker-compose.eventbus.yml -f docker-compose.ingestion.yml up -d --build fluent-bit parser_engine detection_engine

docker compose -f docker-compose.eventbus.yml -f docker-compose.ingestion.yml ps
