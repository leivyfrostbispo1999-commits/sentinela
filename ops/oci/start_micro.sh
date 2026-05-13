#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

if [ ! -f .env ]; then
  umask 077
  secret="$(python3 - <<'PY'
import secrets
print(secrets.token_hex(32))
PY
)"
  printf 'SENTINELA_JWT_SECRET=%s\n' "$secret" > .env
fi

docker update --restart=no sentinela-ai-lite >/dev/null 2>&1 || true
docker rm -f sentinela-ai-lite >/dev/null 2>&1 || true
docker compose -f docker-compose.micro.yml up -d --build --remove-orphans
docker compose -f docker-compose.micro.yml ps
