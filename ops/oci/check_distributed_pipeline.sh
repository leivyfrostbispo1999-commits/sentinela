#!/usr/bin/env bash
set -euo pipefail

cd "${SENTINELA_ROOT_DIR:-/home/ubuntu/sentinela}"

docker compose -f docker-compose.eventbus.yml -f docker-compose.ingestion.yml ps

curl -fsS http://127.0.0.1:8222/healthz >/dev/null
docker exec sentinela-parser-engine python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8011/health', timeout=3).read()"
docker exec sentinela-detection-engine python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8012/health', timeout=3).read()"

echo "DISTRIBUTED_PIPELINE_STATUS=ok"

