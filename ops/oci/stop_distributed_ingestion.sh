#!/usr/bin/env bash
set -euo pipefail

cd "${SENTINELA_ROOT_DIR:-/home/ubuntu/sentinela}"
docker compose -f docker-compose.ingestion.yml stop fluent-bit parser_engine detection_engine
docker compose -f docker-compose.ingestion.yml rm -f fluent-bit parser_engine detection_engine
docker compose -f docker-compose.eventbus.yml ps

