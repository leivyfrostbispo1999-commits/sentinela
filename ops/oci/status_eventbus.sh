#!/usr/bin/env bash
set -euo pipefail

cd "${SENTINELA_ROOT_DIR:-/home/ubuntu/sentinela}"

docker compose -f docker-compose.eventbus.yml ps
docker exec sentinela-eventbus-nats wget -qO- http://127.0.0.1:8222/healthz
echo
docker exec sentinela-eventbus-nats wget -qO- http://127.0.0.1:8222/jsz?streams=true

