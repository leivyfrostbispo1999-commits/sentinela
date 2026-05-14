#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

./ops/oci/start_micro.sh
docker compose -f docker-compose.heavy.yml --profile heavy up -d --build
docker update --restart=no \
  sentinela-kafka-heavy \
  sentinela-jaeger-heavy \
  sentinela-log-collector-heavy \
  sentinela-enrichment-heavy \
  sentinela-rule-engine-heavy \
  sentinela-alert-sink-heavy \
  sentinela-simulator-heavy \
  sentinela-ai-lite-heavy >/dev/null 2>&1 || true
docker compose -f docker-compose.heavy.yml --profile heavy ps
