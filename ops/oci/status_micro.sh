#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

echo "== Micro stack =="
docker compose -f docker-compose.micro.yml ps

echo
echo "== Heavy stack =="
docker ps -a \
  --filter "name=sentinela-kafka-heavy" \
  --filter "name=sentinela-jaeger-heavy" \
  --filter "name=sentinela-log-collector-heavy" \
  --filter "name=sentinela-enrichment-heavy" \
  --filter "name=sentinela-rule-engine-heavy" \
  --filter "name=sentinela-alert-sink-heavy" \
  --filter "name=sentinela-simulator-heavy" \
  --filter "name=sentinela-ai-lite-heavy" \
  --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'

echo
echo "== Restart policies =="
docker inspect \
  sentinela-web-lite \
  sentinela-api-lite \
  sentinela-db-lite \
  sentinela-redis-lite \
  --format '{{.Name}} restart={{.HostConfig.RestartPolicy.Name}} status={{.State.Status}}' 2>/dev/null || true

docker inspect \
  sentinela-kafka-heavy \
  sentinela-jaeger-heavy \
  sentinela-log-collector-heavy \
  sentinela-enrichment-heavy \
  sentinela-rule-engine-heavy \
  sentinela-alert-sink-heavy \
  sentinela-simulator-heavy \
  sentinela-ai-lite-heavy \
  --format '{{.Name}} restart={{.HostConfig.RestartPolicy.Name}} status={{.State.Status}}' 2>/dev/null || true

echo
echo "== Memory =="
free -h

echo
echo "== Host port guard =="
ops/oci/check_host_ports.sh
