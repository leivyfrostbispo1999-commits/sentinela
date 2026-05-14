#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

# Intentionally does not pass -v. Heavy test volumes and the micro Postgres
# volume must not be deleted by this script.
docker compose -f docker-compose.heavy.yml --profile heavy stop
docker compose -f docker-compose.heavy.yml --profile heavy rm -f
docker compose -f docker-compose.micro.yml ps
