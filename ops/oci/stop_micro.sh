#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

# Intentionally does not pass -v. The Postgres named volume must be preserved.
docker compose -f docker-compose.micro.yml stop
docker compose -f docker-compose.micro.yml ps
