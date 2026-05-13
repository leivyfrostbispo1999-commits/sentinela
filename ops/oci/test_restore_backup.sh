#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

backup_file="${1:-}"
if [ -z "$backup_file" ]; then
  backup_file="$(ls -1t backups/postgres/sentinela_*.sql.gz 2>/dev/null | head -n 1 || true)"
fi

if [ -z "$backup_file" ] || [ ! -f "$backup_file" ]; then
  echo "No backup file found. Expected backups/postgres/sentinela_*.sql.gz" >&2
  exit 1
fi

container="sentinela-restore-test"
docker rm -f "$container" >/dev/null 2>&1 || true

cleanup() {
  docker rm -f "$container" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker run -d \
  --name "$container" \
  --network none \
  -e POSTGRES_PASSWORD=restore-test \
  -e POSTGRES_DB=restore_test \
  --memory 192m \
  --cpus "0.25" \
  postgres:15-alpine >/dev/null

for _ in $(seq 1 30); do
  if docker exec "$container" pg_isready -U postgres -d restore_test >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

docker exec "$container" pg_isready -U postgres -d restore_test >/dev/null
gzip -dc "$backup_file" | docker exec -i "$container" psql -v ON_ERROR_STOP=1 -U postgres -d restore_test >/dev/null

table_count="$(docker exec "$container" psql -U postgres -d restore_test -tAc "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='public';")"
alertas_regclass="$(docker exec "$container" psql -U postgres -d restore_test -tAc "SELECT to_regclass('public.alertas') IS NOT NULL;")"

if [ "$table_count" -lt 1 ] || [ "$alertas_regclass" != "t" ]; then
  echo "Restore validation failed: table_count=$table_count alertas_exists=$alertas_regclass" >&2
  exit 1
fi

echo "Restore validation OK: backup=$backup_file tables=$table_count alertas_exists=$alertas_regclass"
