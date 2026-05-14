#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

backup_dir="${SENTINELA_BACKUP_DIR:-backups/postgres}"
backup_file="${1:-}"
required_table="${SENTINELA_RESTORE_REQUIRED_TABLE:-alertas}"
result_file="${SENTINELA_RESTORE_RESULT_FILE:-$backup_dir/restore_last.json}"

if [ -z "$backup_file" ]; then
  backup_file="$(ls -1t "$backup_dir"/sentinela_*.sql.gz 2>/dev/null | head -n 1 || true)"
fi

if [ -z "$backup_file" ] || [ ! -f "$backup_file" ]; then
  echo "No backup file found. Expected $backup_dir/sentinela_*.sql.gz" >&2
  exit 1
fi

container="sentinela-restore-verify-$$"
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
  --memory "${SENTINELA_RESTORE_MEMORY:-192m}" \
  --cpus "${SENTINELA_RESTORE_CPUS:-0.25}" \
  postgres:15-alpine >/dev/null

for _ in $(seq 1 30); do
  if docker exec "$container" pg_isready -U postgres -d restore_test >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

docker exec "$container" pg_isready -U postgres -d restore_test >/dev/null
gzip -dc "$backup_file" | docker exec -i "$container" psql -v ON_ERROR_STOP=1 -U postgres -d restore_test >/dev/null

table_count="$(docker exec "$container" psql -U postgres -d restore_test -tAc "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='public';" | tr -d '[:space:]')"
required_exists="$(docker exec "$container" psql -U postgres -d restore_test -tAc "SELECT to_regclass('public.${required_table}') IS NOT NULL;" | tr -d '[:space:]')"

mkdir -p "$(dirname "$result_file")"

if [ "$table_count" -lt 1 ] || [ "$required_exists" != "t" ]; then
  cat > "$result_file" <<JSON
{
  "verified_at": "$(date -u --iso-8601=seconds)",
  "status": "fail",
  "backup_file": "$backup_file",
  "table_count": $table_count,
  "required_table": "$required_table",
  "required_table_exists": $([ "$required_exists" = "t" ] && echo true || echo false)
}
JSON
  echo "Restore validation failed: table_count=$table_count ${required_table}_exists=$required_exists" >&2
  exit 1
fi

cat > "$result_file" <<JSON
{
  "verified_at": "$(date -u --iso-8601=seconds)",
  "status": "ok",
  "backup_file": "$backup_file",
  "table_count": $table_count,
  "required_table": "$required_table",
  "required_table_exists": $([ "$required_exists" = "t" ] && echo true || echo false)
}
JSON

echo "Restore validation OK: backup=$backup_file tables=$table_count ${required_table}_exists=$required_exists"
