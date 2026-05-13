#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

backup_dir="${SENTINELA_BACKUP_DIR:-backups/postgres}"
retention_days="${SENTINELA_BACKUP_RETENTION_DAYS:-7}"
container="${SENTINELA_POSTGRES_CONTAINER:-sentinela-db-lite}"
db_name="${POSTGRES_DB:-postgres}"
db_user="${POSTGRES_USER:-postgres}"

mkdir -p "$backup_dir"

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
tmp_file="$backup_dir/sentinela_${stamp}.sql.tmp"
sql_file="$backup_dir/sentinela_${stamp}.sql"
final_file="$sql_file.gz"
manifest_file="$final_file.manifest.json"

cleanup() {
  rm -f "$tmp_file" "$sql_file"
}
trap cleanup EXIT

if ! docker inspect "$container" >/dev/null 2>&1; then
  echo "Postgres container not found: $container" >&2
  exit 1
fi

docker exec "$container" pg_dump -U "$db_user" "$db_name" > "$tmp_file"
mv "$tmp_file" "$sql_file"
gzip -f "$sql_file"

sha256="$(sha256sum "$final_file" | awk '{print $1}')"
bytes="$(wc -c < "$final_file" | tr -d ' ')"

cat > "$manifest_file" <<JSON
{
  "created_at": "$(date -u --iso-8601=seconds)",
  "backup_file": "$final_file",
  "sha256": "$sha256",
  "bytes": $bytes,
  "postgres_container": "$container",
  "database": "$db_name",
  "user": "$db_user",
  "retention_days": $retention_days
}
JSON

find "$backup_dir" -type f \( -name 'sentinela_*.sql.gz' -o -name 'sentinela_*.sql.gz.manifest.json' \) -mtime +"$((retention_days - 1))" -delete

echo "Backup written: $final_file"
echo "Manifest written: $manifest_file"
