#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

backup_dir="${SENTINELA_BACKUP_DIR:-/home/ubuntu/sentinela/backups/postgres}"
mkdir -p "$backup_dir"

stamp="$(date -u +%F)"
tmp_file="$backup_dir/sentinela_${stamp}.sql"
final_file="$tmp_file.gz"

if [ -f "$final_file" ]; then
  echo "Backup already exists: $final_file"
  exit 0
fi

docker exec sentinela-db-lite pg_dump -U postgres postgres > "$tmp_file"
gzip -f "$tmp_file"

find "$backup_dir" -type f -name 'sentinela_*.sql.gz' -mtime +6 -delete

echo "Backup written: $final_file"
