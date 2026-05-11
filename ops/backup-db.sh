#!/usr/bin/env bash
set -euo pipefail
source /home/ubuntu/sentinela/ops/common.sh
cd "$ROOT_DIR"
mkdir -p "$BACKUP_DIR/db" "$BACKUP_DIR/config"
chmod 700 "$BACKUP_DIR"
TS="$(date +%Y%m%d-%H%M%S)"
DB_OUT="$BACKUP_DIR/db/postgres-$TS.sql.gz"
CFG_OUT="$BACKUP_DIR/config/config-$TS.tar.gz"
log_line "backup started"
docker exec sentinela-db-lite pg_dump -U postgres -d postgres | gzip -9 > "$DB_OUT"
tar --ignore-failed-read -czf "$CFG_OUT" \
  docker-compose.lite.yml \
  .env .env.production .env.lite \
  config infra 2>/dev/null || true
chmod 600 "$DB_OUT" "$CFG_OUT" 2>/dev/null || true
find "$BACKUP_DIR/db" -type f -name 'postgres-*.sql.gz' -mtime +14 -delete
find "$BACKUP_DIR/config" -type f -name 'config-*.tar.gz' -mtime +30 -delete
log_line "backup finished db=$DB_OUT config=$CFG_OUT"
ls -lh "$DB_OUT" "$CFG_OUT"
