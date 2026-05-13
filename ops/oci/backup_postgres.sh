#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

export SENTINELA_BACKUP_DIR="${SENTINELA_BACKUP_DIR:-/home/ubuntu/sentinela/backups/postgres}"
export SENTINELA_BACKUP_RETENTION_DAYS="${SENTINELA_BACKUP_RETENTION_DAYS:-7}"

exec ops/recovery/backup_postgres.sh "$@"
