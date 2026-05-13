#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

export SENTINELA_BACKUP_DIR="${SENTINELA_BACKUP_DIR:-/home/ubuntu/sentinela/backups/postgres}"
exec ops/recovery/verify_restore.sh "$@"
