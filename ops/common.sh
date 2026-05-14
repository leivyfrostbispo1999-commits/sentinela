#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="/home/ubuntu/sentinela"
COMPOSE_FILE="$ROOT_DIR/docker-compose.lite.yml"
LOG_DIR="$ROOT_DIR/logs"
BACKUP_DIR="$ROOT_DIR/backups"
PROJECT_NAME="sentinela"

compose() {
  if docker compose version >/dev/null 2>&1; then
    docker compose -f "$COMPOSE_FILE" "$@"
  else
    docker-compose -f "$COMPOSE_FILE" "$@"
  fi
}

log_line() {
  mkdir -p "$LOG_DIR"
  printf '%s %s\n' "$(date -Is)" "$*" | tee -a "$LOG_DIR/ops.log"
}
