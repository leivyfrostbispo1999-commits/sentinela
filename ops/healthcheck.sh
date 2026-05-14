#!/usr/bin/env bash
set -euo pipefail
source /home/ubuntu/sentinela/ops/common.sh
cd "$ROOT_DIR"
mkdir -p "$LOG_DIR"
STATUS=0
{
  echo "===== $(date -Is) healthcheck ====="
  echo "-- containers --"
  compose ps
  echo "-- api --"
  curl -fsS --max-time 5 http://127.0.0.1:5000/health || STATUS=1
  echo
  echo "-- web --"
  curl -fsSI --max-time 5 http://127.0.0.1/ | sed -n '1,5p' || STATUS=1
  echo "-- postgres --"
  docker exec sentinela-db-lite pg_isready -U postgres -d postgres || STATUS=1
  echo "-- redis --"
  docker exec sentinela-redis-lite redis-cli ping || STATUS=1
} >> "$LOG_DIR/healthcheck.log" 2>&1
if [ "$STATUS" -ne 0 ]; then
  log_line "healthcheck failed"
  if [ "${AUTO_RECOVER:-0}" = "1" ]; then
    log_line "AUTO_RECOVER=1, running recover"
    "$ROOT_DIR/ops/recover.sh" || true
  fi
else
  log_line "healthcheck ok"
fi
exit "$STATUS"
