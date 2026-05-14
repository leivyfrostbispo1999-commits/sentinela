#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

status=0
backup_dir="${SENTINELA_BACKUP_DIR:-backups/postgres}"
backup_max_age_hours="${SENTINELA_BACKUP_MAX_AGE_HOURS:-36}"
restore_result_file="${SENTINELA_RESTORE_RESULT_FILE:-$backup_dir/restore_last.json}"
restore_max_age_hours="${SENTINELA_RESTORE_MAX_AGE_HOURS:-168}"
metrics_file="${SENTINELA_HOST_METRICS_FILE:-ops/oci/runtime/host_metrics.json}"
metrics_history_file="${SENTINELA_HOST_METRICS_HISTORY_FILE:-ops/oci/runtime/host_metrics.jsonl}"

fail() {
  echo "FAIL $*"
  status=1
}

ok() {
  echo "OK   $*"
}

check_container() {
  local name="$1" state health
  if ! docker inspect "$name" >/dev/null 2>&1; then
    fail "$name is missing"
    return
  fi

  state="$(docker inspect "$name" --format '{{.State.Status}}')"
  health="$(docker inspect "$name" --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}')"
  if [ "$state" != "running" ]; then
    fail "$name state=$state"
    return
  fi
  if [ "$health" != "healthy" ]; then
    fail "$name health=$health"
    return
  fi
  ok "$name running and healthy"
}

check_recent_file() {
  local file="$1" max_hours="$2" label="$3"
  if [ ! -f "$file" ]; then
    fail "$label missing: $file"
    return
  fi
  if find "$file" -mmin "-$((max_hours * 60))" | grep -q .; then
    ok "$label recent: $file"
  else
    fail "$label older than ${max_hours}h: $file"
  fi
}

latest_backup="$(find "$backup_dir" -type f -name 'sentinela_*.sql.gz' -printf '%T@ %p\n' 2>/dev/null | sort -nr | awk 'NR==1 {print $2}')"

echo "===== SENTINELA RECOVERY CHECK $(date -u --iso-8601=seconds) ====="
for name in sentinela-web-lite sentinela-api-lite sentinela-db-lite sentinela-redis-lite; do
  check_container "$name"
done

if [ -n "$latest_backup" ]; then
  check_recent_file "$latest_backup" "$backup_max_age_hours" "latest Postgres backup"
else
  fail "no Postgres backup found in $backup_dir"
fi

check_recent_file "$restore_result_file" "$restore_max_age_hours" "restore validation result"
check_recent_file "$metrics_file" 1 "host metrics snapshot"
check_recent_file "$metrics_history_file" 24 "host metrics history"

if [ "$status" -eq 0 ]; then
  echo "RECOVERY_CHECK_STATUS=ok"
else
  echo "RECOVERY_CHECK_STATUS=fail"
fi

exit "$status"
