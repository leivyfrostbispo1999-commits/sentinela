#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

status=0
backup_dir="${SENTINELA_BACKUP_DIR:-/home/ubuntu/sentinela/backups/postgres}"
backup_max_age_hours="${SENTINELA_BACKUP_MAX_AGE_HOURS:-36}"
metrics_file="${SENTINELA_HOST_METRICS_FILE:-ops/oci/runtime/host_metrics.json}"
metrics_max_age_minutes="${SENTINELA_HOST_METRICS_MAX_AGE_MINUTES:-15}"

fail() {
  echo "FAIL $*"
  status=1
}

ok() {
  echo "OK   $*"
}

check_micro_containers() {
  local name state health
  for name in sentinela-web-lite sentinela-api-lite sentinela-db-lite sentinela-redis-lite; do
    if ! docker inspect "$name" >/dev/null 2>&1; then
      fail "$name is missing"
      continue
    fi

    state="$(docker inspect "$name" --format '{{.State.Status}}')"
    health="$(docker inspect "$name" --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}')"
    if [ "$state" != "running" ]; then
      fail "$name state=$state"
      continue
    fi
    if [ "$health" != "healthy" ]; then
      fail "$name health=$health"
      continue
    fi
    ok "$name running and healthy"
  done
}

check_heavy_stack_stopped() {
  local running
  running="$(docker ps \
    --filter "name=sentinela-kafka-heavy" \
    --filter "name=sentinela-jaeger-heavy" \
    --filter "name=sentinela-log-collector-heavy" \
    --filter "name=sentinela-enrichment-heavy" \
    --filter "name=sentinela-rule-engine-heavy" \
    --filter "name=sentinela-alert-sink-heavy" \
    --filter "name=sentinela-simulator-heavy" \
    --filter "name=sentinela-ai-lite-heavy" \
    --format '{{.Names}}' | sed '/^$/d')"

  if [ -n "$running" ]; then
    fail "heavy stack containers are running: $(echo "$running" | paste -sd ',' -)"
  else
    ok "heavy stack is not running"
  fi
}

check_backup_recent() {
  local max_minutes latest
  max_minutes=$((backup_max_age_hours * 60))
  if [ ! -d "$backup_dir" ]; then
    fail "backup directory missing: $backup_dir"
    return
  fi

  latest="$(find "$backup_dir" -type f -name 'sentinela_*.sql.gz' -printf '%T@ %p\n' 2>/dev/null | sort -nr | awk 'NR==1 {print $2}')"
  if [ -z "$latest" ]; then
    fail "no Postgres backup found in $backup_dir"
    return
  fi

  if find "$backup_dir" -type f -name 'sentinela_*.sql.gz' -mmin "-$max_minutes" | grep -q .; then
    ok "recent Postgres backup exists: $latest"
  else
    fail "latest Postgres backup is older than ${backup_max_age_hours}h: $latest"
  fi
}

check_metrics_recent() {
  if [ ! -f "$metrics_file" ]; then
    fail "host metrics file missing: $metrics_file"
    return
  fi

  if find "$metrics_file" -mmin "-$metrics_max_age_minutes" | grep -q .; then
    ok "host metrics are recent: $metrics_file"
  else
    fail "host metrics are older than ${metrics_max_age_minutes}m: $metrics_file"
  fi
}

check_cron_entries() {
  local cron
  cron="$(crontab -l 2>/dev/null || true)"
  for item in \
    "ops/oci/watchdog_micro.sh" \
    "ops/oci/write_host_metrics.sh" \
    "ops/oci/backup_postgres.sh" \
    "ops/oci/test_restore_backup.sh"; do
    if echo "$cron" | grep -q "$item"; then
      ok "cron contains $item"
    else
      fail "cron missing $item"
    fi
  done
}

echo "===== SENTINELA DR CHECK $(date -u --iso-8601=seconds) ====="
check_micro_containers
check_heavy_stack_stopped
ops/oci/check_host_ports.sh || status=1
check_backup_recent
check_metrics_recent
check_cron_entries

if [ "$status" -eq 0 ]; then
  echo "DR_CHECK_STATUS=ok"
else
  echo "DR_CHECK_STATUS=fail"
fi

exit "$status"
