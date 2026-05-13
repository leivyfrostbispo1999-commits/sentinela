#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

chmod +x ops/oci/backup_postgres.sh ops/oci/watchdog_micro.sh ops/oci/write_host_metrics.sh

tmp_cron="$(mktemp)"
crontab -l 2>/dev/null \
  | grep -v 'sentinela/ops/oci/backup_postgres.sh' \
  | grep -v 'sentinela/ops/oci/watchdog_micro.sh' \
  | grep -v 'sentinela/ops/oci/write_host_metrics.sh' \
  | grep -v 'sentinela/ops/healthcheck.sh' \
  | grep -v 'sentinela/ops/backup-db.sh' \
  > "$tmp_cron" || true
cat >> "$tmp_cron" <<'CRON'
*/2 * * * * /home/ubuntu/sentinela/ops/oci/watchdog_micro.sh >> /home/ubuntu/sentinela/ops/oci/watchdog.log 2>&1
*/5 * * * * /home/ubuntu/sentinela/ops/oci/write_host_metrics.sh >/dev/null 2>&1
17 3 * * * /home/ubuntu/sentinela/ops/oci/backup_postgres.sh >> /home/ubuntu/sentinela/ops/oci/backup.log 2>&1
CRON
crontab "$tmp_cron"
rm -f "$tmp_cron"

ops/oci/write_host_metrics.sh
crontab -l | grep 'sentinela/ops/oci'
