#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

runtime_dir="ops/oci/runtime"
history_file="${SENTINELA_HOST_METRICS_HISTORY_FILE:-$runtime_dir/host_metrics.jsonl}"
history_retention_days="${SENTINELA_HOST_METRICS_RETENTION_DAYS:-14}"
history_interval_minutes="${SENTINELA_HOST_METRICS_INTERVAL_MINUTES:-5}"
mkdir -p "$runtime_dir"

read -r mem_total mem_used mem_free mem_shared mem_buff mem_available < <(free -m | awk '/^Mem:/ {print $2, $3, $4, $5, $6, $7}')
read -r swap_total swap_used swap_free < <(free -m | awk '/^Swap:/ {print $2, $3, $4}')
disk_used_pct="$(df -P / | awk 'NR==2 {print $5}')"
disk_free_mb="$(df -Pm / | awk 'NR==2 {print $4}')"
load_avg="$(cut -d' ' -f1-3 /proc/loadavg)"
uptime_seconds="$(cut -d. -f1 /proc/uptime)"
generated_at="$(date -u --iso-8601=seconds)"

cat > "$runtime_dir/host_metrics.json" <<JSON
{
  "generated_at": "$generated_at",
  "uptime_seconds": $uptime_seconds,
  "load_avg": "$load_avg",
  "memory_mb": {
    "total": $mem_total,
    "used": $mem_used,
    "free": $mem_free,
    "available": $mem_available
  },
  "swap_mb": {
    "total": $swap_total,
    "used": $swap_used,
    "free": $swap_free
  },
  "disk_root": {
    "used_percent": "$disk_used_pct",
    "free_mb": $disk_free_mb
  }
}
JSON

printf '{"generated_at":"%s","uptime_seconds":%s,"load_avg":"%s","memory_mb":{"total":%s,"used":%s,"free":%s,"available":%s},"swap_mb":{"total":%s,"used":%s,"free":%s},"disk_root":{"used_percent":"%s","free_mb":%s}}\n' \
  "$generated_at" \
  "$uptime_seconds" \
  "$load_avg" \
  "$mem_total" \
  "$mem_used" \
  "$mem_free" \
  "$mem_available" \
  "$swap_total" \
  "$swap_used" \
  "$swap_free" \
  "$disk_used_pct" \
  "$disk_free_mb" >> "$history_file"

max_history_lines=$((history_retention_days * 24 * 60 / history_interval_minutes))
tmp_history="$(mktemp)"
tail -n "$max_history_lines" "$history_file" > "$tmp_history"
mv "$tmp_history" "$history_file"
