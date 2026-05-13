#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

runtime_dir="ops/oci/runtime"
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
