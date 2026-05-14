#!/usr/bin/env bash
set -euo pipefail

forbidden_ports="${SENTINELA_FORBIDDEN_HOST_PORTS:-5000 5432 6379}"
pattern="$(printf '%s\n' $forbidden_ports | sed 's/^/:/' | paste -sd '|' -)"

if [ -z "$pattern" ]; then
  echo "No forbidden host ports configured"
  exit 0
fi

matches="$(ss -tulpen 2>/dev/null | grep -E "$pattern" || true)"
if [ -n "$matches" ]; then
  echo "Forbidden host ports are listening:"
  echo "$matches"
  exit 1
fi

echo "Forbidden host ports closed: $forbidden_ports"
