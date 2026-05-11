#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="${ROOT_DIR:-/home/ubuntu/sentinela}"
cd "$ROOT_DIR"

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

info() {
  echo "== $* =="
}

info "git safety"
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  tracked_runtime="$(git ls-files | grep -E '(^|/)\.env$|^backups/|^logs/|\.log$' || true)"
  if [ -n "$tracked_runtime" ]; then
    echo "$tracked_runtime" >&2
    fail "runtime or secret files are tracked"
  fi
else
  fail "not inside a git work tree"
fi

info "required files"
for file in docker-compose.lite.yml .env.example ops/common.sh ops/start-core.sh ops/healthcheck.sh ops/backup-db.sh ops/test-event-ingest.sh ops/retry-dlq.sh; do
  [ -f "$file" ] || fail "missing $file"
done

info "ops executables"
for script in ops/*.sh; do
  [ -x "$script" ] || fail "$script is not executable"
done

info "compose syntax"
if docker compose version >/dev/null 2>&1; then
  docker compose -f docker-compose.lite.yml config >/dev/null
elif command -v docker-compose >/dev/null 2>&1; then
  docker-compose -f docker-compose.lite.yml config >/dev/null
else
  echo "WARN: Docker Compose is not installed; skipping compose config validation"
fi

info "python syntax"
python3 -m compileall -q services cloud_traffic_sim.py

info "secret placeholders"
if grep -R --exclude-dir=.git --exclude=.env --exclude='*.gz' -nE 'SENTINELA_JWT_SECRET=[A-Za-z0-9_-]{20,}' . >/dev/null 2>&1; then
  fail "possible real SENTINELA_JWT_SECRET committed"
fi

echo "validation ok"
