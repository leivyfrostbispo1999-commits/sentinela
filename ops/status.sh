#!/usr/bin/env bash
set -euo pipefail
source /home/ubuntu/sentinela/ops/common.sh
cd "$ROOT_DIR"
echo "== compose ps =="
compose ps
echo
echo "== api health =="
curl -fsS --max-time 5 http://127.0.0.1:5000/health || true
echo
echo "== web =="
curl -fsSI --max-time 5 http://127.0.0.1/ | sed -n '1,8p' || true
