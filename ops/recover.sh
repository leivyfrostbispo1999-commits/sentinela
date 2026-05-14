#!/usr/bin/env bash
set -euo pipefail
source /home/ubuntu/sentinela/ops/common.sh
cd "$ROOT_DIR"
log_line "recover requested"
compose up -d
sleep 5
"$ROOT_DIR/ops/healthcheck.sh"
