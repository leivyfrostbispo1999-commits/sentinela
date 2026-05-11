#!/usr/bin/env bash
set -euo pipefail
source /home/ubuntu/sentinela/ops/common.sh
cd "$ROOT_DIR"
log_line "rebuilding core stack"
compose build --pull
compose up -d
compose ps
