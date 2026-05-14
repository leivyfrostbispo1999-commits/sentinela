#!/usr/bin/env bash
set -euo pipefail
source /home/ubuntu/sentinela/ops/common.sh
cd "$ROOT_DIR"
TAIL="${1:-100}"
compose logs -f --tail="$TAIL"
