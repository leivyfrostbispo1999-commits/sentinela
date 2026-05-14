#!/usr/bin/env bash
set -euo pipefail

server_url="${K3S_URL:?set K3S_URL, example: https://10.0.0.10:6443}"
token="${K3S_TOKEN:?set K3S_TOKEN from node 1 /var/lib/rancher/k3s/server/node-token}"

if command -v k3s >/dev/null 2>&1; then
  echo "k3s already installed"
  exit 0
fi

curl -sfL https://get.k3s.io | K3S_URL="$server_url" K3S_TOKEN="$token" sh -
