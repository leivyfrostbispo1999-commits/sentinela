#!/usr/bin/env bash
set -euo pipefail

if command -v k3s >/dev/null 2>&1; then
  echo "k3s already installed"
  sudo kubectl get nodes -o wide || true
  exit 0
fi

curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC="server --disable traefik --write-kubeconfig-mode=644" sh -

echo
echo "K3S_TOKEN:"
sudo cat /var/lib/rancher/k3s/server/node-token
echo
echo "NODE_INTERNAL_IP:"
hostname -I | awk '{print $1}'
echo
sudo kubectl get nodes -o wide
