#!/usr/bin/env bash
set -euo pipefail

root_dir="${SENTINELA_ROOT_DIR:-/home/ubuntu/sentinela}"
allowed_client_cidr="${SENTINELA_EVENTBUS_ALLOWED_CLIENT_CIDR:-10.0.1.237/32}"
compose_file="${SENTINELA_EVENTBUS_COMPOSE_FILE:-docker-compose.eventbus.yml}"

if ! command -v docker >/dev/null 2>&1; then
  sudo apt-get update
  sudo apt-get install -y ca-certificates curl gnupg
  sudo install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  sudo chmod a+r /etc/apt/keyrings/docker.gpg
  . /etc/os-release
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $VERSION_CODENAME stable" |
    sudo tee /etc/apt/sources.list.d/docker.list >/dev/null
  sudo apt-get update
  sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  sudo usermod -aG docker ubuntu || true
fi

cd "$root_dir"

if [ ! -f "$compose_file" ]; then
  echo "Compose file not found: $root_dir/$compose_file" >&2
  exit 2
fi

sudo ufw allow 22/tcp
sudo ufw allow from "$allowed_client_cidr" to any port 4222 proto tcp
sudo ufw --force enable

docker compose -f "$compose_file" up -d
docker compose -f "$compose_file" ps

echo "Event bus ready on NATS port 4222 for $allowed_client_cidr"

