#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
overlay="${SENTINELA_K8S_OVERLAY:-infra/k8s/overlays/oracle-k3s}"

cd "$root_dir"

kubectl apply -f infra/k8s/base/namespace.yaml

if ! kubectl -n sentinela get secret sentinela-secrets >/dev/null 2>&1; then
  credential_file="${HOME}/.sentinela-k3s-credentials"
  admin_password="${SENTINELA_ADMIN_PASSWORD:-$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 24)}"
  db_password="${SENTINELA_DB_PASSWORD:-$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 32)}"
  api_token="${SENTINELA_API_TOKEN:-$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 48)}"
  jwt_secret="${SENTINELA_JWT_SECRET:-$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 48)}"
  grafana_password="${GRAFANA_ADMIN_PASSWORD:-$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 24)}"
  admin_hash="$(
    SENTINELA_ADMIN_PASSWORD="$admin_password" python3 - <<'PY'
import base64
import hashlib
import os

password = os.environ["SENTINELA_ADMIN_PASSWORD"]
salt = base64.urlsafe_b64encode(os.urandom(16)).decode().rstrip("=")
digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 200000)
encoded = base64.urlsafe_b64encode(digest).decode().rstrip("=")
print(f"pbkdf2_sha256$200000${salt}${encoded}")
PY
  )"
  users_json="$(printf '[{"username":"admin","password_hash":"%s","role":"admin","tenant_id":"default"}]' "$admin_hash")"

  kubectl -n sentinela create secret generic sentinela-secrets \
    --from-literal=DB_PASSWORD="$db_password" \
    --from-literal=SENTINELA_API_TOKEN="$api_token" \
    --from-literal=SENTINELA_JWT_SECRET="$jwt_secret" \
    --from-literal=SENTINELA_USERS_JSON="$users_json" \
    --from-literal=GRAFANA_ADMIN_PASSWORD="$grafana_password"

  umask 077
  {
    printf 'SENTINELA_ADMIN_USER=admin\n'
    printf 'SENTINELA_ADMIN_PASSWORD=%s\n' "$admin_password"
    printf 'GRAFANA_ADMIN_USER=admin\n'
    printf 'GRAFANA_ADMIN_PASSWORD=%s\n' "$grafana_password"
  } >"$credential_file"
  echo "Credenciais iniciais salvas em $credential_file"
fi

kubectl kustomize "$overlay" >/tmp/sentinela-oracle-k3s.yaml
kubectl apply -k "$overlay"

kubectl -n sentinela rollout status deployment/sentinela-api --timeout=240s
kubectl -n sentinela rollout status deployment/sentinela-web --timeout=240s
kubectl -n sentinela get pods -o wide
kubectl -n sentinela get svc
