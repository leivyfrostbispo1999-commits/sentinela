# SENTINELA k3s Oracle Free Tier

This runbook deploys the lightweight Kubernetes tier for Oracle Free Tier. Keep the current Docker micro VM as stable production unless the new cluster has been validated.

## Target Topology

- Node 1: `sentinela-role=app`, k3s server, ingress, API, dashboard, workers, NATS.
- Node 2: `sentinela-role=data`, PostgreSQL and Redis.
- Node 3: `sentinela-role=observability`, Prometheus and Grafana.

Do not install this stack on the existing 1 GB micro VM. It is for three Ampere A1 nodes or equivalent.

## OCI Security List

Allow:

- TCP: 22, 80, 443, 6443, 10250
- UDP: 8472, 51820, 51821

Restrict `6443` and `10250` to the VCN/private CIDR whenever possible.

## Node 1

```bash
cd /home/ubuntu/sentinela
./ops/oci/k3s_server_install.sh
```

Save the token and private IP printed by the script.

## Node 2 and Node 3

```bash
export K3S_URL=https://NODE1_PRIVATE_IP:6443
export K3S_TOKEN='TOKEN_FROM_NODE1'
cd /home/ubuntu/sentinela
./ops/oci/k3s_worker_join.sh
```

## Label Nodes

On node 1:

```bash
export SENTINELA_APP_NODE='node-1-name'
export SENTINELA_DATA_NODE='node-2-name'
export SENTINELA_OBS_NODE='node-3-name'
./ops/oci/k3s_label_nodes.sh
```

## Addons

```bash
./ops/oci/k3s_install_addons.sh
```

## Secrets

Replace demo values before public exposure:

```bash
kubectl create namespace sentinela --dry-run=client -o yaml | kubectl apply -f -
kubectl -n sentinela create secret generic sentinela-secrets \
  --from-literal=DB_PASSWORD='replace-me' \
  --from-literal=SENTINELA_API_TOKEN='replace-me' \
  --from-literal=SENTINELA_JWT_SECRET='replace-me' \
  --from-literal=SENTINELA_USERS_JSON='[{"username":"admin","password_hash":"pbkdf2:replace-me","role":"admin","tenant_id":"default"}]' \
  --from-literal=GRAFANA_ADMIN_PASSWORD='replace-me' \
  --dry-run=client -o yaml | kubectl apply -f -
```

## Deploy SENTINELA

```bash
./ops/oci/k3s_deploy_sentinela.sh
```

## Validate

```bash
kubectl get nodes -o wide
kubectl -n sentinela get pods -o wide
kubectl -n sentinela get statefulsets
kubectl -n sentinela get hpa
kubectl top nodes
kubectl top pods -A
```

## Optional Linkerd

Install Linkerd only after the base cluster is stable:

```bash
curl -sL https://run.linkerd.io/install | sh
export PATH="$PATH:$HOME/.linkerd2/bin"
linkerd install | kubectl apply -f -
linkerd check
kubectl apply -k infra/k8s/overlays/mtls-linkerd
```

## Free Tier Limits

Avoid OpenSearch, large Kafka clusters, long Prometheus retention, and broad exporter sprawl in this tier. Use `infra/k8s/overlays/oracle-k3s`, which uses NATS, short Prometheus retention, and one replica by default.
