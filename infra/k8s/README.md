# SENTINELA Kubernetes

This directory contains the next operational tier for SENTINELA: Kubernetes orchestration, real Kafka-backed queues, namespace RBAC, network policy, TLS ingress, distributed telemetry and multi-node scaling controls.

## Layout

- `base/`: portable manifests for the full SENTINELA control plane.
- `overlays/dev/`: local or staging overlay with `sentinela.local`.
- `overlays/prod/`: production overlay with HPA and PodDisruptionBudgets.
- `overlays/oracle-k3s/`: Oracle Free Tier overlay with NATS, lower resource limits and node placement.
- `overlays/mtls-linkerd/`: production plus Linkerd injection and mesh-only policy for internal mTLS.

## Required Secrets

Replace `base/secret.example.yaml` values before deploying. For production, prefer an external secret manager and generate the Kubernetes secret out of band:

```bash
kubectl -n sentinela create secret generic sentinela-secrets \
  --from-literal=DB_PASSWORD='...' \
  --from-literal=SENTINELA_API_TOKEN='...' \
  --from-literal=SENTINELA_JWT_SECRET='...' \
  --from-literal=SENTINELA_USERS_JSON='[...]' \
  --from-literal=GRAFANA_ADMIN_PASSWORD='...'
```

Create TLS separately:

```bash
kubectl -n sentinela create secret tls sentinela-tls \
  --cert=fullchain.pem \
  --key=privkey.pem
```

## Validate

```bash
kubectl kustomize infra/k8s/base >/tmp/sentinela-base.yaml
kubectl kustomize infra/k8s/overlays/prod >/tmp/sentinela-prod.yaml
kubectl kustomize infra/k8s/overlays/oracle-k3s >/tmp/sentinela-oracle-k3s.yaml
kubectl kustomize infra/k8s/overlays/mtls-linkerd >/tmp/sentinela-mtls.yaml
```

## Deploy

```bash
kubectl apply -k infra/k8s/overlays/prod
kubectl -n sentinela rollout status deploy/sentinela-api
kubectl -n sentinela rollout status deploy/sentinela-rule-engine
kubectl -n sentinela get pods -o wide
```

For Oracle Free Tier k3s:

```bash
kubectl apply -k infra/k8s/overlays/oracle-k3s
```

For internal mTLS, install Linkerd first, then deploy:

```bash
kubectl apply -k infra/k8s/overlays/mtls-linkerd
```

## Operational Notes

- Kafka is deployed as a KRaft StatefulSet. The base is single-broker for cost control; scale to three brokers with a matching quorum change before production HA.
- The Oracle k3s overlay uses NATS JetStream instead of Kafka to keep memory pressure low.
- Postgres and Redis are StatefulSets with PVCs. For high availability, move them to managed services or add operator-managed clusters.
- NetworkPolicy defaults to deny and permits only internal SENTINELA traffic, DNS and outbound HTTPS.
- Ingress terminates public TLS. Internal service-to-service encryption is available through `overlays/mtls-linkerd`.
