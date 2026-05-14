# SENTINELA Orchestration Roadmap

The local and Oracle micro deployments remain the low-cost operational baseline. The Kubernetes layer is now the scale/governance path.

## Implemented Tier

- Kubernetes base and prod overlays with Kustomize.
- Kafka queueing as a real StatefulSet, replacing in-process assumptions for distributed workers.
- Multi-replica API, web and worker deployments.
- RBAC via scoped ServiceAccounts and read-only observability Role.
- Default-deny NetworkPolicy with explicit internal, DNS and HTTPS egress rules.
- TLS Ingress boundary using `sentinela-tls`.
- Distributed tracing path through Jaeger OTLP.
- Prometheus pod discovery through scrape annotations.
- Production HPA and PodDisruptionBudgets for API and rule engine.
- Multi-node scheduling through topology spread constraints and pod anti-affinity in the prod overlay.
- Optional internal mTLS overlay through Linkerd policy resources.
- Oracle Free Tier k3s overlay with NATS, short Prometheus retention and node placement for app/data/observability.

## Production Decisions Still Required

- Cluster provider and node pool sizing.
- Managed Postgres versus in-cluster StatefulSet.
- Three-broker Kafka or managed Kafka/NATS.
- Certificate automation with cert-manager.
- Linkerd installation and certificate rotation policy for internal mTLS.
- Image registry naming and release tags.

## Recommended Rollout

1. Deploy `infra/k8s/overlays/dev` in a disposable cluster.
2. Publish images to GHCR using the CI workflow.
3. Replace `sentinela-secrets` and TLS with real secrets.
4. Deploy `infra/k8s/overlays/prod`.
5. Run load tests against `/ready`, `/alertas`, `/ws/alerts` and the Kafka event path.

For Oracle Free Tier experiments, deploy `infra/k8s/overlays/oracle-k3s` instead of `prod`.
