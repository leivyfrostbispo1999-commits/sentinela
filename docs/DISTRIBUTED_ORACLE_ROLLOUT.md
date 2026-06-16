# SENTINELA Distributed Oracle Rollout

This rollout keeps the current Oracle micro VM as the stable core and adds heavier capabilities only as separate nodes.

## Phase 1 - Micro Core

Active baseline:

- VM: `SENTINELA-AMD-TEST`
- Public URL: `http://163.176.204.190`
- Private IP: `10.0.1.237`
- Allowed continuous services: dashboard web, dashboard API, Postgres and Redis.

Guardrails:

- Do not run heavy services continuously on the micro VM.
- Do not run `docker compose down -v`, `docker volume rm` or `docker system prune` without a fresh backup and explicit confirmation.
- Keep host ports `5000`, `5432` and `6379` closed.
- Run `./ops/oci/dr_check.sh` after operational changes.

## Phase 2 - Event Bus Node

Target node:

- Display name: `SENTINELA-EVENTBUS-A1`
- Shape: `VM.Standard.A1.Flex`
- Initial size: 1 OCPU / 4 GB RAM
- Boot volume: 50 GB
- Service: NATS JetStream

Why NATS first:

- Lower memory footprint than Kafka or Redpanda.
- Good fit for Oracle Free Tier auxiliary capacity.
- Gives the platform a real distributed event backbone without moving Postgres or Redis off the core.

Provisioning status on 2026-05-16:

- A1 creation was attempted in `sa-saopaulo-1`.
- OCI returned `Out of host capacity`.
- No auxiliary VM was created.
- The micro core remained unchanged and healthy.

When capacity is available:

```bash
oci --config-file D:\sentinela\.oci_config_local compute instance launch \
  --availability-domain "azjY:SA-SAOPAULO-1-AD-1" \
  --compartment-id ocid1.tenancy.oc1..aaaaaaaaxj36xd4zxt736myrcqov7su3pymsenr6hvyqdgu7yrkehfdr6u2a \
  --shape VM.Standard.A1.Flex \
  --shape-config file://D:\sentinela\ops\oci\sentinela-arm-shape-1x4.json \
  --source-details file://D:\sentinela\ops\oci\sentinela-arm-source-50gb.json \
  --subnet-id ocid1.subnet.oc1.sa-saopaulo-1.aaaaaaaaln7edugffsegjonsy776slps2xv7ojiesanjku3zsh64o7punpaa \
  --assign-public-ip true \
  --vnic-display-name sentinela-eventbus-vnic \
  --metadata file://D:\sentinela\ops\oci\sentinela-arm-metadata.json \
  --display-name SENTINELA-EVENTBUS-A1 \
  --wait-for-state RUNNING
```

Bootstrap on the new node:

```bash
cd /home/ubuntu/sentinela
SENTINELA_EVENTBUS_ALLOWED_CLIENT_CIDR=10.0.1.237/32 ./ops/oci/bootstrap_eventbus_node.sh
./ops/oci/status_eventbus.sh
```

Security rule:

- Allow SSH only for administration.
- Allow NATS `4222/tcp` only from the micro core private IP `10.0.1.237/32`.
- Keep NATS monitoring `8222/tcp` bound to localhost.

## Phase 3 - Threat Hunting Node

Add OpenSearch only after the event bus node exists and is stable.

Target:

- Dedicated node or larger A1 capacity.
- `ENABLE_OPENSEARCH=true` only for services that need search.
- Keep dashboard API fallback to Postgres available.
- Define retention before ingestion volume grows.

Do not run OpenSearch continuously on the micro VM.

## Phase 4 - Graph Analysis Node

Add Neo4j after threat hunting is stable.

Target:

- Dedicated graph node.
- Graph engine consumes event/alert streams and writes relationships to Neo4j.
- API reads graph data through `NEO4J_URI`.

Do not colocate Neo4j with Postgres on the micro VM.

## Operating Principle

The SENTINELA should be a distributed ecosystem:

- Micro core stays small and recoverable.
- Event bus absorbs traffic and decouples producers from workers.
- Threat hunting search scales independently.
- Graph analysis stays optional and isolated.

