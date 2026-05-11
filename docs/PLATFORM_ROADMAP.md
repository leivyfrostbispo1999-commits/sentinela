# SENTINELA Platform Roadmap

This repository is the Oracle operational checkpoint for the SENTINELA lite stack. The goal is to evolve it without breaking the current production-like baseline running on a small VPS.

## Current Baseline

- Dashboard API, dashboard web, AI lite engine, Postgres and Redis run on Oracle with Docker Compose.
- Postgres and Redis use named persistent volumes.
- Operations scripts live in `ops/`.
- Healthcheck and database backup run from cron.
- Secrets, logs and backups are not versioned.
- GitHub receives the live Oracle checkpoint, not the obsolete local Docker Desktop stack.

## Guardrails

- Do not run `docker compose down` as part of routine changes.
- Do not commit `.env`, backups, logs or local runtime state.
- Prefer incremental platform improvements over large rewrites.
- Keep the lite stack viable on a constrained VPS.
- Every architecture expansion must include rollback and data lifecycle notes.

## Priority 1: Event Pipeline Maturity

Target: make event handling resilient before adding heavier infrastructure.

Planned capabilities:

- Event schema versioning.
- Idempotency keys on ingestion and response actions.
- Retry policy with bounded exponential backoff.
- Dead letter queue for poison events.
- Priority queues for critical alerts.
- Backpressure signals when the database or workers lag.
- Circuit breaker around downstream enrichments and SOAR actions.

First implementation slice:

- Define event envelope v1.
- Add DLQ table or Redis stream for failed events.
- Add operational metrics for retry count, DLQ depth and dropped events.

## Priority 2: Investigation Workspace

Target: move from alert viewing to analyst workflow.

Planned capabilities:

- Incident queue.
- Timeline per incident.
- Alert pivots by IP, service, user, technique and campaign.
- IOC expansion.
- Analyst notes and audit history.
- Incident evidence list.

First implementation slice:

- Add API endpoints for incident timeline and pivots.
- Extend dashboard with a compact incident workspace view.

## Priority 3: ATT&CK Heatmap

Target: show detection coverage and gaps.

Planned capabilities:

- Technique coverage summary.
- Heatmap by tactic and technique.
- Detection count per technique.
- Gap list for missing or weak coverage.
- Defensive score over time.

First implementation slice:

- Normalize MITRE technique fields already present in alerts and incidents.
- Add a `/attack/coverage` API endpoint.
- Add a dashboard panel for tactic coverage.

## Priority 4: Observability

Target: understand service health and latency without opening containers manually.

Planned capabilities:

- Service-level metrics.
- API latency and error budget.
- Worker lag.
- Redis and Postgres checks.
- Trace correlation IDs in logs.
- Optional Prometheus/Grafana/Jaeger profile for non-lite deployments.

First implementation slice:

- Expand `/metrics` and `ops/healthcheck.sh` outputs.
- Add dashboard API health fields for schema, DB, Redis and version.

## Priority 5: Internal Security

Target: protect the SENTINELA platform itself.

Planned capabilities:

- RBAC and multiuser flows.
- JWT rotation strategy.
- Secret management outside Compose files.
- Rate limiting.
- Audit trail for analyst and automation actions.
- Container hardening.
- Network segmentation.

First implementation slice:

- Keep secrets in `.env` only.
- Add CI checks that reject committed secrets and runtime state.
- Add an audit event for sensitive API operations.

## Later Tracks

- Kafka and OpenSearch profile for enterprise ingestion and search.
- Threat hunting with behavioral timelines and campaign correlation.
- Detection DSL and Sigma conversion.
- Offensive simulator with replayable TTP scenarios.
- CI/CD with deploy, rollback and security scans.
- Data lifecycle: retention, compression and archive snapshots.
- Multi-tenant isolation and per-tenant RBAC.
- AI operations: triage summaries and SOC hypothesis generation.
- High availability with replication and failover.
