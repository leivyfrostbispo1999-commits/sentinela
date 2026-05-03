# SENTINELA SOC

Mini-SIEM educacional/profissional com arquitetura inspirada em ambientes reais de SOC.

O SENTINELA demonstra um pipeline completo de segurança: geração e coleta de eventos, ingestão via Kafka, detecção por regras, correlação temporal, Threat Intelligence, persistência em PostgreSQL, métricas Prometheus e dashboard SOC em tempo real.

Este projeto não pretende substituir plataformas como Splunk, Elastic, QRadar ou Wazuh. O objetivo é demonstrar maturidade técnica, organização de código e domínio dos componentes centrais de um pipeline SIEM moderno.

## Architecture

```text
simulator / log_collector
        |
        v
Kafka topic: raw_logs
        |
        v
rule_engine
        |
        v
Kafka topic: security_alerts
        |
        v
alert_sink
        |
        v
PostgreSQL
        |
        v
dashboard_api
        |
        v
dashboard_web
```

## Features

- Event-driven architecture with Kafka.
- Raw event ingestion through `raw_logs`.
- Enriched alert publication through `security_alerts`.
- Rule-based detection with configurable YAML rules.
- Temporal and multidimensional correlation by IP, service, port and event type.
- Local and simulated external Threat Intelligence.
- Risk scoring based on event type, sensitive ports, frequency, sequence and IOC match.
- Safe automated response using `simulated_block`.
- PostgreSQL persistence with backward-compatible schema evolution.
- REST API with token authentication.
- Prometheus-compatible `/metrics` endpoint.
- SOC dashboard with filters, search, ranking, analytics, attack map and drill-down.

## Services

| Service | Role |
| --- | --- |
| `kafka` | Event broker for raw logs and enriched alerts. |
| `db` | PostgreSQL database for alert history. |
| `log_collector` | Produces baseline log events into Kafka. |
| `simulator` | Generates normal traffic, bursts, IOCs and attack sequences. |
| `rule_engine` | Applies YAML rules, correlation, Threat Intelligence and risk scoring. |
| `alert_sink` | Consumes enriched alerts and persists them in PostgreSQL. |
| `dashboard_api` | Exposes alert, health and metrics endpoints. |
| `dashboard_web` | Static SOC dashboard served by Nginx. |

## Requirements

- Docker
- Docker Compose

## Running Locally

```powershell
docker compose up -d --build
```

Check containers:

```powershell
docker ps
```

Read recent logs:

```powershell
docker compose logs --tail=120
```

Open the dashboard:

```text
http://localhost:8080
```

## Endpoints

| Endpoint | Description | Authentication |
| --- | --- | --- |
| `GET /health` | API and database health check. | No |
| `GET /alertas?range=5m` | Alerts from the selected time range. | Yes |
| `GET /alertas?range=1h` | Alerts from the selected time range. | Yes |
| `GET /metrics` | Prometheus-compatible metrics. | Yes |

Base API URL:

```text
http://localhost:5000
```

Supported alert ranges:

- `5m`
- `15m`
- `1h`
- `24h`

## Authentication

Protected endpoints accept the token using either header:

```text
X-SENTINELA-TOKEN: sentinela-demo-token
```

or:

```text
Authorization: Bearer sentinela-demo-token
```

The token is configured with:

```text
SENTINELA_API_TOKEN=sentinela-demo-token
```

The dashboard sends the token automatically in API requests.

## Detection Rules

Rules are configured in:

```text
services/rule_engine/rules.yaml
```

Supported fields:

- `name`
- `enabled`
- `priority`
- `description`
- `conditions`
- `threshold`
- `window_seconds`
- `min_risk`
- `risk`
- `status`
- `tags`

The rule engine ignores disabled rules, applies higher priority matches first and uses a safe fallback rule set if the YAML file is invalid.

## Simulated Blocking

Real blocking is intentionally disabled:

```text
ENABLE_BLOCK=false
```

No real firewall or `iptables` action is executed. High-risk events are marked with:

```text
simulated_block=true
```

This keeps the demo safe while still showing how SOC response logic could be represented.

## Observability

The API exposes Prometheus-format metrics at:

```text
http://localhost:5000/metrics
```

Metrics include:

- `sentinela_events_total`
- `sentinela_critical_events_total`
- `sentinela_ioc_events_total`
- `sentinela_events_by_type_total`

A reference Prometheus configuration is available at:

```text
infra/prometheus/prometheus.yml
```

## Technology Stack

- Python
- Flask
- Kafka
- PostgreSQL
- Docker Compose
- Nginx
- HTML, CSS and JavaScript
- Chart.js
- Prometheus client library
- YAML-based rules

## Repository Structure

```text
services/
  alert-sink/
  dashboard_api/
  dashboard_web/
  log_collector/
  rule_engine/
  simulator/

docs/
infra/
scripts/
docker-compose.yml
README.md
.gitignore
```

## Honest Limitations

- Kafka runs as a single broker for local demonstration.
- Correlation state is local and in memory.
- External Threat Intelligence is simulated for safe portfolio usage.
- Authentication is token-based and intentionally simple.
- There is no RBAC, multi-tenancy or production-grade identity provider.
- There is no schema registry or formal dead-letter queue yet.
- Prometheus is documented and configured, but not added to Compose by default.

## Next Steps

- Add Kafka multi-broker support with planned partitions and replication.
- Add schema validation and dead-letter topics.
- Move correlation state to Redis, Kafka Streams or another state store.
- Add Alembic or another versioned migration tool.
- Add automated tests for detection and API behavior.
- Add optional Prometheus and Grafana services to Docker Compose.
- Add load testing with throughput, latency and consumer lag metrics.
