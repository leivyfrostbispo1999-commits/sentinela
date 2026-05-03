# SENTINELA Demo Script

## 1. Start the Environment

```powershell
docker compose up -d --build
docker ps
docker compose logs --tail=120
```

## 2. Open the SOC Dashboard

```text
http://localhost:8080
```

Explain that the dashboard is a static SOC interface consuming a protected API.

## 3. Explain the Architecture

```text
simulator/log_collector -> Kafka raw_logs -> rule_engine -> Kafka security_alerts -> alert_sink -> PostgreSQL -> dashboard_api -> dashboard_web
```

Kafka separates ingestion from detection and persistence.

## 4. Show Normal Events

Use the feed and charts to show low-risk events mixed with suspicious activity. Explain that normal traffic is preserved and not every event becomes a critical incident.

## 5. Show Attack Correlation

Point to alerts with high risk, repeated IPs, sensitive ports and correlation fields:

- `correlation_key`
- `correlation_reason`

## 6. Show Threat Intelligence

Filter or inspect alerts with:

- `threat_intel_match=true`
- `threat_source=local`
- `threat_source=external`

Explain that the external source is simulated for safe demo usage.

## 7. Show Simulated Blocking

Open a high-risk alert and show:

```text
simulated_block=true
```

Explain that real blocking is intentionally disabled:

```text
ENABLE_BLOCK=false
```

## 8. Show Observability

Query:

```powershell
Invoke-WebRequest `
  -Uri "http://localhost:5000/metrics" `
  -Headers @{ "Authorization" = "Bearer sentinela-demo-token" }
```

Explain that Prometheus can collect these metrics using `infra/prometheus/prometheus.yml`.

## 9. Close the Presentation

Position the project as a practical demonstration of SOC engineering, event-driven architecture, detection logic, safe response automation and production-oriented documentation.
