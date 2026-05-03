# SENTINELA Executive Report

## Overview

SENTINELA is a professional educational mini-SIEM designed to demonstrate core SOC engineering concepts with a practical, containerized architecture.

## Architecture

The system uses Kafka to decouple event ingestion from detection and persistence:

```text
simulator/log_collector -> Kafka raw_logs -> rule_engine -> Kafka security_alerts -> alert_sink -> PostgreSQL -> dashboard_api -> dashboard_web
```

## Detection

The `rule_engine` evaluates YAML rules, temporal windows, event frequency, event sequence, sensitive ports and Threat Intelligence matches. Alerts are enriched with risk, status, correlation fields and safe response indicators.

## Threat Intelligence

The project includes local IOCs and simulated external intelligence with caching. Matches produce category, description and source fields.

## Response Model

Real blocking is disabled by design. The system uses `simulated_block=true` to show response decisions without changing firewall rules or host networking.

## Observability

The API exposes Prometheus-compatible metrics for total events, critical events, IOC matches and event distribution by type.

## Professional Value

The project demonstrates:

- Kafka-based event pipelines.
- Python backend engineering.
- SOC detection logic.
- Correlation and enrichment.
- PostgreSQL persistence.
- Secure demo defaults.
- Dashboard-oriented security analytics.
- Honest production-readiness documentation.
