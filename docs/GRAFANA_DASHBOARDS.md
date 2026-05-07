# Grafana Dashboards

O SENTINELA 7.0 provisiona Grafana automaticamente via Docker Compose.

## Acesso

```powershell
docker compose up -d --build
```

- Grafana: http://localhost:3000
- Usuário: `GRAFANA_ADMIN_USER` ou `admin`
- Senha: `GRAFANA_ADMIN_PASSWORD` ou `sentinela`

## Provisioning

- Datasource: `infra/grafana/provisioning/datasources/prometheus.yml`
- Dashboards: `infra/grafana/dashboards/*.json`

Dashboards disponíveis:

- `SENTINELA 7.0 - Operational Overview`
- `SENTINELA 7.0 - Operational Maturity`

## Painéis principais

- Kafka / Pipeline: consumo por tópico, consumer lag, DLQ events.
- API / Latência: throughput, p95 por rota, erros HTTP e 429.
- SOC / Alertas: alertas, incidentes, severidade e eventos por tenant.
- Realtime / WebSocket: conexões ativas.

## Validação

```powershell
curl http://localhost:9090/-/ready
curl http://localhost:3000/api/health
curl http://localhost:5000/metrics
```

Consultas úteis no Prometheus:

```promql
sum(rate(sentinela_dashboard_http_requests_total[5m]))
histogram_quantile(0.95, sum by (le, endpoint, method) (rate(sentinela_dashboard_request_seconds_bucket[5m])))
sum(sentinela_dlq_events_total)
sum(sentinela_rate_limited_requests_total)
sum by (tenant_id) (sentinela_processed_events_by_tenant)
kafka_consumergroup_lag
```
