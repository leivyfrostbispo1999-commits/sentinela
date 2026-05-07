# Observabilidade, Kafka Exporter e Busca

## Servicos

- Prometheus: `http://localhost:9090`
- Grafana: `http://localhost:3000`
- Kafka exporter: `kafka_exporter:9308` dentro da rede Docker
- OpenSearch: perfil opcional `search`, `http://localhost:9200`

## Metricas

Endpoint da API:

```powershell
curl http://localhost:5000/metrics
```

Metricas principais:

- `sentinela_dashboard_http_requests_total`
- `sentinela_dashboard_request_seconds`
- `sentinela_dashboard_http_errors_total`
- `sentinela_alerts_stored_total`
- `sentinela_incidents_stored_total`
- `sentinela_websocket_connections`
- `sentinela_processed_events_by_tenant`
- `sentinela_kafka_messages_consumed_total`
- `sentinela_kafka_consumer_lag`

Consultas Prometheus uteis:

```text
rate(sentinela_dashboard_http_requests_total[5m])
histogram_quantile(0.95, rate(sentinela_dashboard_request_seconds_bucket[5m]))
sentinela_alerts_stored_total
sentinela_processed_events_by_tenant
kafka_consumergroup_lag
kafka_topic_partition_current_offset
```

## Kafka Exporter

O servico `kafka_exporter` usa `danielqsj/kafka-exporter` e aponta para `kafka:9092`.

Validacao:

```powershell
docker compose up -d kafka kafka_exporter prometheus
curl http://localhost:9090/api/v1/targets
```

Metricas esperadas:

- `kafka_brokers`
- `kafka_topic_partition_current_offset`
- `kafka_consumergroup_current_offset`
- `kafka_consumergroup_lag`

## OpenSearch

OpenSearch fica desligado do caminho padrao e sobe por perfil:

```powershell
docker compose --profile search up -d opensearch
```

Ative indexacao:

```powershell
$env:ENABLE_OPENSEARCH="true"
$env:OPENSEARCH_URL="http://opensearch:9200"
docker compose --profile search up -d --build alert_sink dashboard_api opensearch
```

Indices:

- `sentinela-alerts`

Campos indexados:

- `id`
- `tenant_id`
- `correlation_id`
- `severity`
- `status`
- `source`
- `rule_id`
- `timestamp`
- `description`
- `evidence`
- `event_type`
- `mitre_id`

Busca via API:

```powershell
curl "http://localhost:5000/search?q=BRUTE_FORCE" -H "Authorization: Bearer <JWT>"
```

Com `ENABLE_OPENSEARCH=true`, a API tenta OpenSearch. Se OpenSearch estiver indisponivel, cai automaticamente para Postgres e retorna `backend: "postgres"`.

Consulta direta:

```powershell
curl "http://localhost:9200/sentinela-alerts/_search?q=BRUTE_FORCE"
```

## Troubleshooting

- `backend=postgres`: OpenSearch esta desligado, indisponivel ou sem indice.
- Sem metricas Kafka: verifique `docker compose ps kafka_exporter`.
- Lag alto: consumidores estao atrasados; confira `rule_engine` e `alert_sink`.
- Prometheus sem target: valide `infra/prometheus/prometheus.yml` e `docker compose config`.
