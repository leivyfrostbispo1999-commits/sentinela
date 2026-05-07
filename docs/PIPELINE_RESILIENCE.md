# Pipeline Resilience

Fluxo principal:

```text
raw_logs -> rule_engine -> security_alerts -> alert_sink -> PostgreSQL/OpenSearch -> API/WebSocket
```

## Retry estruturado

Variáveis:

```text
PIPELINE_MAX_RETRIES=3
PIPELINE_RETRY_BACKOFF_MS=500
```

`rule_engine` e `alert_sink` registram `pipeline_retry_count` no payload durante retries. Falhas finais são enviadas para a DLQ.

## Dead-letter queue

Tópico padrão:

```text
dead_letter_events
```

Payload DLQ:

```json
{
  "original_event": {},
  "error_message": "erro",
  "error_type": "RuntimeError",
  "failed_service": "rule_engine",
  "failed_at": "2026-05-06T00:00:00Z",
  "retry_count": 3,
  "tenant_id": "default",
  "correlation_id": "cid",
  "source_topic": "raw_logs",
  "target_topic": "security_alerts"
}
```

Métrica:

```promql
sum by (service, topic) (sentinela_dlq_events_total)
```

Inspecionar via Kafka CLI:

```powershell
docker compose exec kafka kafka-console-consumer --bootstrap-server kafka:9092 --topic dead_letter_events --from-beginning --max-messages 10
```

## Backpressure

Variáveis:

```text
PIPELINE_MAX_BATCH_SIZE=100
PIPELINE_CONSUMER_TIMEOUT_MS=1000
PIPELINE_POLL_INTERVAL_MS=250
```

Esses limites evitam consumo ilimitado e dão tempo para o worker respirar entre ciclos de polling.

## Idempotência

`alert_sink` calcula `idempotency_key` por:

- `event_id`, quando presente;
- hash determinístico de tenant, correlation_id, rule_id, timestamp, source e status quando não há `event_id`.

O banco cria índice único em `alertas.idempotency_key` e `incidents.idempotency_key`. OpenSearch usa `idempotency_key` como `document_id` quando disponível.

## Replay

Dry-run por padrão:

```powershell
python scripts/replay_events.py --source dlq --dry-run
python scripts/replay_events.py --source file --file exported-dlq.jsonl --tenant default --limit 10
```

Execução explícita:

```powershell
python scripts/replay_events.py --source dlq --tenant default --limit 10 --execute
```
