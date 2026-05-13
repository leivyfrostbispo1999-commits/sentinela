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

O retry agora usa backoff exponencial com prioridade:

- eventos `high` voltam mais cedo que `medium` e `low`
- o payload carrega `event_schema_version`, `pipeline_priority`, `max_retry_count` e `next_retry_at`
- o breaker do pipeline abre após falhas consecutivas para evitar loop agressivo de reconexão

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
  "target_topic": "security_alerts",
  "pipeline_priority": "high",
  "event_schema_version": "sentinela.event.v2",
  "max_retry_count": 3,
  "next_retry_at": "2026-05-06T00:00:05Z",
  "retry_strategy": "exponential_backoff"
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

## Circuit breaker

`rule_engine` e `alert_sink` mantêm um breaker local com recuperação temporizada. Quando o backend fica instável, o serviço pausa novas tentativas por um intervalo curto antes de reabrir a execução.

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
