# Event Pipeline v1

The first mature ingestion path is intentionally lightweight and compatible with the Oracle lite stack.

## Endpoint

```http
POST /events
Content-Type: application/json
```

Auth follows the dashboard API configuration. In the current lite environment, `ENABLE_AUTH=false`, so the endpoint is available to the operational stack without a login flow.

## Envelope

```json
{
  "schema_version": "sentinela.event.v1",
  "source": "collector-name",
  "tenant_id": "default",
  "idempotency_key": "collector-name:event-123",
  "event": {
    "event_id": "0d4d18ff-ec51-4995-81b9-a88d5998db2c",
    "event_type": "PORT_SCAN",
    "source_ip": "203.0.113.77",
    "score": 55,
    "service": "ssh",
    "port": 22,
    "target_host": "sentinela-api",
    "target_service": "ssh",
    "reasons": ["multiple connection attempts"]
  }
}
```

## Required Fields

- `schema_version`: must be `sentinela.event.v1`.
- `event.event_type`: detection type, normalized to uppercase with underscores.
- `event.source_ip`: source entity used for alerting and correlation.

## Idempotency

`idempotency_key` is stored in `alertas.idempotency_key` and has a unique partial index. Replaying the same event returns:

```json
{"status":"duplicate"}
```

If no idempotency key is provided, the API derives one from the stable event envelope. Producers should still send an explicit key.

## DLQ

Invalid envelopes or persistence failures are recorded in `event_dlq`.

Common rejection reasons:

- `payload_must_be_object`
- `event_must_be_object`
- `unsupported_schema_version:<value>`
- `missing_event_type`
- `missing_source_ip`
- `persist_failed`

Operators can inspect the queue with:

```http
GET /events/dlq
GET /events/dlq?status=pending
```

## Metrics

Prometheus counters:

- `sentinela_event_ingest_total{result,source}`
- `sentinela_dlq_events_total{service}`

## Smoke Test

From the Oracle host:

```bash
cd /home/ubuntu/sentinela
./ops/test-event-ingest.sh
```

## DLQ Retry

Pending or failed DLQ items can be reprocessed without creating duplicates. The retry path reads the original payload, normalizes it again as `sentinela.event.v1`, persists through the same idempotent alert insertion path and then marks the DLQ item as:

- `resolved`: event was accepted and stored.
- `duplicate`: event already exists by `idempotency_key`.
- `failed`: event is still invalid or persistence failed.

API:

```http
POST /events/dlq/retry
Content-Type: application/json

{"limit": 10}
```

Retry specific IDs:

```json
{"limit": 10, "ids": [12, 13]}
```

Operational script:

```bash
cd /home/ubuntu/sentinela
./ops/retry-dlq.sh 10
./ops/retry-dlq.sh 10 "12,13"
```

Metric:

- `sentinela_dlq_retry_total{result}`

## Event Pipeline Observability

Administrative endpoint:

```http
GET /events/stats
```

Response fields:

```json
{
  "total_accepted": 0,
  "total_duplicates": 0,
  "total_rejected": 0,
  "dlq_pending": 0,
  "dlq_failed": 0,
  "dlq_resolved": 0,
  "by_source": {},
  "by_event_type": {}
}
```

Operational script:

```bash
cd /home/ubuntu/sentinela
./ops/event-stats.sh
./ops/test-event-stats.sh
```

Prometheus metrics added for pipeline visibility:

- `sentinela_event_ingest_total{result,source}` for accepted, duplicate, rejected and DLQ outcomes.
- `sentinela_event_ingest_seconds{source,result}` for ingestion latency.
- `sentinela_event_pipeline_total{result}` for database-derived totals.
- `sentinela_events_by_source{source}` for source distribution.
- `sentinela_events_by_event_type{event_type}` for event type distribution.
- `sentinela_dlq_items{status}` for pending, failed and resolved DLQ depth.
- `sentinela_dlq_retry_total{result}` for retry outcomes.
