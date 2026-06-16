# SENTINELA Detection Engine

The detection engine consumes normalized events from NATS and emits operational alerts.

## Rule Format

Rules live in `infra/detection_rules/*.yaml`.

Required fields:

- `id`
- `name`
- `description`
- `severity`
- `condition`
- `mitre.tactic`
- `mitre.technique`
- `mitre.technique_name`

Optional fields:

- `window_seconds`
- `threshold`
- `group_by`
- `score`
- `recommended_action`

Rules are hot-reloaded when YAML files change.

## Current Rules

- SSH brute force
- multiple failed logins
- sudo abuse
- port scan
- reverse shell indicators
- suspicious curl/wget
- persistence indicators

## Alert Delivery

Each alert is published to `sentinela.alerts.detections` and POSTed to the core API at `/ingest/alerts` using the existing `X-SENTINELA-TOKEN` path. If the core API is unavailable, the alert remains on the event bus and a DLQ event is emitted.

