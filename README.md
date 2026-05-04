# Sentinela SOC 6.0

Sentinela SOC 6.0 é um mini-SIEM educacional/profissional com arquitetura inspirada em ambientes reais de SOC.

O projeto demonstra um pipeline completo de segurança: geração e coleta de eventos, ingestão via Kafka, detecção por regras YAML, correlação temporal com state store Redis, Threat Intelligence, persistência em PostgreSQL, autenticação por token/JWT, métricas Prometheus e dashboard SOC em tempo real.

Ele não pretende substituir Splunk, Elastic, QRadar, Wazuh ou outra plataforma corporativa. O objetivo é demonstrar maturidade técnica, organização de código, segurança por padrão e capacidade de evolução.

## What's New in 6.0

- Incidentes persistidos em tabelas próprias (`incidents`, `incident_alerts`, `incident_audit_log`) com `PATCH /incidents/{incident_id}` seguro para status, notas, responsável e ação SOC simulada.
- Correlação multi-IP/multi-entidade por `source_ip`, destino, usuário, serviço/porta, MITRE, replay e janela temporal.
- Investigação por IP refinada com resumo do analista, incidentes relacionados, timeline técnica e recomendações defensivas.
- Timeline narrativa com fases `RECONNAISSANCE`, `CREDENTIAL_ACCESS`, `IOC_MATCH`, `ESCALATION`, `CORRELATION` e `RESPONSE_SIMULATED`.
- Endpoint `/rules` para visualizar regras YAML carregadas, MITRE, score, threshold e status enabled/disabled.
- Endpoint `/metrics` com métricas JSON reais para dashboard; Prometheus permanece em `/metrics/prometheus` ou `/metrics?format=prometheus`.
- Endpoints SOC explícitos: `/alerts`, `/incidents`, `/campaigns`, `/metrics/timeline` e `/metrics/summary`.
- Separação operacional entre evento bruto, alerta interpretado por regra, incidente investigável e campanha agregada.
- Score explicável por fatores (`score_breakdown` e `score_explanation`) e resposta SOC sempre marcada como simulação.
- Relatórios Markdown e PDF profissional com alertas relacionados, notas do analista e recomendações defensivas.
- Replay seguro com cenários: `brute_force`, `port_scan`, `ioc_match`, `critical_chain`, `false_positive`, `multi_ip` e `multi_ip_campaign`.
- Dashboard polido para portfólio com aviso de ambiente local/demo e nenhum bloqueio real.

## Foundation

- Redis como state store do `rule_engine`, com fallback automático para memória.
- Autenticação JWT HMAC-SHA256 mantendo compatibilidade com `X-SENTINELA-TOKEN`.
- Endpoint `/auth/token` para emissão de JWT de demo usando o token legado.
- Testes com `pytest` para scoring, detecção, autenticação e `simulated_block`.
- GitHub Actions com `pytest` e `py_compile`.
- Serviço Redis adicionado ao Docker Compose.
- Profile educacional `kafka-lab` com broker Kafka adicional sem quebrar o modo single broker.
- Modo de demonstração de incidente com botão `Simular Ataque` e `Incident Timeline`.
- Toggle visual `DEMO / HISTÓRICO` no dashboard.
- Score acumulativo por IP com severidade `LOW`, `MEDIUM`, `HIGH` e `CRITICAL`.
- Replay seguro de ataque simulado via `scripts/replay_attack.py`.
- Enriquecimento MITRE ATT&CK nos alertas sem misturar regras internas ou playbooks em campos MITRE.
- Investigação por IP, incidentes persistidos, timeline real e relatórios Markdown/PDF.
- Explicação humana automática em `human_summary` / `explanation`.
- Notificações Discord/Telegram opcionais e desligadas por padrão.
- Autenticação opcional com `ENABLE_AUTH=false` para preservar a demo local.
- README atualizado para refletir a versão 6.0 e as decisões técnicas.

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
        +--> Redis state store
        |    fallback: in-memory state
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

## Core Features

- Event-driven architecture with Kafka.
- Raw event ingestion through `raw_logs`.
- Enriched alert publication through `security_alerts`.
- Configurable YAML detection rules.
- Temporal and multidimensional correlation by IP, destination, username, service, port, replay and event type.
- Redis-backed correlation state with safe in-memory fallback.
- Local and simulated external Threat Intelligence.
- Risk scoring based on explicit factors: base signal, sensitive port, volume, time window, IOC, asset criticality, MITRE correlation, repetition and confidence.
- Accumulative per-IP `threat_score` with clear correlation reasons.
- MITRE ATT&CK enrichment with `mitre_id`, `mitre_name` and `mitre_tactic`.
- IP investigation, persisted editable incidents, real alert timeline and Markdown/PDF reports.
- Professional simulated response model using `recommended_action`, `action_reason`, `response_playbook`, `execution_mode=simulation` and `execution_status=not_executed`.
- PostgreSQL persistence with backward-compatible schema evolution.
- REST API with legacy token and JWT authentication.
- JSON `/metrics` endpoint and Prometheus-compatible `/metrics/prometheus`.
- SOC dashboard with filters, search, ranking, analytics, attack map and drill-down.
- Demo Mode with controlled incident simulation and visual incident timeline.
- CI pipeline with tests and Python compilation checks.

## Services

| Service | Role |
| --- | --- |
| `kafka` | Single broker used by default for local event streaming. |
| `redis` | State store for rule engine correlation windows. |
| `db` | PostgreSQL database for alert history, persisted incidents, links and audit log. |
| `log_collector` | Produces baseline log events into Kafka. |
| `simulator` | Generates normal traffic, bursts, IOCs and attack sequences. |
| `rule_engine` | Applies rules, correlation, Threat Intelligence and risk scoring. |
| `alert_sink` | Consumes enriched alerts and persists them in PostgreSQL. |
| `dashboard_api` | Exposes health, auth, alert, incident, report and metrics endpoints. |
| `dashboard_web` | Static SOC dashboard served by Nginx. |

## Requirements

- Docker
- Docker Compose
- Python 3.11+ for local tests

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

Base API URL:

```text
http://localhost:5000
```

| Endpoint | Description | Authentication |
| --- | --- | --- |
| `GET /health` | API and database health check. | No |
| `POST /auth/token` | Issues a demo JWT using the legacy token. | Legacy token |
| `POST /demo/simulate-attack` | Registers a controlled demo incident. | Yes |
| `GET /demo/summary` | Demo cards summary: totals, top IP, score and replay events. | Yes |
| `GET /alertas?range=5m` | Alerts from the selected time range. | Yes |
| `GET /alerts?range=5m` | Alias em inglês com o mesmo contrato enriquecido de alertas. | Yes |
| `GET /alertas?range=1h` | Alerts from the selected time range. | Yes |
| `GET /historico?range=24h` | Historical alert list using the same compatible alert schema. | Yes |
| `GET /scores?range=24h` | Accumulative threat score by source IP. | Yes |
| `GET /timeline?source_ip=45.67.89.12` | Timeline visual baseada nos alertas reais. | Optional |
| `GET /investigation/ip/{source_ip}` | Investigação detalhada por IP. | Optional |
| `GET /incidents` | Incidentes persistidos e enriquecidos por IPs, score, replay, MITRE e campos do analista. | Optional |
| `GET /incidents/{incident_id}` | Detalhe de incidente. | Optional |
| `PATCH /incidents/{incident_id}` | Atualiza `status`, `analyst_notes`, `assigned_to` e `soc_action`. | Optional |
| `GET /incidents/{incident_id}/alerts` | Alertas relacionados ao incidente persistido. | Optional |
| `GET /incidents/{incident_id}/audit` | Histórico de alterações manuais do incidente. | Optional |
| `GET /campaigns` | Campanhas agregadas quando há múltiplos IPs/eventos/alvos/serviços. | Optional |
| `GET /reports/incident/{incident_id}.pdf` | Relatório PDF exportável gerado localmente. | Optional |
| `GET /reports/incident/{incident_id}.md` | Relatório Markdown exportável. | Optional |
| `GET /rules` | Regras YAML carregadas, MITRE, score, threshold e enabled/disabled. | Optional |
| `GET /metrics` | Métricas JSON reais para dashboard. | Yes |
| `GET /metrics/timeline?range=24h` | Buckets temporais úteis para últimas 24h, 1h ou janelas menores. | Yes |
| `GET /metrics/summary` | Alias explícito para resumo operacional. | Yes |
| `GET /metrics/prometheus` | Métricas Prometheus compatíveis. | Yes |

Supported alert ranges:

- `5m`
- `15m`
- `1h`
- `24h`

## Authentication

Protected endpoints accept the legacy demo token:

```text
X-SENTINELA-TOKEN: sentinela-demo-token
```

They also accept Bearer authentication:

```text
Authorization: Bearer sentinela-demo-token
```

or a JWT issued by `/auth/token`:

```powershell
Invoke-RestMethod `
  -Method Post `
  -Uri "http://localhost:5000/auth/token" `
  -Headers @{ "X-SENTINELA-TOKEN" = "sentinela-demo-token" }
```

Relevant environment variables:

```text
SENTINELA_API_TOKEN=sentinela-demo-token
SENTINELA_JWT_SECRET=sentinela-demo-jwt-secret
SENTINELA_JWT_TTL_SECONDS=3600
```

The dashboard keeps using the legacy token header for local demo compatibility.

Authentication is optional in 6.0. By default, local demo usage is not blocked:

```text
ENABLE_AUTH=false
```

To require authentication:

```text
ENABLE_AUTH=true
SENTINELA_USER=admin
SENTINELA_PASSWORD=sentinela
```

When enabled, protected endpoints accept the existing token/JWT path and Basic Auth with the configured local credentials.

## MITRE ATT&CK

Alertas 6.0 incluem MITRE quando o tipo de evento permite:

| Evento | MITRE | Técnica | Tática |
| --- | --- | --- | --- |
| `PORT_SCAN` | `T1046` | Network Service Discovery | Discovery |
| `BRUTE_FORCE` / `FAILED_LOGIN` | `T1110` | Brute Force | Credential Access |
| `SUSPICIOUS` | `T1087` | Account Discovery | Discovery |
| `IOC_MATCH` | `T1071` | Application Layer Protocol | Command and Control |
| `ESCALATION` | `T1068` | Exploitation for Privilege Escalation | Privilege Escalation |

Valores internos como regra Sentinela, categoria de correlação ou playbook de resposta não são gravados como MITRE. Eles aparecem em campos próprios:

Campos adicionados:

- `mitre_id`
- `mitre_name`
- `mitre_tactic`
- `mitre_techniques`
- `internal_rule_id`
- `internal_rule_name`
- `correlation_rule`
- `response_playbook`
- `detection_source`
- `human_summary`
- `explanation`

## Modelo operacional SOC

O projeto separa quatro níveis:

- Evento: ocorrência bruta ou quase bruta recebida do coletor/simulador, preservada em `raw_event` com timestamp, origem, alvo, serviço, porta e `event_type`.
- Alerta: evento interpretado por regra, com `internal_rule_id`, severidade, score, MITRE real quando aplicável, confiança, alvo afetado e evidências.
- Incidente: agrupamento investigável de alertas relacionados, persistido em `incidents` e ligado por `incident_alerts`, com lifecycle, severidade, score, ativos afetados, evidências e timeline.
- Campanha: padrão agregado exposto em `/campaigns` quando há múltiplos IPs, eventos, alvos/serviços ou repetição coerente em janela maior.

## Investigação e Incidentes

Clique no IP no feed do dashboard para abrir a investigação por IP. A visão mostra score atual, maior severidade, primeiro/último visto, eventos, incidentes relacionados, origem, alvo, portas/serviços, criticidade do ativo, técnicas MITRE, regra interna, correlação, playbook recomendado, eventos de replay, timeline, resumo do analista e próximas ações sugeridas.

Incidentes são materializados como entidade persistida no PostgreSQL. A API e o `alert_sink` associam alertas a incidentes em `incident_alerts`, atualizando score, severidade, IPs, serviços, usuários, MITRE e reasons de correlação sem apagar alertas existentes.

Alterações manuais feitas via `PATCH /incidents/{incident_id}` são registradas em `incident_audit_log`. O PATCH aceita apenas campos seguros: `status`, `analyst_notes`, `assigned_to` e `soc_action`; campos calculados como `max_score` e `event_count` não são alteráveis diretamente.

Lifecycle/status permitidos: `NEW`, `DETECTED`, `TRIAGED`, `INVESTIGATING`, `CONTAINED`, `RESOLVED`, `FALSE_POSITIVE` e `CLOSED`.

Severidade, lifecycle e resposta são campos diferentes. Exemplo: `severity=HIGH`, `lifecycle_stage=Investigating`, `recommended_action=Recomendar bloqueio temporario`, `execution_mode=simulation`, `execution_status=not_executed`.

## Relatório Exportável

Depois de obter um `incident_id` em `/incidents`, gere relatório PDF ou Markdown:

```text
GET http://localhost:5000/reports/incident/INC-xxxx.pdf
GET http://localhost:5000/reports/incident/INC-xxxx.md
```

O relatório contém ID, título, lifecycle/status, IP principal, IPs relacionados, alvos, severidade, score, técnicas MITRE, regras internas, alertas relacionados, timeline, razões de correlação, explicação humana, notas do analista, ações recomendadas, playbook, modo de execução simulado e a observação de segurança de que nenhuma ação real de bloqueio, ataque, firewall ou iptables foi executada.

## Notificações

Notificações são opcionais e desligadas por padrão:

```text
ENABLE_NOTIFICATIONS=false
DISCORD_WEBHOOK_URL=
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=
```

Se `ENABLE_NOTIFICATIONS=true`, o `alert_sink` tenta enviar alertas críticos para Discord/Telegram apenas quando as credenciais estiverem presentes. Falhas de notificação são registradas em log e não interrompem o pipeline. A mensagem usa o formato `SENTINELA SOC 6.0 - ALERTA CRÍTICO` e reforça `bloqueio simulado apenas`.

## Demo Mode

Sentinela SOC 6.0 includes a visible incident demonstration mode for presentations and recruiter walkthroughs.

How to use:

```powershell
docker compose up -d --build
```

Open:

```text
http://localhost:8080
```

Click:

```text
Simular Ataque
```

The dashboard will:

- Highlight `INCIDENTE CRÍTICO EM ANDAMENTO`.
- Update the main cards: incidentes abertos, incidentes críticos, IPs envolvidos, maior score, MITRE dominante e último replay.
- Animate attack lines on the global map.
- Render the `Linha do Tempo`.
- Show stages such as event received, suspicious IP identified, brute force detection, YAML rule match, Threat Intelligence match and `simulated_block`.

Use the `DEMO / HISTÓRICO` toggle in the header:

- `DEMO` prioritizes recent SOC activity, replay events, the attack map and the incident timeline.
- `HISTÓRICO` hides the live incident presentation and focuses on a professional alert table with IP, timestamp, alert type, severity, score and correlation reason.

## Replay Attack

The replay script publishes a safe sequence of simulated events to Kafka topic `raw_logs`. It does not access external networks, does not run an attack and does not change firewall rules.

```powershell
py scripts\replay_attack.py --scenario critical_chain
py scripts\replay_attack.py --scenario multi_ip_campaign
```

Available scenarios:

```powershell
py scripts\replay_attack.py --scenario brute_force
py scripts\replay_attack.py --scenario port_scan
py scripts\replay_attack.py --scenario ioc_match
py scripts\replay_attack.py --scenario critical_chain
py scripts\replay_attack.py --scenario false_positive
py scripts\replay_attack.py --scenario multi_ip
py scripts\replay_attack.py --scenario multi_ip_campaign
```

`multi_ip_campaign` simula três ou mais `source_ips` atacando o mesmo `destination_ip`, usuário `admin` e serviço `ssh` na mesma janela, com `replay_id` comum. O resultado esperado é um único incidente persistido com múltiplos IPs em `source_ips`.

Default connection:

```text
KAFKA_BOOTSTRAP_SERVERS=localhost:9092
RAW_LOGS_TOPIC=raw_logs
```

Expected sequence:

- `FAILED_LOGIN` from a common user.
- Repeated `FAILED_LOGIN` from the same IP.
- Attempt against `admin`.
- `BRUTE_FORCE` pattern.
- Final suspicious event that should push the correlated alert toward `HIGH` or `CRITICAL`.

## Score por IP

The rule engine computes `threat_score` per source IP inside the correlation window. The alert keeps legacy fields like `risco` and `score_final`, while adding an explainable SOC score:

- `source_ip`
- `threat_score`
- `severity`
- `score_breakdown`
- `score_explanation`
- `reasons`
- `correlation_reasons`
- `last_seen`
- `event_count`
- `replay_id`
- `is_replay_event`

Score factors:

- `base_score`
- `sensitive_port_score`
- `event_volume_score`
- `time_window_score`
- `ioc_score`
- `asset_criticality_score`
- `mitre_correlation_score`
- `repeated_activity_score`
- `confidence_score`
- `final_score`

Classification:

- `0-29`: informational/low
- `30-49`: `LOW`
- `50-69`: `MEDIUM`
- `70-89`: `HIGH`
- `90-100`: `CRITICAL`

Score 100 é reservado para múltiplas evidências fortes. Um evento simples em porta sensível não deve virar `CRITICAL` sozinho.

The API endpoint used by the button is:

```text
POST /demo/simulate-attack
```

It requires the same authentication as other protected endpoints and records demo alerts in PostgreSQL. It does not execute firewall rules, `iptables` or any real blocking action. The response action is represented by:

```text
recommended_action=...
response_playbook=...
execution_mode=simulation
execution_status=not_executed
```

## Incident Timeline UX

After clicking `Simular Ataque`, the dashboard shows a SOC-style investigation timeline with seven connected stages. The view highlights the attacker, the detection sequence, the rule correlation and the safe response decision.

The `Primary Attacker` card summarizes:

- Main attacker IP.
- Initial vector.
- Maximum severity.
- SOC response status.

The `Incident Summary` provides a short narrative for demos, videos and interviews. It explains that a controlled attack was detected, correlation rules elevated the incident to `CRITICAL`, and the system registered `simulated_block` without real blocking.

This feature is educational and demonstrative. It is designed to show detection, correlation and response logic while keeping the environment safe.

## Redis State Store

The rule engine uses Redis to store correlation windows by IP:

```text
REDIS_URL=redis://redis:6379/0
REDIS_STATE_ENABLED=true
CORRELATION_WINDOW_SECONDS=300
```

If Redis is unavailable, the rule engine logs the failure and falls back to in-memory state. This keeps the demo resilient while showing the intended production direction.

## Noise Reduction & SOC Correlation

Sentinela SOC 6.0 reduces noise in the alert pipeline without removing historical retention.

How it works:

- Repeated alerts with the same `ip`, `event_type`, `status`, `port` and `threat_category` are consolidated.
- Alerts emitted many times inside the configured window are rate limited by IP and status.
- Related events are aggregated per IP into a single consolidated alert when possible.
- The alert keeps `first_seen`, `last_seen`, `occurrence_count`, `ports`, `services`, `event_types` and `aggregated`.
- Redis stores correlation state when available; in-memory fallback keeps the demo working if Redis is offline.

Important distinction:

- Raw events remain part of the SIEM history.
- Consolidated alerts are the view used by the dashboard for faster SOC triage.
- Demo mode can be isolated with `mode=demo` so the presentation does not mix with historical noise.

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

Real blocking remains disabled:

```text
ENABLE_BLOCK=false
```

No firewall, `iptables` or host-level blocking action is executed. High-risk events are marked with:

```text
simulated_block=true
```

This keeps the project safe for demos and portfolio review while preserving the SOC response concept.

## Observability

The API exposes Prometheus-format metrics:

```text
http://localhost:5000/metrics
```

Metrics include:

- `sentinela_events_total`
- `sentinela_critical_events_total`
- `sentinela_ioc_events_total`
- `sentinela_events_by_type_total`

Reference configuration:

```text
infra/prometheus/prometheus.yml
```

## Kafka Multi-Broker Lab

The default mode remains a single Kafka broker for simplicity and reliability in local demos.

SENTINELA SOC 6.0 keeps the educational Compose profile:

```powershell
docker compose --profile kafka-lab up -d --build
```

This starts an additional Kafka broker service for architecture discussion and experimentation. It is not required for the normal demo path and does not change the default single-broker behavior.

## Running Tests

Install test dependencies:

```powershell
py -m pip install pytest
py -m pip install -r services/rule_engine/requirements.txt
py -m pip install -r services/dashboard_api/requirements.txt
```

Run:

```powershell
py -m pytest -q
```

Compile service files:

```powershell
py -m py_compile services\log_collector\main.py services\rule_engine\main.py services\alert-sink\main.py services\dashboard_api\main.py services\simulator\main.py
```

## CI

GitHub Actions workflow:

```text
.github/workflows/ci.yml
```

The pipeline runs:

- dependency installation
- Python compilation checks
- `pytest`

## Technology Stack

- Python
- Flask
- Kafka
- Redis
- PostgreSQL
- Docker Compose
- Nginx
- HTML, CSS and JavaScript
- Chart.js
- Prometheus client library
- YAML-based rules
- GitHub Actions
- Pytest

## Technical Decision History

- **4.0:** Visual SOC dashboard, attack map, local Threat Intelligence and simulated blocking.
- **5.0:** YAML rules, temporal ranges, Prometheus metrics and richer analytics.
- **5.5:** Production maturity pass with API token authentication, documentation, observability and repository cleanup.
- **6.0:** Redis state store, JWT compatibility, pytest coverage, CI workflow, educational Kafka profile, MITRE enrichment, IP investigation, editable incidents, metrics JSON, replay scenarios and exportable reports.
- **6.0 Demo Mode:** Controlled incident simulation with a visual timeline; no real blocking is executed.

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
tests/
.github/
docker-compose.yml
README.md
.gitignore
```

## Honest Limitations

- Kafka still runs as a single broker by default.
- The additional Kafka broker is educational and not a complete production cluster.
- Redis improves correlation state maturity, but full distributed stream processing would need stronger partition/state guarantees.
- External Threat Intelligence is simulated for safe portfolio usage.
- JWT is intentionally simple and suitable for demo, not a full identity platform.
- There is no RBAC, multi-tenancy or production-grade identity provider.
- There is no schema registry or formal dead-letter queue yet.

## Next Steps

- Add schema validation and dead-letter topics.
- Add Kafka partitioning strategy by IP or tenant.
- Add Alembic or another versioned migration tool.
- Add service-level metrics for Kafka lag, Redis health and processing latency.
- Add Grafana dashboards.
- Add integration tests with Docker Compose.
