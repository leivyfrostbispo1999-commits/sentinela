# SENTINELA SOC 5.5

Mini-SIEM educacional/profissional com arquitetura inspirada em ambientes reais de SOC.

O SENTINELA demonstra coleta, processamento, correlação, threat intelligence, persistência, observabilidade e dashboard analítico usando Docker Compose, Kafka, Python, PostgreSQL e frontend em HTML/CSS/JS puro.

## Arquitetura

```text
simulator/log_collector
  -> Kafka raw_logs
  -> rule_engine
  -> Kafka security_alerts
  -> alert_sink
  -> PostgreSQL
  -> dashboard_api
  -> dashboard_web
```

## Serviços

- `kafka`: barramento de eventos.
- `db`: PostgreSQL para histórico de alertas.
- `log_collector`: gerador/coletor de eventos.
- `simulator`: simula tráfego normal, bursts, IOCs e ataques multiestágio.
- `rule_engine`: aplica regras YAML, correlação temporal, threat intelligence e scoring.
- `alert_sink`: persiste alertas no banco.
- `dashboard_api`: expõe `/alertas`, `/metrics` e `/health`.
- `dashboard_web`: dashboard SOC visual.

## Como rodar

```powershell
docker compose up -d --build
docker ps
docker compose logs --tail=120
```

Dashboard:

```text
http://localhost:8080
```

API:

```text
http://localhost:5000/health
http://localhost:5000/alertas?range=5m
http://localhost:5000/metrics
```

## Token de API

Os endpoints `/alertas` e `/metrics` exigem:

```text
X-SENTINELA-TOKEN: sentinela-demo-token
```

Variável de ambiente:

```text
SENTINELA_API_TOKEN=sentinela-demo-token
```

O dashboard já envia esse header nas chamadas `fetch`.

## Regras YAML

As regras ficam em:

```text
services/rule_engine/rules.yaml
```

Campos suportados:

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

O `rule_engine` mantém fallback caso o YAML esteja inválido.

## Correlação

A correlação considera:

- IP
- serviço
- porta
- tipo de evento
- janela temporal

Campos gerados:

- `correlation_key`
- `correlation_reason`
- `correlation_window_seconds`

## Dashboard

O dashboard inclui:

- filtros por tempo
- busca por IP, status, event_type e service
- filtro de criticidade
- filtro de threat_source
- filtro por simulated_block
- gráficos com Chart.js
- mapa global simulado
- painel lateral de drill-down

## Métricas

O endpoint `/metrics` expõe métricas em formato Prometheus:

- `sentinela_events_total`
- `sentinela_critical_events_total`
- `sentinela_ioc_events_total`
- `sentinela_events_by_type_total`

Arquivo de referência:

```text
infra/prometheus/prometheus.yml
```

## Segurança e resposta

O projeto preserva:

```text
ENABLE_BLOCK=false
```

Nenhum bloqueio real é executado. A resposta automatizada é demonstrada por:

```text
simulated_block=true
```

## Limitações honestas

- Não é substituto de Splunk, Elastic, QRadar ou Wazuh.
- Kafka roda em nó único no ambiente local.
- Correlação é em memória.
- Threat Intel externa é simulada.
- Autenticação é token simples para demo.
- Não há RBAC, multi-tenant, schema registry ou DLQ formal.

## Próximos passos

- Kafka multi-broker com partitions planejadas.
- DLQ e validação de schema.
- State store distribuído para correlação.
- Migrações versionadas de banco.
- Prometheus/Grafana em compose opcional.
- Testes de carga com métricas de throughput e latência.
