# Arquitetura SENTINELA SOC 6.0

## Visao geral

O SENTINELA opera como um pipeline SOC/SIEM local:

`log_collector/simulator -> Kafka raw_logs -> rule_engine -> Kafka security_alerts -> alert_sink -> Postgres -> dashboard_api -> dashboard_web`

Prometheus coleta `/metrics` dos servicos e Grafana provisiona dashboards iniciais.

## Comunicacao entre servicos

- `log_collector` publica eventos normalizados no topico `raw_logs`.
- `simulator` publica eventos defensivos simulados no mesmo topico.
- `rule_engine` consome `raw_logs`, aplica regras YAML, threat intel local, scoring e correlacao temporal.
- `rule_engine` publica alertas enriquecidos em `security_alerts`.
- `alert_sink` consome `security_alerts`, persiste alertas e materializa incidentes no Postgres.
- `dashboard_api` le Postgres e entrega alertas, incidentes, investigacao, metricas e relatorios.
- `dashboard_web` consome a API no navegador.
- `Prometheus` coleta metricas operacionais.
- `Grafana` apresenta visao de throughput, latencia, incidentes e erros.
- `dashboard_web_exporter` converte `stub_status` do Nginx em metricas Prometheus.

## Fluxo de eventos

1. Evento bruto recebe `event_id`, `ts`, `source_ip`, `event_type`, `service` e `port`.
2. Kafka desacopla ingestao e correlacao.
3. O motor de regras agrega por origem, janela temporal, tipo de evento e contexto do ativo.
4. Alertas mantem payload retrocompativel e adicionam campos SOC: MITRE, score, playbook e resposta simulada.

## Fluxo de incidentes

1. `alert_sink` grava cada alerta em `alertas`.
2. Alertas relacionados sao vinculados em `incident_alerts`.
3. `incidents` consolida severidade, score maximo, entidades, evidencias e timeline.
4. O dashboard permite triagem, notas, responsavel, relatorios Markdown/PDF e auditoria.

## Fluxo de correlacao

- Janela temporal configuravel por `CORRELATION_WINDOW_SECONDS`.
- Estado em Redis quando disponivel, fallback em memoria.
- Regras YAML seguem incrementais e nao substituem a logica existente.
- Score considera severidade, portas sensiveis, volume, MITRE, IOC, criticidade do ativo e repeticao.

## Dependencias operacionais

- Kafka: transporte de eventos e alertas.
- Redis: estado de correlacao compartilhado.
- Postgres: persistencia de alertas, incidentes e auditoria.
- Prometheus: coleta de metricas.
- Grafana: visualizacao operacional.
