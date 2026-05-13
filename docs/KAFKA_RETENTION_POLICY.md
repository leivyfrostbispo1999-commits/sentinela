# Política de Retenção Kafka - SENTINELA

Esta política define como os dados são retidos no cluster Kafka do SENTINELA para garantir equilíbrio entre observabilidade, conformidade e uso de recursos.

## Tópicos e Ciclo de Vida

| Tópico | Origem | Destino | Retenção (Tempo) | Retenção (Tamanho) | Descrição |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `raw_logs` | Log Collector / Simulator | Enrichment Worker | 12 horas | 2 GB | Logs brutos recebidos da rede. |
| `enriched_events` | Enrichment Worker | Rule Engine / AI Engine | 24 horas | 2 GB | Eventos normalizados e enriquecidos com GeoIP, etc. |
| `detections` | Rule Engine | Alert Sink | 7 dias | 1 GB | Alertas brutos gerados pelas regras. |
| `alerts` | Alert Sink | SOC / Externo | 30 dias | 500 MB | Alertas filtrados, agregados e notificados. |
| `audit_logs` | SOAR / Rule Engine | Dashboard API / DB | 90 dias | 500 MB | Log de auditoria de ações do sistema e SOAR. |
| `dead_letter_events` | Todos | Admin / Manual | 7 dias | 100 MB | Eventos que falharam no processamento. |

## Configuração de Retenção Global (Default)

- `log.retention.hours`: 24
- `log.retention.bytes`: 1073741824 (1GB)
- `log.segment.bytes`: 1073741824
- `log.retention.check.interval.ms`: 300000

## Preservação de Campos Obrigatórios

Todos os eventos que transitam pelos tópicos acima **DEVEM** preservar os seguintes campos:

- `event_id`: Identificador único do evento.
- `trace_id`: ID de rastreamento distribuído (OTel).
- `span_id`: ID do span atual (OTel).
- `correlation_id`: ID de correlação de eventos relacionados.
- `attack_session_id`: ID da sessão de ataque (Redis correlation).
- `tenant_id`: ID do cliente/tenant.
- `source_ip`: IP de origem da atividade.
- `timestamp`: Timestamp ISO8601 do evento original.

## Estratégia de Mitigação de Payload

Para evitar duplicação de payloads grandes (ex: `raw_log` gigante dentro de um alerta):
1. O `enrichment_worker` pode remover campos desnecessários do log original após normalização.
2. A `rule_engine` deve incluir apenas campos relevantes na evidência do alerta.
3. O payload bruto original deve ser armazenado preferencialmente no `raw_logs` ou em Cold Storage (OpenSearch), mantendo apenas referências nos tópicos downstream.
