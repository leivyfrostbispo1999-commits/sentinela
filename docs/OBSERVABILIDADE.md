# Observabilidade do SENTINELA

O SENTINELA expõe métricas em formato Prometheus pelo endpoint:

```text
http://localhost:5000/metrics
```

Esse endpoint é protegido pelo header:

```text
X-SENTINELA-TOKEN: sentinela-demo-token
```

## Métricas disponíveis

- `sentinela_events_total`: total de eventos persistidos no banco.
- `sentinela_critical_events_total`: total de eventos críticos ou com `simulated_block=true`.
- `sentinela_ioc_events_total`: total de eventos com `threat_intel_match=true`.
- `sentinela_events_by_type_total{event_type="..."}`: contagem por tipo de evento.

## Coleta com Prometheus

Exemplo de configuração:

```yaml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: sentinela-dashboard-api
    metrics_path: /metrics
    static_configs:
      - targets:
          - dashboard_api:5000
    authorization:
      type: X-SENTINELA-TOKEN
      credentials: sentinela-demo-token
```

Algumas versões do Prometheus não suportam header customizado via `authorization` nesse formato. Nesse caso, use proxy local, exporter auxiliar ou configuração equivalente no ambiente de observabilidade.

## Ideia de dashboard Grafana

Painéis úteis:

- Eventos totais por minuto.
- Eventos críticos por minuto.
- IOCs por fonte: local e external.
- Distribuição por `event_type`.
- Top IPs por volume.
- Top portas atacadas.
- Taxa de `simulated_block`.

## Alertas automáticos possíveis

- Alta taxa de eventos críticos por 5 minutos.
- Aumento repentino de `sentinela_ioc_events_total`.
- Ausência de eventos por período anormal.
- Crescimento de eventos em portas sensíveis.
- Aumento de campanhas hostis.

## Limitações atuais

As métricas são geradas consultando o PostgreSQL no momento do scrape. Para produção, seria melhor manter contadores em memória, exportar métricas por serviço e adicionar métricas de Kafka, consumer lag, banco e latência fim a fim.
