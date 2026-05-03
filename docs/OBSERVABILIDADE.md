# Observabilidade do SENTINELA

O SENTINELA expõe métricas em formato Prometheus por meio do `dashboard_api`.

```text
http://localhost:5000/metrics
```

O endpoint é protegido por token para manter consistência com o restante da API.

## Autenticação

Headers aceitos:

```text
X-SENTINELA-TOKEN: sentinela-demo-token
```

ou:

```text
Authorization: Bearer sentinela-demo-token
```

## Métricas Disponíveis

- `sentinela_events_total`: total de eventos persistidos no PostgreSQL.
- `sentinela_critical_events_total`: total de eventos críticos ou com `simulated_block=true`.
- `sentinela_ioc_events_total`: total de eventos com `threat_intel_match=true`.
- `sentinela_events_by_type_total{event_type="..."}`: contagem de eventos por tipo.

## Coleta com Prometheus

Arquivo de referência:

```text
infra/prometheus/prometheus.yml
```

Exemplo:

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
      type: Bearer
      credentials: sentinela-demo-token
```

## Ideia de Dashboard Grafana

Painéis úteis:

- Eventos totais por minuto.
- Eventos críticos por minuto.
- IOCs por fonte.
- Distribuição por `event_type`.
- Top IPs por volume.
- Top portas atacadas.
- Percentual de eventos com `simulated_block=true`.

## Alertas Operacionais Possíveis

- Alta taxa de eventos críticos por 5 minutos.
- Crescimento repentino de IOCs.
- Ausência anormal de eventos.
- Aumento de eventos em portas sensíveis.
- Crescimento do consumer lag no Kafka.
- Falhas recorrentes de escrita no PostgreSQL.

## Limitação Atual

As métricas são calculadas consultando o PostgreSQL durante o scrape. Para produção, cada serviço deveria expor suas próprias métricas, incluindo latência, erros, throughput, consumer lag, tamanho de lote e tempo fim a fim.
