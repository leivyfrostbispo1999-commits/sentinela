# Validação de Observabilidade

O Sentinela foi projetado com observabilidade out-of-the-box usando o stack Prometheus + Grafana e geração massiva de métricas nas aplicações (Python Prometheus Client).

## 1. Verificando as Métricas Brutas (Prometheus Exporters)

Cada serviço expõe métricas no endpoint `/metrics`.
Você pode visualizar diretamente usando:
```powershell
Invoke-RestMethod http://127.0.0.1:5000/metrics | Select-Object -First 20
```

*Métricas-chave a observar:*
- `sentinela_http_requests_total`
- `sentinela_request_latency_seconds`
- `sentinela_events_consumed_total`
- `sentinela_alerts_generated_total`
- `sentinela_dlq_messages_total`

## 2. Acesso ao Prometheus

O Prometheus faz o scraping de todos os serviços (API, Rule Engine, Log Collector, Alert Sink).
- **URL:** [http://127.0.0.1:9090](http://127.0.0.1:9090)
- **Status dos Targets:** Acesse [http://127.0.0.1:9090/targets](http://127.0.0.1:9090/targets) e verifique se todos estão com status `UP`.

**Queries úteis para o Prometheus (PromQL):**
- Taxa de ingestão: `rate(sentinela_events_consumed_total[1m])`
- Latência P95 da API: `histogram_quantile(0.95, rate(sentinela_request_latency_seconds_bucket[5m]))`
- Alertas gerados por severidade: `sum by (severity) (rate(sentinela_alerts_generated_total[5m]))`

## 3. Acesso ao Grafana

Os dashboards consolidados estão no Grafana.
- **URL:** [http://127.0.0.1:3000](http://127.0.0.1:3000)
- **Usuário Padrão:** `admin`
- **Senha Padrão:** `sentinela`

**Dashboards Disponíveis:**
1. **Sentinela SOC Overview:** Visão tática de segurança, com quantidade de alertas e funil de detecção.
2. **Sentinela Operational Maturity:** Visão técnica (SRE) mostrando latência, throughput do Kafka, tamanho de filas e erros HTTP.

## 4. Validando Latência e Degradação

Para forçar métricas sob carga e analisar os resultados no Grafana, utilize a suíte de k6:
```powershell
k6 run tests/load/sentinela-load-test.js
```
Acompanhe no dashboard "Operational Maturity" como os percentis P95 e P99 de latência reagem durante a execução.
