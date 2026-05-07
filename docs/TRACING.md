# Tracing Distribuido

Tracing e opcional e fica desligado por padrao.

## Variaveis

```env
ENABLE_TRACING=false
OTEL_SERVICE_NAME=sentinela-7-api
OTEL_EXPORTER_OTLP_ENDPOINT=http://jaeger:4318/v1/traces
```

Para ativar:

```powershell
$env:ENABLE_TRACING="true"
docker compose up -d --build jaeger dashboard_api
```

Jaeger UI:

```text
http://localhost:16686
```

## O que e instrumentado

- Flask/API via OpenTelemetry.
- `correlation_id`, rota e tenant como atributos de span quando disponiveis.
- O pipeline continua propagando `correlation_id` em eventos Kafka e alertas.

O tracing nao e requisito para funcionamento da API. Se as dependencias OpenTelemetry ou Jaeger nao estiverem disponiveis, a aplicacao continua rodando.

## Validacao

1. Ative `ENABLE_TRACING=true`.
2. Suba Jaeger e API.
3. Gere trafego:

```powershell
curl http://localhost:5000/health
curl "http://localhost:5000/search?q=BRUTE_FORCE" -H "Authorization: Bearer <JWT>"
```

4. Abra `http://localhost:16686`.
5. Procure o service `sentinela-7-api`.

## Troubleshooting

- Sem traces: confira `ENABLE_TRACING=true`.
- Service ausente no Jaeger: confira `OTEL_EXPORTER_OTLP_ENDPOINT`.
- Erro de import OpenTelemetry: rode `docker compose up -d --build dashboard_api` para reinstalar dependencias da imagem.
- Ambiente sem Jaeger: a API continua funcionando, apenas sem exportacao de traces.
