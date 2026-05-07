# Testes de Carga com k6

## Instalar k6 no host

Windows:

```powershell
winget install k6.k6
```

Linux:

```bash
sudo apt update
sudo apt install k6
```

Docker:

```powershell
docker run --rm -i -v ${PWD}/tests/load:/scripts grafana/k6 run /scripts/api_endpoints_stress.js
```

## Smoke test

```powershell
k6 run tests/load/api_endpoints_stress.js
```

Com parametros:

```powershell
$env:BASE_URL="http://localhost:5000"
$env:USERNAME="admin"
$env:PASSWORD="sentinela"
$env:VUS="1"
$env:DURATION="30s"
k6 run tests/load/api_endpoints_stress.js
```

## Stress test

```powershell
$env:VUS="20"
$env:DURATION="5m"
k6 run tests/load/api_endpoints_stress.js
```

## Cobertura do script

`tests/load/api_endpoints_stress.js` cobre:

- `POST /auth/token`
- `GET /metrics`
- `GET /search?q=BRUTE_FORCE`
- `GET /alerts`
- `GET /incidents`
- `POST /demo/simulate-attack`
- WebSocket `/ws/alerts?token=<JWT>`

Thresholds:

- `http_req_failed < 3%`
- `p95 http_req_duration < 5s`
- `checks > 90%`

## Docker Compose

Subir ambiente:

```powershell
docker compose up -d --build
```

Rodar com container oficial:

```powershell
docker run --rm -i --network sentinela_sentinela-net -v ${PWD}/tests/load:/scripts grafana/k6 run /scripts/api_endpoints_stress.js
```

## Troubleshooting

- `401` em endpoints: confirme `USERNAME` e `PASSWORD`.
- WebSocket falhando: confirme que `dashboard_api` foi reconstruido com `flask-sock`.
- Latencia alta: confira Prometheus, Kafka lag e logs de `rule_engine`/`alert_sink`.
