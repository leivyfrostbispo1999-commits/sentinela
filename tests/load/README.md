# Testes de carga SENTINELA SOC 6.0

Scripts k6 para validar ingestao, stress de API e multiplos incidentes simulados.

## Execucao

```powershell
k6 run tests/load/high_ingestion.js
k6 run tests/load/multiple_incidents.js
k6 run tests/load/dashboard_stress.js
k6 run tests/load/api_endpoints_stress.js
```

Variaveis:

- `BASE_URL`: API do dashboard. Padrao: `http://localhost:5000`
- `API_TOKEN`: token bearer. Padrao: `sentinela-demo-token`
- `VUS`: usuarios virtuais
- `DURATION`: duracao do teste

