# Production Hardening

## Ambientes

```text
SENTINELA_ENV=development|production
ENABLE_AUTH=true
```

Em `production`, `SENTINELA_JWT_SECRET` é obrigatório e não pode usar valor padrão.

## Secrets

Ordem de resolução:

1. variável direta, por exemplo `SENTINELA_JWT_SECRET`;
2. arquivo por variável `SENTINELA_JWT_SECRET_FILE`;
3. Docker secret `/run/secrets/SENTINELA_JWT_SECRET`;
4. fallback somente em `SENTINELA_ENV=development`.

Variáveis preparadas:

```text
SENTINELA_JWT_SECRET
SENTINELA_JWT_SECRET_FILE
GRAFANA_ADMIN_PASSWORD
GRAFANA_ADMIN_PASSWORD_FILE
VIRUSTOTAL_API_KEY
ABUSEIPDB_API_KEY
OTX_API_KEY
```

## CORS

```text
CORS_ALLOWED_ORIGINS=http://localhost:8080,https://sentinela.example
```

## Logs seguros

Campos com `password`, `token`, `secret`, `api_key`, `authorization` e similares são redigidos nos logs estruturados.

## Rate limiting

Desligado por padrão em desenvolvimento:

```text
ENABLE_RATE_LIMITING=false
RATE_LIMIT_AUTH_PER_MINUTE=20
RATE_LIMIT_API_PER_MINUTE=120
```

Ativar:

```powershell
$env:ENABLE_RATE_LIMITING="true"
docker compose up -d --build dashboard_api
```

Limitação atual: rate limiting é em memória por réplica. Para múltiplas réplicas, a evolução recomendada é Redis.
