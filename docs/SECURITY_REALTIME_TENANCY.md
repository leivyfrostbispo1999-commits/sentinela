# Segurança, Tenancy e Realtime

## Autenticação

A API suporta autenticação por JWT em `/auth/token` e mantém compatibilidade com o token legado `X-SENTINELA-TOKEN`.

Login padrão local:

```bash
curl -X POST http://localhost:5000/auth/token \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"admin\",\"password\":\"sentinela\"}"
```

Usuários padrão quando `SENTINELA_USERS_JSON` não é definido:

| Usuário | Senha | Papel | Tenant |
| --- | --- | --- | --- |
| admin | `SENTINELA_PASSWORD` ou `sentinela` | admin | `DEFAULT_TENANT_ID` |
| analyst | `SENTINELA_ANALYST_PASSWORD` ou `analyst` | analyst | `DEFAULT_TENANT_ID` |
| viewer | `SENTINELA_VIEWER_PASSWORD` ou `viewer` | viewer | `DEFAULT_TENANT_ID` |

Para produção, defina `SENTINELA_USERS_JSON` com `password_hash` PBKDF2 e altere `SENTINELA_JWT_SECRET`.

## RBAC

| Ação | admin | analyst | viewer |
| --- | --- | --- | --- |
| Ler alertas, métricas, regras, incidentes e relatórios | sim | sim | sim |
| Buscar alertas em `/search` | sim | sim | sim |
| Atualizar incidente em `PATCH /incidents/{id}` | sim | sim | não |
| Executar demo em `/demo/simulate-attack` | sim | sim | não |

## Multi-tenant

O pipeline carrega `tenant_id` desde simulador/coletor até `rule_engine`, `alert_sink` e API. Consultas principais filtram por tenant do JWT. Em modo sem autenticação, a API usa `X-Tenant-ID` se enviado ou `DEFAULT_TENANT_ID`.

Campos persistidos:

- `alertas.tenant_id`
- `alertas.correlation_id`
- `incidents.tenant_id`

## Realtime

O frontend tenta abrir `ws://localhost:5000/ws/alerts` e envia o JWT como query string. Se o WebSocket falhar, o polling existente continua atualizando o painel.

Teste simples:

```bash
docker compose up -d --build
curl -X POST http://localhost:5000/auth/token -H "Content-Type: application/json" -d "{\"username\":\"admin\",\"password\":\"sentinela\"}"
```

Use o token retornado em um cliente WebSocket:

```text
ws://localhost:5000/ws/alerts?token=<JWT>
```

## Busca

Endpoint:

```bash
curl "http://localhost:5000/search?q=BRUTE_FORCE" -H "Authorization: Bearer <JWT>"
```

Busca em IP, tipo de evento, status, severidade, MITRE e resumo humano.

## Validação

```bash
py -m pytest -q
py -m py_compile services\dashboard_api\main.py services\rule_engine\main.py services\alert-sink\main.py services\simulator\main.py services\log_collector\main.py
docker compose config
```
