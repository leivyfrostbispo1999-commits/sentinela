# Audit and Retention

## Auditoria

Tabela: `audit_logs`.

Campos principais:

```text
id, timestamp, tenant_id, actor_user, actor_role, action, resource_type,
resource_id, correlation_id, source_ip, success, metadata_json
```

Endpoint admin:

```powershell
curl "http://localhost:5000/audit?action=login_success&limit=50" -H "Authorization: Bearer <ADMIN_JWT>"
```

Viewer recebe `403`. O filtro por tenant vem do JWT.

Ações registradas:

- `login_success`
- `login_failed`
- `refresh_token`
- `refresh_failed`
- `incident_updated`
- `demo_ingestion_executed`
- `rate_limit_exceeded`

## Retenção

Dry-run por padrão:

```powershell
python scripts/retention_cleanup.py --dry-run
python scripts/retention_cleanup.py --print-plan
```

Execução explícita:

```powershell
python scripts/retention_cleanup.py --execute
```

Variáveis:

```text
RETENTION_ALERTS_DAYS=30
RETENTION_EVENTS_DAYS=30
RETENTION_AUDIT_DAYS=180
RETENTION_INCIDENTS_DAYS=90
```

Agendamento exemplo:

```cron
15 3 * * * cd /opt/sentinela && python scripts/retention_cleanup.py --execute >> /var/log/sentinela-retention.log 2>&1
```
