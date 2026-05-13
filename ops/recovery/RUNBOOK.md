# SENTINELA Recovery Runbook

Objetivo: reconstruir o SENTINELA usando apenas repo, `.env` documentado e backup validado.

## Rotina normal

1. Gerar dump Postgres:

```bash
./ops/recovery/backup_postgres.sh
```

2. Validar restore em container isolado, sem tocar producao:

```bash
./ops/recovery/verify_restore.sh
```

3. Rodar o check de recovery:

```bash
./ops/recovery/dr_check.sh
```

O backup fica em `backups/postgres` por padrao, com manifesto `.manifest.json` contendo hash, tamanho, origem e retencao. Em producao, defina `SENTINELA_BACKUP_DIR` para um caminho persistente e copie esse diretorio para fora da VPS.

## Restore em VPS nova

1. Instale Docker e Docker Compose.
2. Clone o repo.
3. Crie `.env` a partir de `.env.example` e preencha segredos reais.
4. Copie o backup validado para `backups/postgres/`.
5. Suba banco e Redis:

```bash
docker compose -f docker-compose.micro.yml up -d db redis
```

6. Restaure o dump no banco novo:

```bash
gzip -dc backups/postgres/sentinela_YYYYMMDDTHHMMSSZ.sql.gz | docker exec -i sentinela-db-lite psql -v ON_ERROR_STOP=1 -U postgres -d postgres
```

7. Suba a aplicacao:

```bash
docker compose -f docker-compose.micro.yml up -d --build
```

8. Valide:

```bash
./ops/recovery/verify_restore.sh backups/postgres/sentinela_YYYYMMDDTHHMMSSZ.sql.gz
./ops/recovery/dr_check.sh
```

## Variaveis uteis

- `SENTINELA_BACKUP_DIR`: diretorio dos dumps.
- `SENTINELA_BACKUP_RETENTION_DAYS`: retencao local, padrao `7`.
- `SENTINELA_BACKUP_MAX_AGE_HOURS`: idade maxima aceita no check, padrao `36`.
- `SENTINELA_RESTORE_MAX_AGE_HOURS`: idade maxima da ultima validacao de restore, padrao `168`.
- `SENTINELA_POSTGRES_CONTAINER`: container de origem, padrao `sentinela-db-lite`.

## Guardrails

Nao use `docker compose down -v`, `docker volume rm` ou prune destrutivo antes de ter backup validado e copia fora da VPS.
