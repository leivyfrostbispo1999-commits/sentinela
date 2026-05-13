# SENTINELA Oracle Micro Runbook

This VM is an Oracle `VM.Standard.E2.1.Micro`. It is suitable for the dashboard, API, Postgres and Redis only. It must not run the heavy SOC pipeline continuously.

## 24/7 Stack

Run this stack continuously:

```bash
./ops/oci/start_micro.sh
```

Expected containers after boot:

```text
sentinela-web-lite
sentinela-api-lite
sentinela-db-lite
sentinela-redis-lite
```

These services use `restart: always` and are allowed to return after reboot.

## Heavy Test Stack

Run heavy services only for short validation windows:

```bash
./ops/oci/start_heavy_test.sh
```

Stop them immediately after the test:

```bash
./ops/oci/stop_heavy_test.sh
```

Heavy services include Kafka, Jaeger, simulators, AI lite and Kafka workers. They are configured with `restart: "no"` and must not be left running on the micro VM.

## Status

```bash
./ops/oci/status_micro.sh
```

Check that all heavy services are stopped and have restart policy `no`.
The status command also enforces the host port rule: ports `5000`, `5432`
and `6379` must not be listening on the host. Only Nginx on port `80`
should expose the application path.

## Daily DR Check

Run this read-only check after changes and during routine operations:

```bash
./ops/oci/dr_check.sh
```

It fails if:

- Any micro container is missing, stopped or unhealthy.
- Any heavy stack container is running on the micro VM.
- Host ports `5000`, `5432` or `6379` are listening.
- No Postgres backup exists, or the latest backup is older than 36 hours.
- `ops/oci/runtime/host_metrics.json` is missing or older than 15 minutes.
- Cron is missing `watchdog_micro.sh`, `write_host_metrics.sh`, `backup_postgres.sh` or the weekly restore validation.

The check is intentionally non-destructive. It does not restart containers,
change cron, restore backups, delete files or modify volumes.

## Backups

Daily Postgres backups are handled by cron:

```bash
./ops/oci/backup_postgres.sh
```

Backups are written to `/home/ubuntu/sentinela/backups/postgres` as `.sql.gz` files with a `.manifest.json` sidecar containing hash, size and origin metadata. The script keeps the last 7 days. Copy these files outside the VPS after every important change.

Test the latest backup restore without touching production:

```bash
./ops/oci/test_restore_backup.sh
```

The restore test uses a temporary isolated Postgres container, validates that the schema restores, and removes the temporary container. It must not restore into `sentinela-db-lite`.

The generic recovery scripts live in `ops/recovery/`:

```bash
./ops/recovery/backup_postgres.sh
./ops/recovery/verify_restore.sh
./ops/recovery/dr_check.sh
```

Use `ops/recovery/RUNBOOK.md` when rebuilding on a clean VPS.

Copy backups outside the VPS after each important change. Current local off-VPS target used by the operator:

```text
D:\sentinela_backups
```

## Watchdog

The API and web watchdog runs from cron every 2 minutes:

```bash
./ops/oci/watchdog_micro.sh
```

It checks `http://127.0.0.1/ready` and `http://127.0.0.1/health` through
Nginx, then restarts only the affected lite container. Do not publish API
port `5000` on the host just for monitoring.

## Host Metrics

Minimal host metrics are written every 5 minutes:

```bash
./ops/oci/write_host_metrics.sh
```

Public endpoint:

```text
http://163.176.204.190/runtime/host_metrics.json
```

This exposes RAM, swap, disk, uptime and load average only. The same script appends a small JSONL history to `ops/oci/runtime/host_metrics.jsonl` and keeps the last 14 days at the default 5 minute interval. It does not start Prometheus, Grafana or Jaeger.

## Firewall

The micro VM should expose only SSH and HTTP:

```bash
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw --force enable
```

OCI Security List should also expose only ports 22 and 80.

Local host enforcement:

```bash
./ops/oci/check_host_ports.sh
```

This command must fail if `5000`, `5432` or `6379` are listening on the host.
Postgres and Redis stay inside the Docker network, and the API stays behind
Nginx.

## Data Safety

Do not delete Docker volumes unless a backup exists. In particular, do not remove `sentinela_sentinela-db-data`.

Do not run `docker compose down -v`, `docker volume rm`, or `docker system prune` without explicit confirmation.

## Architecture Rule

The micro VM is the control plane and demo dashboard. Kafka, Jaeger, AI and simulators are on-demand test tools. If the SOC pipeline needs to run continuously, migrate to Ampere A1 or split the services across multiple hosts.

## Optional Ampere A1 Lab

Ampere A1 is optional capacity. It must not be required for the AMD micro stack
to stay online.

Use the isolated creation helper from an operator machine with OCI CLI
configured:

```bash
OCI_CONFIG_FILE=/path/to/oci/config ./ops/oci/try_create_ampere_a1.sh
OCI_CONFIG_FILE=/path/to/oci/config ./ops/oci/try_create_ampere_a1.sh --execute
```

Default request:

```text
VM.Standard.A1.Flex
1 OCPU
6 GB RAM
display-name: SENTINELA-ARM-HEAVY
```

The helper only requests a new ARM instance and lists matching instances after
the attempt. It does not touch `SENTINELA-AMD-TEST`, Docker containers, volumes,
DNS, Nginx or production data. If OCI returns `Out of host capacity`, keep the
micro stack as the active 24/7 base and retry later.

After a successful creation, bootstrap manually and validate only the basics
first: SSH access, Docker availability, repository checkout and
`docker compose config`. Do not migrate production or start the heavy stack
automatically.

## Future DNS and HTTPS

The current public URL is `http://163.176.204.190`. A future production hardening pass should add:

- DNS name for the service.
- HTTPS termination.
- Cloudflare or equivalent edge protection.
- Certificate renewal automation.
