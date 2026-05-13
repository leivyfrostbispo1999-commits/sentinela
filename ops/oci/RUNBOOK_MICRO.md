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

## Backups

Daily Postgres backups are handled by cron:

```bash
./ops/oci/backup_postgres.sh
```

Backups are written to `/home/ubuntu/sentinela/backups/postgres` as `.sql.gz` files. The script keeps the last 7 days. Future hardening should copy these files outside the VPS.

Test the latest backup restore without touching production:

```bash
./ops/oci/test_restore_backup.sh
```

The restore test uses a temporary isolated Postgres container, validates that the schema restores, and removes the temporary container. It must not restore into `sentinela-db-lite`.

Copy backups outside the VPS after each important change. Current local off-VPS target used by the operator:

```text
D:\sentinela_backups
```

## Watchdog

The API and web watchdog runs from cron every 2 minutes:

```bash
./ops/oci/watchdog_micro.sh
```

It checks `http://127.0.0.1:5000/ready` and `http://127.0.0.1/health`, then restarts only the affected lite container.

## Host Metrics

Minimal host metrics are written every 5 minutes:

```bash
./ops/oci/write_host_metrics.sh
```

Public endpoint:

```text
http://163.176.204.190/runtime/host_metrics.json
```

This exposes RAM, swap, disk, uptime and load average only. It does not start Prometheus, Grafana or Jaeger.

## Firewall

The micro VM should expose only SSH and HTTP:

```bash
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw --force enable
```

OCI Security List should also expose only ports 22 and 80.

## Data Safety

Do not delete Docker volumes unless a backup exists. In particular, do not remove `sentinela_sentinela-db-data`.

Do not run `docker compose down -v`, `docker volume rm`, or `docker system prune` without explicit confirmation.

## Architecture Rule

The micro VM is the control plane and demo dashboard. Kafka, Jaeger, AI and simulators are on-demand test tools. If the SOC pipeline needs to run continuously, migrate to Ampere A1 or split the services across multiple hosts.

## Future DNS and HTTPS

The current public URL is `http://163.176.204.190`. A future production hardening pass should add:

- DNS name for the service.
- HTTPS termination.
- Cloudflare or equivalent edge protection.
- Certificate renewal automation.
