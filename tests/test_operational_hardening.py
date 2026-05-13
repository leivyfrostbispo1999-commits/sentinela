import importlib.util
import json
import sys
import types
import uuid
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
_ALERT_SINK_MODULE = None


def load_module(path):
    module_name = f"sentinela_test_{uuid.uuid4().hex}"
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def load_alert_sink_module():
    global _ALERT_SINK_MODULE
    if _ALERT_SINK_MODULE is None:
        sys.modules["kafka"] = types.SimpleNamespace(KafkaConsumer=object, KafkaProducer=object, TopicPartition=object)
        sys.modules["psycopg2"] = types.SimpleNamespace(Error=Exception, connect=lambda **_: None)
        _ALERT_SINK_MODULE = load_module(ROOT / "services" / "alert-sink" / "main.py")
    return _ALERT_SINK_MODULE


def load_pipeline_resilience_module():
    return load_module(ROOT / "services" / "common" / "pipeline_resilience.py")


def test_secret_resolver_env_and_file(monkeypatch, tmp_path):
    secrets = load_module(ROOT / "services" / "common" / "secrets.py")
    secret_file = tmp_path / "jwt.txt"
    secret_file.write_text("from-file", encoding="utf-8")

    monkeypatch.setenv("SENTINELA_ENV", "production")
    monkeypatch.setenv("SENTINELA_JWT_SECRET", "from-env")
    assert secrets.resolve_secret("SENTINELA_JWT_SECRET", required=True) == "from-env"

    monkeypatch.delenv("SENTINELA_JWT_SECRET")
    monkeypatch.setenv("SENTINELA_JWT_SECRET_FILE", str(secret_file))
    assert secrets.resolve_secret("SENTINELA_JWT_SECRET", required=True) == "from-file"


def test_secret_resolver_rejects_default_in_production(monkeypatch):
    secrets = load_module(ROOT / "services" / "common" / "secrets.py")
    monkeypatch.setenv("SENTINELA_ENV", "production")
    monkeypatch.setenv("SENTINELA_JWT_SECRET", "sentinela-demo-jwt-secret")

    try:
        secrets.resolve_secret("SENTINELA_JWT_SECRET", required=True)
        raised = False
    except RuntimeError:
        raised = True

    assert raised is True


def test_retention_plan_is_safe_and_uses_env(monkeypatch):
    retention = load_module(ROOT / "scripts" / "retention_cleanup.py")
    monkeypatch.setenv("RETENTION_ALERTS_DAYS", "7")

    plan = retention.build_retention_plan()

    assert {"table": "alertas", "column": "ts", "days": 7} in plan
    assert any(item["table"] == "audit_logs" for item in plan)


def test_replay_events_file_dry_run_filters_tenant(tmp_path):
    replay = load_module(ROOT / "scripts" / "replay_events.py")
    exported = tmp_path / "dlq.jsonl"
    exported.write_text(
        "\n".join([
            json.dumps({"tenant_id": "tenant-a", "correlation_id": "cid-a", "original_event": {"event_id": "a", "tenant_id": "tenant-a"}}),
            json.dumps({"tenant_id": "tenant-b", "correlation_id": "cid-b", "original_event": {"event_id": "b", "tenant_id": "tenant-b"}}),
        ]),
        encoding="utf-8",
    )

    args = types.SimpleNamespace(source="file", file=str(exported), tenant="tenant-a", limit=10, dlq_topic="dead_letter_events", group_id="test", consumer_timeout_ms=100)
    events = replay.select_events(args)

    assert len(events) == 1
    assert events[0]["tenant_id"] == "tenant-a"
    assert events[0]["correlation_id"] == "cid-a"


def test_alert_sink_idempotency_key_is_deterministic(monkeypatch):
    alert_sink = load_alert_sink_module()
    event = {
        "tenant_id": "tenant-a",
        "correlation_id": "cid-1",
        "internal_rule_id": "BRUTE_FORCE",
        "timestamp": "2026-05-06T10:00:00Z",
        "ip": "10.0.0.1",
        "status": "BRUTE FORCE",
    }

    first = alert_sink.idempotency_key_for_alert(dict(event))
    second = alert_sink.idempotency_key_for_alert(dict(event))
    alert = dict(event)
    event_id = alert_sink.ensure_event_id(alert)

    assert first == second
    assert alert["idempotency_key"] == first
    assert event_id


def test_alert_sink_dlq_payload_shape(monkeypatch):
    alert_sink = load_alert_sink_module()

    dlq = alert_sink.build_dlq_event({"tenant_id": "tenant-a", "correlation_id": "cid"}, ValueError("bad"), retry_count=2)

    assert dlq["failed_service"] == "alert_sink"
    assert dlq["source_topic"] == alert_sink.ALERTS_TOPIC
    assert dlq["retry_count"] == 2
    assert dlq["max_retry_count"] == alert_sink.PIPELINE_MAX_RETRIES
    assert dlq["retry_strategy"] == "exponential_backoff"
    assert dlq["pipeline_priority"] in {"low", "medium", "high"}
    assert dlq["tenant_id"] == "tenant-a"


def test_pipeline_resilience_breaker_and_priority():
    resilience = load_pipeline_resilience_module()

    assert resilience.event_priority({"severity": "CRITICAL"}) == "high"
    assert resilience.event_priority({"severity": "LOW"}) == "low"
    assert resilience.retry_backoff_seconds(0, base_ms=500, max_seconds=10, priority="high", jitter_ratio=0) == 0.375

    breaker = resilience.CircuitBreaker(failure_threshold=2, recovery_seconds=10)
    assert breaker.allow(now=100) is True
    breaker.record_failure(now=100)
    assert breaker.allow(now=101) is True
    breaker.record_failure(now=101)
    assert breaker.allow(now=102) is False
    assert breaker.remaining_seconds(now=105) == 6.0


def test_micro_ops_enforces_private_ports():
    port_guard = (ROOT / "ops" / "oci" / "check_host_ports.sh").read_text(encoding="utf-8")
    status_micro = (ROOT / "ops" / "oci" / "status_micro.sh").read_text(encoding="utf-8")
    runbook = (ROOT / "ops" / "oci" / "RUNBOOK_MICRO.md").read_text(encoding="utf-8")
    compose_micro = (ROOT / "docker-compose.micro.yml").read_text(encoding="utf-8")

    for port in ("5000", "5432", "6379"):
        assert port in port_guard
        assert port in runbook

    assert "ss -tulpen" in port_guard
    assert "exit 1" in port_guard
    assert "ops/oci/check_host_ports.sh" in status_micro
    assert '"80:80"' in compose_micro
    assert '"5000:5000"' not in compose_micro
    assert '"5432:5432"' not in compose_micro
    assert '"6379:6379"' not in compose_micro


def test_ampere_a1_helper_is_isolated_and_conservative():
    helper = (ROOT / "ops" / "oci" / "try_create_ampere_a1.sh").read_text(encoding="utf-8")
    shape = json.loads((ROOT / "ops" / "oci" / "sentinela-arm-shape-1x6.json").read_text(encoding="utf-8"))
    runbook = (ROOT / "ops" / "oci" / "RUNBOOK_MICRO.md").read_text(encoding="utf-8")

    assert shape == {"ocpus": 1, "memoryInGBs": 6}
    assert "--execute" in helper
    assert "Dry run only" in helper
    assert "VM.Standard.A1.Flex" in helper
    assert "SENTINELA-ARM-HEAVY" in helper
    assert "does not touch SENTINELA-AMD-TEST" in helper
    assert "docker compose down" not in helper
    assert "docker volume rm" not in helper
    assert "SENTINELA-AMD-TEST" in runbook
    assert "Out of host capacity" in runbook


def test_dr_check_is_read_only_and_covers_recovery_guardrails():
    dr_check = (ROOT / "ops" / "oci" / "dr_check.sh").read_text(encoding="utf-8")
    runbook = (ROOT / "ops" / "oci" / "RUNBOOK_MICRO.md").read_text(encoding="utf-8")

    for expected in (
        "sentinela-web-lite",
        "sentinela-api-lite",
        "sentinela-db-lite",
        "sentinela-redis-lite",
        "check_heavy_stack_stopped",
        "ops/oci/check_host_ports.sh",
        "backup_postgres.sh",
        "test_restore_backup.sh",
        "write_host_metrics.sh",
        "watchdog_micro.sh",
        "DR_CHECK_STATUS=ok",
        "DR_CHECK_STATUS=fail",
    ):
        assert expected in dr_check

    assert "SENTINELA_BACKUP_MAX_AGE_HOURS:-36" in dr_check
    assert "SENTINELA_HOST_METRICS_MAX_AGE_MINUTES:-15" in dr_check
    assert "docker restart" not in dr_check
    assert "docker compose down" not in dr_check
    assert "docker volume rm" not in dr_check
    assert "rm -rf" not in dr_check
    assert "./ops/oci/dr_check.sh" in runbook
    assert "intentionally non-destructive" in runbook


def test_recovery_scripts_validate_restore_without_touching_production():
    backup = (ROOT / "ops" / "recovery" / "backup_postgres.sh").read_text(encoding="utf-8")
    restore = (ROOT / "ops" / "recovery" / "verify_restore.sh").read_text(encoding="utf-8")
    dr_check = (ROOT / "ops" / "recovery" / "dr_check.sh").read_text(encoding="utf-8")
    runbook = (ROOT / "ops" / "recovery" / "RUNBOOK.md").read_text(encoding="utf-8")

    assert "pg_dump" in backup
    assert "sha256sum" in backup
    assert ".manifest.json" in backup
    assert "SENTINELA_BACKUP_RETENTION_DAYS:-7" in backup
    assert "find \"$backup_dir\"" in backup

    assert "--network none" in restore
    assert "postgres:15-alpine" in restore
    assert "restore_last.json" in restore
    assert "to_regclass('public.${required_table}')" in restore
    assert "sentinela-db-lite psql" not in restore

    assert "RECOVERY_CHECK_STATUS=ok" in dr_check
    assert "RECOVERY_CHECK_STATUS=fail" in dr_check
    assert "restore validation result" in dr_check
    assert "host metrics history" in dr_check

    for forbidden in ("docker compose down", "docker volume rm", "rm -rf"):
        assert forbidden not in backup
        assert forbidden not in restore
        assert forbidden not in dr_check

    assert "VPS nova" in runbook
    assert "backup validado" in runbook
    assert "docker compose down -v" in runbook


def test_micro_cron_covers_backup_restore_and_metrics_history():
    cron = (ROOT / "ops" / "oci" / "install_micro_cron.sh").read_text(encoding="utf-8")
    metrics = (ROOT / "ops" / "oci" / "write_host_metrics.sh").read_text(encoding="utf-8")
    gitignore = (ROOT / ".gitignore").read_text(encoding="utf-8")

    assert "ops/oci/backup_postgres.sh" in cron
    assert "ops/oci/test_restore_backup.sh" in cron
    assert "ops/recovery/verify_restore.sh" in cron
    assert "host_metrics.jsonl" in metrics
    assert "SENTINELA_HOST_METRICS_RETENTION_DAYS:-14" in metrics
    assert "tail -n \"$max_history_lines\"" in metrics
    assert "backups/" in gitignore
    assert "ops/oci/runtime/*.jsonl" in gitignore
