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
    assert dlq["tenant_id"] == "tenant-a"
