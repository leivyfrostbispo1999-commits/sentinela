import asyncio
import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]


def load_ingestion():
    if "ingestion_worker_tests" in sys.modules:
        return sys.modules["ingestion_worker_tests"]
    path = ROOT / "services" / "ingestion_worker" / "main.py"
    spec = importlib.util.spec_from_file_location("ingestion_worker_tests", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class FakeNats:
    def __init__(self):
        self.messages = []

    async def publish(self, subject, data):
        self.messages.append((subject, json.loads(data.decode("utf-8"))))


def test_build_log_payload_handles_newlines_and_source():
    ingestion = load_ingestion()
    payload = ingestion.build_log_payload(Path("/host/var/log/auth.log"), "line\n", timestamp="2026-05-16T19:00:00Z")
    assert payload == {
        "source": "/host/var/log/auth.log",
        "log": "line",
        "timestamp": "2026-05-16T19:00:00Z",
    }


def test_publish_log_line_uses_raw_subject():
    ingestion = load_ingestion()
    nc = FakeNats()
    asyncio.run(ingestion.publish_log_line(nc, "/host/var/log/syslog", "sudo: test", subject="sentinela.logs.raw"))
    assert nc.messages[0][0] == "sentinela.logs.raw"
    assert nc.messages[0][1]["log"] == "sudo: test"


def test_connect_nats_missing_dependency_graceful(monkeypatch):
    ingestion = load_ingestion()
    monkeypatch.setattr(ingestion, "nats", None)
    try:
        asyncio.run(ingestion.connect_nats())
    except RuntimeError as exc:
        assert "nats-py" in str(exc)
    else:
        raise AssertionError("connect_nats should fail fast when nats-py is absent")


def test_connect_nats_retries_then_sets_ready(monkeypatch):
    ingestion = load_ingestion()
    attempts = {"count": 0}

    async def fake_connect(**_kwargs):
        attempts["count"] += 1
        if attempts["count"] == 1:
            raise OSError("bus offline")
        return object()

    async def no_sleep(_delay):
        return None

    monkeypatch.setattr(ingestion, "nats", SimpleNamespace(connect=fake_connect))
    monkeypatch.setattr(ingestion.asyncio, "sleep", no_sleep)

    nc = asyncio.run(ingestion.connect_nats())
    assert nc is not None
    assert attempts["count"] == 2
    assert ingestion.SERVICE_READY.labels(service="ingestion_worker")._value.get() == 1


def test_follow_file_publishes_existing_lines_then_can_be_cancelled(tmp_path, monkeypatch):
    ingestion = load_ingestion()
    log_file = tmp_path / "auth.log"
    log_file.write_text("first\nsecond\n", encoding="utf-8")
    nc = FakeNats()

    async def cancel_sleep(_delay):
        raise asyncio.CancelledError()

    monkeypatch.setattr(ingestion.asyncio, "sleep", cancel_sleep)

    try:
        asyncio.run(ingestion.follow_file(nc, log_file))
    except asyncio.CancelledError:
        pass

    assert [message[1]["log"] for message in nc.messages] == ["first", "second"]
