import importlib.util
import json
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]


def load_module(name, relative):
    for existing_name in ("websocket_gateway_tests", name):
        module = sys.modules.get(existing_name)
        if module is not None and "websocket_gateway" in str(relative) and hasattr(module, "handle_bus_message"):
            return module
        if module is not None and "websocket_gateway" in str(relative) and not hasattr(module, "handle_bus_message"):
            sys.modules.pop(existing_name, None)
    if name in sys.modules:
        return sys.modules[name]
    path = ROOT / relative
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.mark.asyncio
async def test_in_memory_pipeline_fluentbit_nats_parser_detection_api_websocket(monkeypatch):
    parser = load_module("e2e_parser", Path("services/parser_engine/parser.py"))
    engine_module = load_module("e2e_detection", Path("services/detection_engine/engine.py"))
    gateway = load_module("e2e_gateway", Path("services/websocket_gateway/main.py"))

    class FakeCore:
        def __init__(self):
            self.alerts = []

        def ingest(self, alert):
            self.alerts.append(alert)
            return {"status": "ok", "event_id": alert["event_id"]}

    class FakeWebsocket:
        def __init__(self):
            self.messages = []

        async def send(self, payload):
            self.messages.append(json.loads(payload))

    core = FakeCore()
    ws = FakeWebsocket()
    gateway.CLIENTS.clear()
    gateway.CLIENTS.add(ws)
    detector = engine_module.DetectionEngine(ROOT / "infra" / "detection_rules")

    for index in range(5):
        fluent_bit_record = {
            "source": "/var/log/auth.log",
            "host": "core-1",
            "log": f"May 16 19:30:0{index} core-1 sshd[999]: Failed password for invalid user codex from 203.0.113.200 port 5122{index} ssh2",
            "timestamp": "2026-05-16T19:30:00+00:00",
        }
        normalized = parser.normalize_record(fluent_bit_record)
        assert REQUIRED_EVENT_FIELDS.issubset(normalized)
        for alert in detector.evaluate(normalized):
            core.ingest(alert)
            await gateway.handle_bus_message(json.dumps(alert).encode("utf-8"))

    brute = [alert for alert in core.alerts if alert["internal_rule_id"] == "ssh_bruteforce"]
    assert brute
    assert brute[-1]["mitre_id"] == "T1110"
    assert brute[-1]["severity"] == "HIGH"
    assert any(message["type"] == "alert" and message["data"]["internal_rule_id"] == "ssh_bruteforce" for message in ws.messages)


REQUIRED_EVENT_FIELDS = {
    "timestamp",
    "host",
    "source_ip",
    "destination_ip",
    "event_type",
    "severity",
    "username",
    "raw_log",
    "tags",
    "technique",
    "service",
}
