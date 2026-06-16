import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[1]


def load_gateway():
    for name in ("websocket_gateway_tests", "e2e_gateway"):
        module = sys.modules.get(name)
        if module is not None and hasattr(module, "handle_bus_message"):
            return module
        if module is not None and not hasattr(module, "handle_bus_message"):
            sys.modules.pop(name, None)
    path = ROOT / "services" / "websocket_gateway" / "main.py"
    spec = importlib.util.spec_from_file_location("websocket_gateway_tests", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class FakeClient:
    def __init__(self, fail=False):
        self.messages = []
        self.fail = fail

    async def send(self, payload):
        if self.fail:
            raise RuntimeError("closed")
        self.messages.append(json.loads(payload))

    async def wait_closed(self):
        return None


@pytest.mark.asyncio
async def test_realtime_delivery_to_multiple_clients_and_dropped_connections():
    gateway = load_gateway()
    gateway.CLIENTS.clear()
    ok_a = FakeClient()
    ok_b = FakeClient()
    dead = FakeClient(fail=True)
    gateway.CLIENTS.update({ok_a, ok_b, dead})

    await gateway.broadcast({"event_type": "BRUTE_FORCE", "source_ip": "203.0.113.10"})

    assert ok_a.messages[0]["type"] == "alert"
    assert ok_b.messages[0]["data"]["source_ip"] == "203.0.113.10"
    assert dead not in gateway.CLIENTS


@pytest.mark.asyncio
async def test_malformed_payload_is_counted_and_does_not_crash():
    gateway = load_gateway()
    gateway.CLIENTS.clear()
    assert await gateway.handle_bus_message(b"{not-json") is False


@pytest.mark.asyncio
async def test_handle_bus_message_broadcasts_valid_payload():
    gateway = load_gateway()
    gateway.CLIENTS.clear()
    client = FakeClient()
    gateway.CLIENTS.add(client)

    delivered = await gateway.handle_bus_message(json.dumps({"severity": "HIGH"}).encode("utf-8"))

    assert delivered is True
    assert client.messages[0]["type"] == "alert"
    assert client.messages[0]["data"]["severity"] == "HIGH"


@pytest.mark.asyncio
async def test_connect_nats_retries_then_recovers(monkeypatch):
    gateway = load_gateway()
    attempts = {"count": 0}

    async def fake_connect(**_kwargs):
        attempts["count"] += 1
        if attempts["count"] == 1:
            raise OSError("offline")
        return object()

    async def no_sleep(_delay):
        return None

    monkeypatch.setattr(gateway, "nats", SimpleNamespace(connect=fake_connect))
    monkeypatch.setattr(gateway.asyncio, "sleep", no_sleep)

    nc = await gateway.connect_nats()
    assert nc is not None
    assert attempts["count"] == 2
    assert gateway.NATS_CONNECTED._value.get() == 1


def test_encode_alert_contract():
    gateway = load_gateway()
    payload = json.loads(gateway.encode_alert({"event_type": "TEST"}))
    assert payload == {"type": "alert", "data": {"event_type": "TEST"}}


@pytest.mark.asyncio
async def test_ws_handler_sends_ready_and_removes_client():
    gateway = load_gateway()
    gateway.CLIENTS.clear()
    client = FakeClient()

    await gateway.ws_handler(client)

    assert client.messages[0]["type"] == "ready"
    assert client not in gateway.CLIENTS
