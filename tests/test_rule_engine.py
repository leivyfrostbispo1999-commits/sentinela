import importlib.util
import sys
import types
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RULE_ENGINE_PATH = ROOT / "services" / "rule_engine"
sys.path.insert(0, str(RULE_ENGINE_PATH))

if "kafka" not in sys.modules:
    sys.modules["kafka"] = types.SimpleNamespace(KafkaConsumer=object, KafkaProducer=object)


def load_rule_engine(monkeypatch):
    monkeypatch.setenv("REDIS_STATE_ENABLED", "false")
    module_name = f"sentinela_rule_engine_main_{uuid.uuid4().hex}"
    spec = importlib.util.spec_from_file_location(module_name, RULE_ENGINE_PATH / "main.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    module.STATE_STORE = module.InMemoryCorrelationStore(module.STATE_WINDOW_SECONDS)
    return module


def make_event(ip="20.20.20.20", event_type="PORT_SCAN", port=80, service="http", ts=None):
    return {
        "ip": ip,
        "event_type": event_type,
        "port": port,
        "service": service,
        "ts": ts,
    }


def test_risk_scoring_increases_for_brute_force_on_sensitive_port(monkeypatch):
    rule_engine = load_rule_engine(monkeypatch)
    event = {"ip": "10.10.10.10", "event_type": "BRUTE_FORCE", "port": 22, "service": "ssh"}
    events = rule_engine.update_state(event)

    status, risk, reasons = rule_engine.calculate_risk(event, events, None, [])

    assert status == "BRUTE FORCE"
    assert risk >= 88
    assert "porta_sensivel" in reasons


def test_yaml_multistage_detection(monkeypatch):
    rule_engine = load_rule_engine(monkeypatch)
    rules = [
        {
            "name": "ataque_multi_etapa",
            "enabled": True,
            "priority": 80,
            "conditions": ["PORT_SCAN", "BRUTE_FORCE"],
            "min_risk": 97,
            "status": "ATAQUE MULTIETAPA",
        }
    ]

    scan = {"ip": "20.20.20.20", "event_type": "PORT_SCAN", "port": 22, "service": "ssh"}
    brute = {"ip": "20.20.20.20", "event_type": "BRUTE_FORCE", "port": 22, "service": "ssh"}
    rule_engine.update_state(scan)
    events = rule_engine.update_state(brute)

    status, risk, reasons = rule_engine.calculate_risk(brute, events, None, rules)

    assert status == "ATAQUE MULTIETAPA"
    assert risk >= 97
    assert "regra_yaml:ataque_multi_etapa" in reasons


def test_simulated_block_for_critical_risk(monkeypatch):
    rule_engine = load_rule_engine(monkeypatch)

    action, simulated_block = rule_engine.simulated_auto_response("IOC DETECTADO", 98, True)

    assert action == "simulated_block"
    assert simulated_block is True


def test_aggregation_collapses_repeated_events_by_ip_and_status(monkeypatch):
    rule_engine = load_rule_engine(monkeypatch)
    rule_engine.STATE_STORE = rule_engine.InMemoryCorrelationStore(rule_engine.STATE_WINDOW_SECONDS)
    base_ts = datetime(2026, 5, 3, 12, 0, tzinfo=timezone.utc)
    first = make_event(ts=base_ts.isoformat())
    second = make_event(ts=(base_ts + timedelta(seconds=10)).isoformat())

    events_1 = rule_engine.update_state(first)
    status_1, risk_1, reasons_1 = rule_engine.calculate_risk(first, events_1, None, [])
    auto_1, block_1 = rule_engine.simulated_auto_response(status_1, risk_1, False)
    alert_1 = rule_engine.build_alert(first, status_1, risk_1, events_1, reasons_1, auto_1, block_1, None, "key-1", "reason-1")

    events_2 = rule_engine.update_state(second)
    status_2, risk_2, reasons_2 = rule_engine.calculate_risk(second, events_2, None, [])
    auto_2, block_2 = rule_engine.simulated_auto_response(status_2, risk_2, False)
    alert_2 = rule_engine.build_alert(second, status_2, risk_2, events_2, reasons_2, auto_2, block_2, None, "key-1", "reason-1")

    assert alert_1["occurrence_count"] == 1
    assert alert_2["occurrence_count"] == 2
    assert alert_2["aggregated"] is True
    assert alert_2["ports"] == [80]
    assert alert_2["services"] == ["http"]
    assert alert_2["event_types"] == ["PORT_SCAN"]
    assert alert_2["simulated_block"] is False
    assert alert_2["action_soc"] in {"MONITORADO", "INVESTIGANDO"}


def test_aggregation_window_expires_old_entries(monkeypatch):
    rule_engine = load_rule_engine(monkeypatch)
    rule_engine.ALERT_AGGREGATION_WINDOW_SECONDS = 30
    rule_engine.STATE_STORE = rule_engine.InMemoryCorrelationStore(rule_engine.STATE_WINDOW_SECONDS)
    base_ts = datetime(2026, 5, 3, 12, 0, tzinfo=timezone.utc)
    first = make_event(ts=base_ts.isoformat())
    second = make_event(ts=(base_ts + timedelta(seconds=61)).isoformat())

    events_1 = rule_engine.update_state(first)
    status_1, risk_1, reasons_1 = rule_engine.calculate_risk(first, events_1, None, [])
    auto_1, block_1 = rule_engine.simulated_auto_response(status_1, risk_1, False)
    rule_engine.build_alert(first, status_1, risk_1, events_1, reasons_1, auto_1, block_1, None, "key-2", "reason-2")

    events_2 = rule_engine.update_state(second)
    status_2, risk_2, reasons_2 = rule_engine.calculate_risk(second, events_2, None, [])
    auto_2, block_2 = rule_engine.simulated_auto_response(status_2, risk_2, False)
    alert_2 = rule_engine.build_alert(second, status_2, risk_2, events_2, reasons_2, auto_2, block_2, None, "key-2", "reason-2")

    assert alert_2["occurrence_count"] == 1
    assert alert_2["aggregated"] is False


def test_normal_traffic_keeps_low_risk(monkeypatch):
    rule_engine = load_rule_engine(monkeypatch)
    event = {"ip": "30.30.30.30", "event_type": "HTTP_REQUEST", "port": 443, "service": "https"}
    events = rule_engine.update_state(event)

    status, risk, _ = rule_engine.calculate_risk(event, events, None, [])

    assert status == "TRÁFEGO NORMAL"
    assert risk <= 34


def test_fallback_without_redis_uses_memory_store(monkeypatch):
    rule_engine = load_rule_engine(monkeypatch)

    assert isinstance(rule_engine.STATE_STORE, rule_engine.InMemoryCorrelationStore)
