import importlib.util
import sys
import types
import uuid
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "replay_attack.py"


def load_replay():
    sys.modules["kafka"] = types.SimpleNamespace(KafkaConsumer=object, KafkaProducer=object)
    module_name = f"sentinela_replay_attack_{uuid.uuid4().hex}"
    spec = importlib.util.spec_from_file_location(module_name, SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def test_replay_scenarios_are_defined():
    replay = load_replay()

    assert {"brute_force", "port_scan", "ioc_match", "critical_chain", "false_positive", "multi_ip", "multi_ip_campaign"} <= replay.SCENARIOS


def test_critical_chain_events_are_simulated_only():
    replay = load_replay()
    events = replay.scenario_events("critical_chain", "replay-test")

    assert len(events) >= 6
    assert all(event["is_replay_event"] is True for event in events)
    assert all(event["simulated_only"] is True for event in events)
    assert {event["event_type"] for event in events} >= {"PORT_SCAN", "BRUTE_FORCE", "IOC_MATCH"}


def test_multi_ip_campaign_keeps_same_target_and_replay_id():
    replay = load_replay()
    events = replay.scenario_events("multi_ip_campaign", "replay-campaign")

    assert len({event["source_ip"] for event in events}) >= 3
    assert {event["destination_ip"] for event in events} == {"10.10.10.10"}
    assert {event["username"] for event in events} == {"scanner", "admin"}
    assert all(event["replay_id"] == "replay-campaign" for event in events)
    assert all(event["is_replay_event"] is True for event in events)
