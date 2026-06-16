import importlib.util
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def test_parser_normalizes_ssh_failed_login():
    parser = load_module("sentinela_parser_engine_parser", ROOT / "services" / "parser_engine" / "parser.py")

    event = parser.normalize_record({
        "source": "/var/log/auth.log",
        "host": "core-1",
        "log": "May 16 18:00:01 core-1 sshd[123]: Failed password for invalid user admin from 203.0.113.10 port 51222 ssh2",
    })

    assert event["event_type"] == "FAILED_LOGIN"
    assert event["service"] == "ssh"
    assert event["source_ip"] == "203.0.113.10"
    assert event["username"] == "admin"
    assert event["technique"] == "T1110"


def test_detection_engine_hot_rules_emit_mitre_alert():
    engine_module = load_module("sentinela_detection_engine_engine", ROOT / "services" / "detection_engine" / "engine.py")
    engine = engine_module.DetectionEngine(ROOT / "infra" / "detection_rules")

    alerts = []
    for index in range(5):
        event = {
            "event_id": f"evt-{index}",
            "timestamp": "2026-05-16T18:00:00+00:00",
            "host": "core-1",
            "source_ip": "203.0.113.10",
            "event_type": "FAILED_LOGIN",
            "severity": "MEDIUM",
            "username": "admin",
            "raw_log": "Failed password for admin from 203.0.113.10 port 51222 ssh2",
            "tags": ["ssh"],
            "technique": "T1110",
            "service": "ssh",
        }
        alerts.extend(engine.evaluate(event))

    brute = [alert for alert in alerts if alert["internal_rule_id"] == "ssh_bruteforce"]
    assert brute
    assert brute[-1]["mitre_id"] == "T1110"
    assert brute[-1]["severity"] == "HIGH"
    assert brute[-1]["event_count"] >= 5

