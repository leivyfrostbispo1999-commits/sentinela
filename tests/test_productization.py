import importlib.util
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def test_timeline_reconstruction_sequence_and_scores():
    engine = load_module("timeline_engine_product_tests", Path("services/timeline_engine/engine.py"))
    alerts = [
        {
            "timestamp": "2026-05-16T10:11:00+00:00",
            "event_type": "FAILED_LOGIN",
            "severity": "MEDIUM",
            "source_ip": "203.0.113.1",
            "target_host": "core",
            "mitre_id": "T1110",
            "threat_score": 55,
        },
        {
            "timestamp": "2026-05-16T10:12:00+00:00",
            "event_type": "BRUTE_FORCE",
            "severity": "HIGH",
            "source_ip": "203.0.113.1",
            "target_host": "core",
            "mitre_id": "T1110",
            "threat_score": 85,
        },
        {
            "timestamp": "2026-05-16T10:14:00+00:00",
            "event_type": "SUDO_COMMAND",
            "severity": "HIGH",
            "source_ip": "203.0.113.1",
            "target_user": "root",
            "target_host": "core",
            "mitre_id": "T1548",
            "threat_score": 80,
        },
    ]
    result = engine.build_incident_timeline("INC-1", alerts)
    assert result["incident_id"] == "INC-1"
    assert result["risk_score"] == 85
    assert result["mitre_sequence"] == ["T1110", "T1548"]
    assert [item["sequence_index"] for item in result["timeline"]] == [1, 2, 3]
    assert result["timeline"][1]["related_to_previous"] is True


def test_correlation_engine_builds_entity_graph_and_lateral_movement():
    module = load_module("correlation_engine_product_tests", Path("services/correlation_engine/engine.py"))
    engine = module.CorrelationEngine(window_seconds=900)
    result = engine.correlate(
        [
            {
                "timestamp": "2026-05-16T10:00:00+00:00",
                "source_ip": "203.0.113.1",
                "host": "core-a",
                "username": "alice",
                "mitre_id": "T1110",
                "threat_score": 55,
            },
            {
                "timestamp": "2026-05-16T10:05:00+00:00",
                "source_ip": "203.0.113.1",
                "host": "core-b",
                "username": "alice",
                "mitre_id": "T1548",
                "threat_score": 80,
            },
            {
                "timestamp": "2026-05-16T10:06:00+00:00",
                "source_ip": "203.0.113.1",
                "host": "core-c",
                "username": "alice",
                "mitre_id": "T1105",
                "threat_score": 70,
            },
        ]
    )
    assert result["lateral_movement_indicators"][0]["host_count"] == 3
    assert result["user_behavior"]["alice"]["event_count"] == 3
    assert any(item["ioc"] == "source_ip:203.0.113.1" for item in result["repeated_iocs"])


def test_replay_engine_filters_and_retention_plan():
    module = load_module("replay_engine_product_tests", Path("services/replay_engine/engine.py"))
    engine = module.ReplayEngine()
    job = engine.start(
        [
            {"timestamp": "2026-05-16T10:00:00+00:00", "host": "core-a", "source_ip": "203.0.113.1"},
            {"timestamp": "2026-05-16T12:00:00+00:00", "host": "core-b", "source_ip": "203.0.113.2"},
        ],
        {"host": "core-a"},
    )
    assert job["status"] == "completed"
    assert job["processed"] == 1
    assert engine.status(job["replay_id"])["processed"] == 1
    plan = module.retention_plan(retention_days=30, archive_after_days=10)
    assert plan["retention_days"] == 30
    assert plan["archive_after_days"] == 10


def load_api(monkeypatch):
    service_dir = str(ROOT / "services" / "dashboard_api")
    if service_dir not in sys.path:
        sys.path.insert(0, service_dir)
    monkeypatch.setenv("SENTINELA_ENV", "development")
    monkeypatch.setenv("SENTINELA_JWT_SECRET", "product-secret")
    monkeypatch.setenv("SENTINELA_API_TOKEN", "product-token")
    return load_module("dashboard_api_product_tests", Path("services/dashboard_api/main.py"))


def test_rule_studio_validation_and_retention_endpoint(monkeypatch):
    api = load_api(monkeypatch)
    client = api.app.test_client()
    token = {"X-SENTINELA-TOKEN": "product-token"}
    good_rule = {
        "rule_id": "studio-test",
        "title": "Studio Test",
        "description": "Detecta teste",
        "severity": "HIGH",
        "score": 80,
        "tactic": "Credential Access",
        "technique": "T1110",
        "conditions": {"event_type": "FAILED_LOGIN"},
        "aggregation": {"threshold": 3},
        "timeframe": 300,
        "enabled": True,
    }
    response = client.post("/api/rules/validate", json={"rule": good_rule}, headers=token)
    assert response.status_code == 200
    assert response.get_json()["valid"] is True
    bad = dict(good_rule, severity="NOPE")
    response = client.post("/api/rules/validate", json={"rule": bad}, headers=token)
    assert response.get_json()["valid"] is False
    response = client.get("/api/retention/policy", headers=token)
    assert response.status_code == 200
    assert response.get_json()["alerts_retention_days"] >= 180
