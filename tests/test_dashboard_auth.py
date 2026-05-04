import importlib.util
import sys
import types
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
API_PATH = ROOT / "services" / "dashboard_api"
sys.path.insert(0, str(API_PATH))

if "psycopg2" not in sys.modules:
    sys.modules["psycopg2"] = types.SimpleNamespace(connect=lambda **_: None)


def load_api(monkeypatch):
    monkeypatch.setenv("SENTINELA_API_TOKEN", "sentinela-demo-token")
    monkeypatch.setenv("SENTINELA_JWT_SECRET", "unit-test-secret")
    module_name = f"sentinela_dashboard_api_main_{uuid.uuid4().hex}"
    spec = importlib.util.spec_from_file_location(module_name, API_PATH / "main.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


class FakeCursor:
    def __init__(self):
        self.statements = []

    def execute(self, statement, params=None):
        self.statements.append((statement, params))

    def fetchone(self):
        return [1]

    def fetchall(self):
        return []

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False


class FakeConnection:
    def __init__(self):
        self.cursor_obj = FakeCursor()
        self.commits = 0
        self.closed = False

    def cursor(self):
        return self.cursor_obj

    def commit(self):
        self.commits += 1

    def close(self):
        self.closed = True


def test_missing_token_is_rejected(monkeypatch):
    monkeypatch.setenv("ENABLE_AUTH", "true")
    api = load_api(monkeypatch)
    client = api.app.test_client()

    response = client.get("/alertas?range=5m")

    assert response.status_code == 401


def test_legacy_token_is_accepted(monkeypatch):
    api = load_api(monkeypatch)
    with api.app.test_request_context(headers={"X-SENTINELA-TOKEN": "sentinela-demo-token"}):
        assert api.token_is_valid() is True


def test_jwt_is_created_and_accepted(monkeypatch):
    api = load_api(monkeypatch)
    token = api.create_jwt(subject="pytest", ttl_seconds=60)

    assert api.verify_jwt(token) is True
    with api.app.test_request_context(headers={"Authorization": f"Bearer {token}"}):
        assert api.token_is_valid() is True


def test_invalid_jwt_is_rejected(monkeypatch):
    api = load_api(monkeypatch)

    assert api.verify_jwt("invalid.jwt.token") is False


def test_demo_simulation_requires_authentication(monkeypatch):
    monkeypatch.setenv("ENABLE_AUTH", "true")
    api = load_api(monkeypatch)
    client = api.app.test_client()

    response = client.post("/demo/simulate-attack")

    assert response.status_code == 401


def test_demo_simulation_generates_alerts_with_simulated_block(monkeypatch):
    api = load_api(monkeypatch)
    fake_conn = FakeConnection()
    monkeypatch.setattr(api, "get_connection", lambda: fake_conn)
    client = api.app.test_client()

    response = client.post("/demo/simulate-attack", headers={"X-SENTINELA-TOKEN": "sentinela-demo-token"})
    payload = response.get_json()

    assert response.status_code == 201
    assert payload["events_created"] == 7
    assert payload["simulated_block"] is True
    assert payload["real_blocking"] is False
    assert payload["primary_attacker"]["ip"] == "45.67.89.12"
    assert payload["primary_attacker"]["max_severity"] == "CRITICAL"
    assert "bloqueio simulado" in payload["incident_summary"]
    assert len(payload["timeline"]) == 7
    assert [item["severity"] for item in payload["timeline"][:2]] == ["LOW", "LOW"]
    assert [item["severity"] for item in payload["timeline"][2:4]] == ["MEDIUM", "MEDIUM"]
    assert [item["severity"] for item in payload["timeline"][4:]] == ["HIGH", "HIGH", "CRITICAL"]
    assert [alert["risco"] for alert in payload["alerts"]] == [24, 38, 58, 68, 82, 88, 94]
    assert all(not str(alert.get("mitre_id") or "").startswith("SENTINELA-") for alert in payload["alerts"])
    assert all(alert["human_summary"] for alert in payload["alerts"])
    assert all(alert["execution_mode"] == "simulation" for alert in payload["alerts"])
    assert all(alert["execution_status"] == "not_executed" for alert in payload["alerts"])
    assert all(alert["target_host"] for alert in payload["alerts"])
    assert all(alert["internal_rule_id"] for alert in payload["alerts"])
    assert any(alert["simulated_block"] for alert in payload["alerts"])
    assert any("DELETE FROM alertas WHERE is_demo = TRUE" in statement for statement, _ in fake_conn.cursor_obj.statements)
    assert any("is_demo" in statement and "INSERT INTO alertas" in statement for statement, _ in fake_conn.cursor_obj.statements)
    assert any("INSERT INTO alertas" in statement for statement, _ in fake_conn.cursor_obj.statements)
    assert fake_conn.commits >= 2


def test_alertas_demo_filter_uses_is_demo(monkeypatch):
    api = load_api(monkeypatch)
    fake_conn = FakeConnection()
    monkeypatch.setattr(api, "get_connection", lambda: fake_conn)
    client = api.app.test_client()

    response = client.get("/alertas?mode=demo", headers={"X-SENTINELA-TOKEN": "sentinela-demo-token"})

    assert response.status_code == 200
    assert response.get_json()["demo"] is True
    assert response.get_json()["mode"] == "demo"
    assert any("is_demo = TRUE" in statement for statement, _ in fake_conn.cursor_obj.statements)


def test_health_endpoint_still_works(monkeypatch):
    api = load_api(monkeypatch)
    fake_conn = FakeConnection()
    monkeypatch.setattr(api, "get_connection", lambda: fake_conn)
    client = api.app.test_client()

    response = client.get("/health")

    assert response.status_code == 200
    assert response.get_json()["status"] == "ok"


def test_auth_is_optional_by_default(monkeypatch):
    api = load_api(monkeypatch)
    fake_conn = FakeConnection()
    monkeypatch.setattr(api, "get_connection", lambda: fake_conn)
    client = api.app.test_client()

    response = client.get("/alertas?range=5m")

    assert response.status_code == 200


def test_mitre_and_human_summary_helpers(monkeypatch):
    api = load_api(monkeypatch)
    alert = api.enrich_alert({
        "ip": "45.67.89.12",
        "event_type": "BRUTE_FORCE",
        "service": "ssh",
        "port": 22,
        "threat_score": 95,
        "severity": "CRITICAL",
        "simulated_block": True,
    })

    assert alert["mitre_id"] == "T1110"
    assert "Brute Force" in alert["mitre_name"]
    assert "45.67.89.12" in alert["human_summary"]


def test_enrich_alert_uses_final_score_contract(monkeypatch):
    api = load_api(monkeypatch)
    alert = api.enrich_alert({
        "ip": "45.67.89.12",
        "event_type": "BRUTE_FORCE",
        "threat_score": 100,
        "score_final": 82,
        "risco": 82,
        "score_breakdown": {"final_score": 82, "score_explanation": "Score 82: evidencias correlacionadas."},
    })

    assert alert["threat_score"] == 82
    assert alert["score_final"] == 82
    assert alert["risco"] == 82
    assert alert["severity"] == "HIGH"
    assert alert["score_explanation"] == "Score 82: evidencias correlacionadas."


def test_timeline_buckets_respect_requested_range(monkeypatch):
    api = load_api(monkeypatch)
    now = datetime.now(timezone.utc)
    alerts = [
        api.enrich_alert({"ip": "10.0.0.1", "event_type": "PORT_SCAN", "score_final": 35, "ts": (now - timedelta(minutes=10)).isoformat()}),
        api.enrich_alert({"ip": "10.0.0.2", "event_type": "BRUTE_FORCE", "score_final": 82, "ts": (now - timedelta(hours=2)).isoformat()}),
    ]

    buckets = api.build_timeline_buckets(alerts, "1h")

    assert sum(item["count"] for item in buckets) == 1
    assert sum(item["high"] for item in buckets) == 0


def test_fetch_alert_rows_limits_recent_alerts_before_sorting(monkeypatch):
    api = load_api(monkeypatch)
    fake_conn = FakeConnection()

    api.fetch_alert_rows(fake_conn, limit=1000)

    statement = fake_conn.cursor_obj.statements[-1][0]
    assert "ORDER BY ts DESC" in statement
    assert "recent_alerts" in statement
    assert statement.rstrip().endswith("ORDER BY ts ASC")


def test_incident_builder_groups_alerts(monkeypatch):
    api = load_api(monkeypatch)
    alerts = [
        api.enrich_alert({"event_id": "11111111-1111-1111-1111-111111111111", "ip": "45.67.89.12", "event_type": "FAILED_LOGIN", "threat_score": 30, "severity": "MEDIUM", "ts": "2026-05-04T10:00:00+00:00"}),
        api.enrich_alert({"event_id": "22222222-2222-2222-2222-222222222222", "ip": "45.67.89.12", "event_type": "BRUTE_FORCE", "threat_score": 95, "severity": "CRITICAL", "ts": "2026-05-04T10:01:00+00:00", "simulated_block": True}),
    ]

    incidents = api.build_incidents(alerts)

    assert len(incidents) == 1
    assert incidents[0]["severity"] == "CRITICAL"
    assert incidents[0]["status"] == "INVESTIGATING"
    assert incidents[0]["mitre_techniques"][0]["id"] == "T1110"
    assert "related_alerts" in incidents[0]
    assert "recommendations" in incidents[0]


def test_incident_status_update_endpoint_accepts_safe_fields(monkeypatch):
    api = load_api(monkeypatch)
    fake_conn = FakeConnection()
    alerts = [
        api.enrich_alert({"event_id": "11111111-1111-1111-1111-111111111111", "ip": "45.67.89.12", "event_type": "BRUTE_FORCE", "threat_score": 95, "severity": "CRITICAL", "ts": "2026-05-04T10:01:00+00:00"})
    ]
    incident_id = api.build_incidents(alerts)[0]["incident_id"]
    monkeypatch.setattr(api, "ensure_connection", lambda: fake_conn)
    monkeypatch.setattr(api, "fetch_alert_rows", lambda conn, source_ip=None, limit=500: alerts)
    monkeypatch.setattr(api, "fetch_incident_overrides", lambda conn: {})
    client = api.app.test_client()

    response = client.patch(f"/incidents/{incident_id}", json={
        "status": "investigating",
        "analyst_notes": "Validar se e falso positivo.",
        "assigned_to": "analista-demo",
        "soc_action": "bloqueio simulado apenas",
        "ignored": "nope",
    })

    assert response.status_code == 200
    assert any("INSERT INTO incidents" in statement for statement, _ in fake_conn.cursor_obj.statements)
    assert any("incident_audit_log" in statement for statement, _ in fake_conn.cursor_obj.statements)


def test_investigation_includes_analyst_summary_and_recommendations(monkeypatch):
    api = load_api(monkeypatch)
    fake_conn = FakeConnection()
    alerts = [
        api.enrich_alert({"event_id": "11111111-1111-1111-1111-111111111111", "ip": "45.67.89.12", "event_type": "PORT_SCAN", "threat_score": 25, "severity": "LOW", "ts": "2026-05-04T10:00:00+00:00"}),
        api.enrich_alert({"event_id": "22222222-2222-2222-2222-222222222222", "ip": "45.67.89.12", "event_type": "BRUTE_FORCE", "threat_score": 95, "severity": "CRITICAL", "ts": "2026-05-04T10:01:00+00:00", "is_replay_event": True}),
    ]
    monkeypatch.setattr(api, "fetch_alert_rows", lambda conn, source_ip=None, limit=300: alerts)
    monkeypatch.setattr(api, "fetch_incident_overrides", lambda conn: {})

    payload = api.build_investigation(fake_conn, "45.67.89.12")

    assert "Resumo" not in payload
    assert "analyst_summary" in payload
    assert "recommended_actions" in payload
    assert payload["replay_events"]


def test_metrics_payload_uses_real_alert_rows(monkeypatch):
    api = load_api(monkeypatch)
    fake_conn = FakeConnection()
    alerts = [
        api.enrich_alert({"event_id": "11111111-1111-1111-1111-111111111111", "ip": "45.67.89.12", "event_type": "BRUTE_FORCE", "threat_score": 95, "severity": "CRITICAL", "mitre_id": "T1110", "ts": "2026-05-04T10:01:00+00:00", "is_replay_event": True}),
    ]
    monkeypatch.setattr(api, "metric_rows", lambda conn: alerts)
    monkeypatch.setattr(api, "fetch_incident_overrides", lambda conn: {})

    payload = api.build_metrics_payload(fake_conn)

    assert payload["total_alerts"] == 1
    assert payload["tecnicas_mitre"]["T1110"] == 1
    assert payload["replay_vs_normal"]["replay"] == 1


def test_report_generation_contains_60_sections(monkeypatch):
    api = load_api(monkeypatch)
    fake_conn = FakeConnection()
    alerts = [
        api.enrich_alert({"event_id": "11111111-1111-1111-1111-111111111111", "ip": "45.67.89.12", "event_type": "BRUTE_FORCE", "threat_score": 95, "severity": "CRITICAL", "ts": "2026-05-04T10:01:00+00:00", "simulated_block": True}),
    ]
    incident_id = api.build_incidents(alerts)[0]["incident_id"]
    monkeypatch.setattr(api, "ensure_connection", lambda: fake_conn)
    monkeypatch.setattr(api, "fetch_alert_rows", lambda conn, source_ip=None, limit=500: alerts)
    monkeypatch.setattr(api, "fetch_incident_overrides", lambda conn: {})
    client = api.app.test_client()

    response = client.get(f"/reports/incident/{incident_id}.md")
    body = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "SENTINELA SOC 6.0" in body
    assert "Notas do Analista" in body
    assert "Recomendações Defensivas" in body
