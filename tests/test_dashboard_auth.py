import importlib.util
import base64
import hashlib
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


def api_hash_for_test(password, salt_b64, iterations):
    salt = salt_b64
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), iterations)
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


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
    token = api.create_jwt(subject="pytest", ttl_seconds=60, role="analyst", tenant_id="tenant-a", session_id="sess-1", user_id=42)

    assert api.verify_jwt(token) is True
    assert api.decode_jwt(token)["role"] == "analyst"
    assert api.decode_jwt(token)["tenant_id"] == "tenant-a"
    assert api.decode_jwt(token)["session_id"] == "sess-1"
    assert api.decode_jwt(token)["user_id"] == 42
    with api.app.test_request_context(headers={"Authorization": f"Bearer {token}"}):
        assert api.token_is_valid() is True


def test_invalid_jwt_is_rejected(monkeypatch):
    api = load_api(monkeypatch)

    assert api.verify_jwt("invalid.jwt.token") is False


def test_expired_jwt_is_rejected(monkeypatch):
    api = load_api(monkeypatch)
    token = api.create_jwt(subject="pytest", ttl_seconds=-1)

    assert api.verify_jwt(token) is False


def test_refresh_token_valid_returns_new_access_token(monkeypatch):
    monkeypatch.setenv("ENABLE_AUTH", "true")
    api = load_api(monkeypatch)
    client = api.app.test_client()
    refresh = api.create_jwt(subject="analyst", ttl_seconds=60, role="analyst", tenant_id="tenant-a", token_use="refresh")

    response = client.post("/auth/refresh", json={"refresh_token": refresh})
    payload = response.get_json()

    assert response.status_code == 200
    assert payload["access_token"]
    assert payload["refresh_token"]
    assert payload["token"] == payload["access_token"]
    assert api.decode_jwt(payload["access_token"])["token_use"] == "access"


def test_refresh_rejects_invalid_expired_and_access_token(monkeypatch):
    monkeypatch.setenv("ENABLE_AUTH", "true")
    api = load_api(monkeypatch)
    client = api.app.test_client()
    access = api.create_jwt(subject="analyst", ttl_seconds=60, role="analyst", tenant_id="tenant-a", token_use="access")
    expired_refresh = api.create_jwt(subject="analyst", ttl_seconds=-1, role="analyst", tenant_id="tenant-a", token_use="refresh")

    assert client.post("/auth/refresh", json={"refresh_token": "bad"}).status_code == 401
    assert client.post("/auth/refresh", json={"refresh_token": expired_refresh}).status_code == 401
    assert client.post("/auth/refresh", json={"refresh_token": access}).status_code == 401


def test_login_returns_role_and_tenant_claims(monkeypatch):
    monkeypatch.setenv("ENABLE_AUTH", "true")
    api = load_api(monkeypatch)
    client = api.app.test_client()

    response = client.post("/auth/token", json={"username": "analyst", "password": "analyst"})
    payload = response.get_json()

    assert response.status_code == 200
    assert payload["user"]["role"] == "analyst"
    assert payload["user"]["tenant_id"] == "default"
    assert api.decode_jwt(payload["token"])["role"] == "analyst"
    assert payload["access_token"] == payload["token"]
    assert payload["refresh_token"]


def test_auth_me_returns_role_tenant_and_permissions(monkeypatch):
    monkeypatch.setenv("ENABLE_AUTH", "true")
    api = load_api(monkeypatch)
    token = api.create_jwt(subject="analyst", role="analyst", tenant_id="tenant-a")
    client = api.app.test_client()

    response = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    payload = response.get_json()

    assert response.status_code == 200
    assert payload["user"]["role"] == "analyst"
    assert payload["user"]["tenant_id"] == "tenant-a"
    assert payload["user"]["auth_enabled"] is True
    assert "incident:update" in payload["user"]["permissions"]


def test_password_policy_requires_length_and_complexity(monkeypatch):
    api = load_api(monkeypatch)

    assert "minimum_length_10" in api.password_policy_errors("short")
    assert api.password_policy_errors("StrongerPass1") == []


def test_operator_can_validate_rules_but_analyst_cannot(monkeypatch):
    monkeypatch.setenv("ENABLE_AUTH", "true")
    api = load_api(monkeypatch)
    client = api.app.test_client()
    operator = api.create_jwt(subject="operator", role="operator", tenant_id="default")
    analyst = api.create_jwt(subject="analyst", role="analyst", tenant_id="default")

    rule = {
        "rule_id": "pytest_rule",
        "title": "Pytest Rule",
        "description": "Rule validation test.",
        "severity": "MEDIUM",
        "score": 50,
        "tactic": "Credential Access",
        "technique": "T1110",
        "conditions": {"event_type": "FAILED_LOGIN"},
    }

    allowed = client.post("/api/rules/validate", json={"rule": rule}, headers={"Authorization": f"Bearer {operator}"})
    denied = client.post("/api/rules/validate", json={"rule": rule}, headers={"Authorization": f"Bearer {analyst}"})

    assert allowed.status_code == 200
    assert denied.status_code == 403


def test_admin_create_user_enforces_password_policy(monkeypatch):
    monkeypatch.setenv("ENABLE_AUTH", "true")
    api = load_api(monkeypatch)
    token = api.create_jwt(subject="admin", role="admin", tenant_id="default")
    client = api.app.test_client()

    response = client.post(
        "/api/admin/users",
        json={"username": "new-user", "password": "weak", "role": "viewer"},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 400
    assert response.get_json()["error"] == "password_policy_failed"


def test_viewer_cannot_update_incident(monkeypatch):
    monkeypatch.setenv("ENABLE_AUTH", "true")
    api = load_api(monkeypatch)
    token = api.create_jwt(subject="viewer", role="viewer", tenant_id="default")
    client = api.app.test_client()

    response = client.patch("/incidents/INC-1", json={"status": "investigating"}, headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 403


def test_fetch_alert_rows_filters_by_tenant(monkeypatch):
    api = load_api(monkeypatch)
    fake_conn = FakeConnection()

    with api.app.test_request_context(headers={"X-Tenant-ID": "tenant-a"}):
        api.fetch_alert_rows(fake_conn, limit=10)

    statement, params = fake_conn.cursor_obj.statements[-1]
    assert "tenant_id = %s" in statement
    assert params[0] == "tenant-a"


def test_metrics_endpoint_returns_prometheus_payload(monkeypatch):
    api = load_api(monkeypatch)
    fake_conn = FakeConnection()
    monkeypatch.setattr(api, "get_connection", lambda: fake_conn)
    client = api.app.test_client()

    response = client.get("/metrics", headers={"X-SENTINELA-TOKEN": "sentinela-demo-token"})

    assert response.status_code == 200
    assert "sentinela_dashboard_http_requests_total" in response.get_data(as_text=True)


def test_ready_endpoint_checks_database(monkeypatch):
    api = load_api(monkeypatch)
    fake_conn = FakeConnection()
    monkeypatch.setattr(api, "get_connection", lambda: fake_conn)
    client = api.app.test_client()

    response = client.get("/ready")

    assert response.status_code == 200
    assert response.get_json()["dependencies"]["postgres"] == "ok"


def test_search_requires_authorization_when_auth_enabled(monkeypatch):
    monkeypatch.setenv("ENABLE_AUTH", "true")
    api = load_api(monkeypatch)
    client = api.app.test_client()

    response = client.get("/search?q=BRUTE_FORCE")

    assert response.status_code == 401


def test_rate_limiting_blocks_sensitive_endpoint_when_enabled(monkeypatch):
    monkeypatch.setenv("ENABLE_AUTH", "true")
    monkeypatch.setenv("ENABLE_RATE_LIMITING", "true")
    monkeypatch.setenv("RATE_LIMIT_AUTH_PER_MINUTE", "1")
    api = load_api(monkeypatch)
    client = api.app.test_client()

    first = client.post("/auth/token", json={"username": "analyst", "password": "wrong"})
    second = client.post("/auth/token", json={"username": "analyst", "password": "wrong"})

    assert first.status_code == 401
    assert second.status_code == 429


def test_search_falls_back_to_postgres_when_opensearch_unavailable(monkeypatch):
    api = load_api(monkeypatch)
    fake_conn = FakeConnection()
    monkeypatch.setattr(api, "get_connection", lambda: fake_conn)
    monkeypatch.setattr(api, "search_opensearch", lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("offline")))
    client = api.app.test_client()

    response = client.get("/search?q=BRUTE_FORCE", headers={"X-Tenant-ID": "tenant-b", "X-SENTINELA-TOKEN": "sentinela-demo-token"})

    assert response.status_code == 200
    assert response.get_json()["backend"] == "postgres"
    statement, params = fake_conn.cursor_obj.statements[-1]
    assert "tenant_id = %s" in statement
    assert params[0] == "tenant-b"


def test_pbkdf2_auth_with_users_json_object(monkeypatch):
    password_hash = "pbkdf2_sha256$1$dGVzdHNhbHQ$" + api_hash_for_test("secret", "dGVzdHNhbHQ", 1)
    monkeypatch.setenv("ENABLE_AUTH", "true")
    monkeypatch.setenv("SENTINELA_USERS_JSON", f'{{"soc-admin":{{"password_hash":"{password_hash}","role":"admin","tenant_id":"tenant-sec"}}}}')
    api = load_api(monkeypatch)
    client = api.app.test_client()

    response = client.post("/auth/token", json={"username": "soc-admin", "password": "secret"})

    assert response.status_code == 200
    assert response.get_json()["user"]["tenant_id"] == "tenant-sec"


def test_production_rejects_default_jwt_secret(monkeypatch):
    monkeypatch.setenv("SENTINELA_ENV", "production")
    monkeypatch.setenv("SENTINELA_JWT_SECRET", "sentinela-demo-jwt-secret")
    module_name = f"sentinela_dashboard_api_main_{uuid.uuid4().hex}"
    spec = importlib.util.spec_from_file_location(module_name, API_PATH / "main.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module

    try:
        spec.loader.exec_module(module)
        raised = False
    except RuntimeError as exc:
        raised = "SENTINELA_JWT_SECRET" in str(exc)

    assert raised is True


def test_tracing_disabled_does_not_require_otel(monkeypatch):
    monkeypatch.setenv("ENABLE_TRACING", "false")
    api = load_api(monkeypatch)

    assert api.ENABLE_TRACING is False
    assert api.TRACER is None


class AuditCursor(FakeCursor):
    description = [
        ("id",), ("timestamp",), ("tenant_id",), ("actor_user",), ("actor_role",), ("action",),
        ("resource_type",), ("resource_id",), ("correlation_id",), ("source_ip",), ("success",), ("metadata_json",)
    ]

    def fetchall(self):
        return [(1, datetime.now(timezone.utc), "tenant-a", "admin", "admin", "login_success", "auth", "admin", "cid", "127.0.0.1", True, {})]


class AuditConnection(FakeConnection):
    def __init__(self):
        super().__init__()
        self.cursor_obj = AuditCursor()


def test_audit_admin_access_and_tenant_filter(monkeypatch):
    monkeypatch.setenv("ENABLE_AUTH", "true")
    api = load_api(monkeypatch)
    token = api.create_jwt(subject="admin", role="admin", tenant_id="tenant-a")
    fake_conn = AuditConnection()
    monkeypatch.setattr(api, "get_connection", lambda: fake_conn)
    client = api.app.test_client()

    response = client.get("/audit?action=login_success", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 200
    assert response.get_json()["count"] == 1
    statement, params = fake_conn.cursor_obj.statements[-1]
    assert "tenant_id = %s" in statement
    assert params[0] == "tenant-a"


def test_audit_viewer_is_forbidden(monkeypatch):
    monkeypatch.setenv("ENABLE_AUTH", "true")
    api = load_api(monkeypatch)
    token = api.create_jwt(subject="viewer", role="viewer", tenant_id="tenant-a")
    client = api.app.test_client()

    response = client.get("/audit", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 403


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


def test_incident_lifecycle_transition_policy(monkeypatch):
    api = load_api(monkeypatch)

    assert api.incident_transition_allowed("NEW", "TRIAGED")
    assert api.incident_transition_allowed("TRIAGED", "INVESTIGATING")
    assert api.incident_transition_allowed("INVESTIGATING", "CONTAINED")
    assert api.incident_transition_allowed("CONTAINED", "RESOLVED")
    assert api.incident_transition_allowed("CLOSED", "INVESTIGATING")
    assert not api.incident_transition_allowed("CLOSED", "RESOLVED")
    assert not api.incident_transition_allowed("FALSE_POSITIVE", "CONTAINED")


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
    assert "SENTINELA 7.0" in body
    assert "Notas do Analista" in body
    assert "Recomendações Defensivas" in body
