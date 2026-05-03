import importlib.util
import sys
import types
import uuid
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
    assert "simulated_block without real blocking" in payload["incident_summary"]
    assert len(payload["timeline"]) == 7
    assert [item["severity"] for item in payload["timeline"][:2]] == ["LOW", "LOW"]
    assert [item["severity"] for item in payload["timeline"][2:4]] == ["MEDIUM", "MEDIUM"]
    assert [item["severity"] for item in payload["timeline"][4:]] == ["CRITICAL", "CRITICAL", "CRITICAL"]
    assert [alert["risco"] for alert in payload["alerts"]] == [25, 40, 60, 70, 85, 92, 98]
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
