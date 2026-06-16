import importlib.util
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def load_api(monkeypatch):
    if "dashboard_api_hardening_tests" in sys.modules:
        return sys.modules["dashboard_api_hardening_tests"]
    monkeypatch.setenv("SENTINELA_ENV", "development")
    monkeypatch.setenv("SENTINELA_JWT_SECRET", "unit-secret")
    monkeypatch.setenv("SENTINELA_API_TOKEN", "unit-token")
    monkeypatch.setenv("ENABLE_AUTH", "true")
    service_dir = str(ROOT / "services" / "dashboard_api")
    if service_dir not in sys.path:
        sys.path.insert(0, service_dir)
    path = ROOT / "services" / "dashboard_api" / "main.py"
    spec = importlib.util.spec_from_file_location("dashboard_api_hardening_tests", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    module.app.config.update(TESTING=True)
    return module


def test_jwt_validation_and_rbac_identity(monkeypatch):
    api = load_api(monkeypatch)
    token = api.create_jwt(subject="analyst", role="analyst", tenant_id="tenant-a")
    with api.app.test_request_context("/alertas", headers={"Authorization": f"Bearer {token}"}):
        identity = api.current_identity()
    assert identity["sub"] == "analyst"
    assert identity["role"] == "analyst"
    assert identity["tenant_id"] == "tenant-a"


def test_legacy_token_identity_for_internal_pipeline(monkeypatch):
    api = load_api(monkeypatch)
    with api.app.test_request_context("/ingest/alerts", headers={"X-SENTINELA-TOKEN": "unit-token"}):
        identity = api.current_identity()
    assert identity["sub"] == "legacy-token"
    assert identity["role"] == "admin"


def test_ingest_alerts_rejects_empty_payload_without_db(monkeypatch):
    api = load_api(monkeypatch)
    client = api.app.test_client()
    response = client.post("/ingest/alerts", json={}, headers={"X-SENTINELA-TOKEN": "unit-token"})
    assert response.status_code == 400
    assert response.get_json()["error"] == "invalid_payload"


def test_ingest_alerts_accepts_batch_with_mocked_persistence(monkeypatch):
    api = load_api(monkeypatch)

    class FakeConnection:
        def commit(self):
            pass

        def rollback(self):
            pass

        def close(self):
            pass

    monkeypatch.setattr(api, "ensure_connection", lambda: FakeConnection())
    monkeypatch.setattr(api, "persist_ingested_alert", lambda _conn, alert, _identity: alert["event_id"])
    monkeypatch.setattr(api, "write_audit", lambda **_kwargs: None)

    client = api.app.test_client()
    response = client.post(
        "/ingest/alerts",
        json={"alerts": [{"event_id": "evt-1", "source_ip": "203.0.113.10", "event_type": "BRUTE_FORCE"}]},
        headers={"X-SENTINELA-TOKEN": "unit-token"},
    )
    assert response.status_code == 202
    assert response.get_json()["event_ids"] == ["evt-1"]


def test_rate_limit_path_uses_stable_identity(monkeypatch):
    api = load_api(monkeypatch)
    with api.app.test_request_context("/ready", headers={"X-SENTINELA-TOKEN": "unit-token"}):
        assert api.current_identity()["sub"] == "legacy-token"
