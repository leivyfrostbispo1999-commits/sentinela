import importlib.util
import sys
import types
import uuid
from pathlib import Path
import pytest
from unittest.mock import patch, MagicMock

ROOT = Path(__file__).resolve().parents[1]
API_PATH = ROOT / "services" / "dashboard_api"
sys.path.insert(0, str(API_PATH))

# Mocks para dependências pesadas ou ausentes no host
if "psycopg2" not in sys.modules:
    sys.modules["psycopg2"] = types.SimpleNamespace(connect=lambda **_: MagicMock())
if "flask_sock" not in sys.modules:
    sys.modules["flask_sock"] = types.SimpleNamespace(Sock=lambda _: MagicMock())

def load_api(monkeypatch):
    monkeypatch.setenv("ENABLE_AUTH", "false")
    monkeypatch.setenv("ENABLE_OPENSEARCH", "true")
    monkeypatch.setenv("OPENSEARCH_URL", "http://localhost:9200")
    module_name = f"sentinela_dashboard_api_main_{uuid.uuid4().hex}"
    spec = importlib.util.spec_from_file_location(module_name, API_PATH / "main.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module

def test_hunting_endpoint_structure(monkeypatch):
    api = load_api(monkeypatch)
    client = api.app.test_client()
    
    with patch(f"{api.__name__}.opensearch_available") as mock_avail, \
         patch(f"{api.__name__}.opensearch_request") as mock_request:
        
        mock_avail.return_value = True
        mock_request.return_value = {
            "hits": {"total": {"value": 1}, "hits": [{"_source": {"description": "test alert"}}]},
            "aggregations": {"top_sources": {"buckets": []}}
        }
        
        resp = client.get("/hunting?q=test")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "hits" in data
        assert "aggregations" in data

def test_hunting_pivot_query(monkeypatch):
    api = load_api(monkeypatch)
    client = api.app.test_client()
    
    with patch(f"{api.__name__}.ensure_connection") as mock_conn:
        mock_cur = mock_conn.return_value.cursor.return_value.__enter__.return_value
        mock_cur.description = [("id",), ("source_ip",), ("event_type",), ("ts",), ("status",), ("risco",), ("score_final",), ("severity",), ("human_summary",), ("explanation",), ("reasons",), ("correlation_reasons",), ("ip",), ("port",), ("service",), ("mitre_id",), ("mitre_name",), ("mitre_tactic",)]
        
        # Simula um alerta retornado
        mock_cur.fetchall.return_value = [(1, "1.1.1.1", "PORT_SCAN", "2026-05-07", "NEW", 50, 50, "LOW", "desc", "expl", "[]", "[]", "1.1.1.1", 80, "http", "T1046", "Name", "Tactic")]
        
        resp = client.get("/hunting/pivot?type=ip&value=1.1.1.1")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["count"] == 1
        assert data["related_alerts"][0]["source_ip"] == "1.1.1.1"
