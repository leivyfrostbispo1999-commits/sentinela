import pytest
import json
import sys
from services.rule_engine.correlation_engine import CorrelationEngine, get_mitre_mapping

class MockStore:
    def __init__(self):
        self.events = []
        self.global_sets = {}
        self.global_counters = {}

    def add_event(self, ip, event):
        self.events.append(event)
        return self.events

    def record_aggregate(self, key, status, alert):
        return {"max_risk": 0, "occurrence_count": 1, "simulated_block": False, "event_id": "abc", "first_seen": "ts", "last_seen": "ts", "aggregated": False, "ports": [], "services": [], "event_types": [], "aggregation_key": "k", "threat_category": None, "threat_description": None, "threat_reputation_score": None, "threat_source": None, "status": status, "dedup_key": "d"}

    def add_to_set(self, key, value, window):
        s = self.global_sets.setdefault(key, set())
        s.add(value)
        return s

    def increment_counter(self, key, window):
        self.global_counters[key] = self.global_counters.get(key, 0) + 1
        return self.global_counters[key]

def test_mitre_mapping():
    assert get_mitre_mapping("PORT_SCAN")["id"] == "T1046"
    assert get_mitre_mapping("BRUTE_FORCE")["id"] == "T1110"
    assert get_mitre_mapping("UNKNOWN")["id"] is None

def test_correlation_tactical_progression():
    store = MockStore()
    engine = CorrelationEngine(store)
    
    # Evento 1: Recon (PORT_SCAN) - Phase 1
    log1 = {"ip": "1.2.3.4", "event_type": "PORT_SCAN"}
    events = [{"event_type": "PORT_SCAN", "seen_at": 1000}]
    
    # Evento 2: Acesso Inicial / Brute Force (BRUTE_FORCE) - Phase 2
    log2 = {"ip": "1.2.3.4", "event_type": "BRUTE_FORCE"}
    
    correlation = engine.correlate(log2, events)
    assert any("tactical_progression" in r for r in correlation["reasons"])
    assert "Discovery" in correlation["tactics_seen"]
    
    # Validações da Kill Chain
    kill_chain = correlation.get("kill_chain")
    assert kill_chain is not None
    assert kill_chain["highest_phase"] == 4 # BRUTE_FORCE e agora Credential Access (Fase 4)
    assert kill_chain["current_phase"] == 4 # BRUTE_FORCE e agora Credential Access (Fase 4)
    assert kill_chain["current_tactic"] == "Credential Access"
    assert len(kill_chain["path"]) == 1
    assert kill_chain["path"][0]["tactic"] == "Discovery"

def test_correlation_distributed_scan():
    store = MockStore()
    engine = CorrelationEngine(store)
    
    # 3 IPs diferentes escaneando o mesmo alvo
    ips = ["1.1.1.1", "2.2.2.2", "3.3.3.3"]
    target = "10.0.0.5"
    
    for ip in ips:
        log = {"ip": ip, "event_type": "PORT_SCAN", "target_ip": target, "tenant_id": "t1"}
        res = engine.correlate(log, [])
    
    assert res["distributed_attack"] is True
    assert res["correlation_type"] == "distributed_port_scan"
    assert res["source_count"] == 3
    assert "1.1.1.1" in res["involved_sources"]

def test_correlation_distributed_brute_force():
    store = MockStore()
    engine = CorrelationEngine(store)
    
    # 3 IPs atacando o mesmo usuário
    ips = ["1.1.1.1", "2.2.2.2", "3.3.3.3"]
    user = "admin"
    
    for ip in ips:
        log = {"ip": ip, "event_type": "BRUTE_FORCE", "username": user, "tenant_id": "t1"}
        res = engine.correlate(log, [])
    
    assert res["distributed_attack"] is True
    assert res["correlation_type"] == "distributed_brute_force"
    assert res["source_count"] == 3

def test_correlation_tenant_volume():
    store = MockStore()
    engine = CorrelationEngine(store)
    
    # Gerar 50 eventos suspeitos no mesmo tenant (HIGH threshold)
    for _ in range(50):
        log = {"ip": "1.1.1.1", "event_type": "PORT_SCAN", "tenant_id": "t1"}
        res = engine.correlate(log, [])
    
    assert any("tenant_high_volume" in r for r in res["reasons"])

def test_correlation_high_volume_single_ip():
    store = MockStore()
    engine = CorrelationEngine(store)
    
    events = [{"event_type": "NORMAL", "seen_at": 1000} for _ in range(10)]
    log = {"ip": "1.1.1.1", "event_type": "NORMAL"}
    
    correlation = engine.correlate(log, events)
    assert "high_session_volume" in correlation["reasons"]

def test_redis_stream_store_logic(monkeypatch):
    import types
    import json
    
    mock_redis_obj = types.SimpleNamespace()
    mock_redis_obj.data = {}
    mock_redis_obj.calls = []
    
    def mock_xadd(key, payload, maxlen=0, approximate=False):
        mock_redis_obj.data.setdefault(key, []).append(("id", payload))
        mock_redis_obj.calls.append(("xadd", key, maxlen))
        
    def mock_xrange(key, min="-", max="+"):
        return mock_redis_obj.data.get(key, [])

    def mock_expire(key, ttl):
        mock_redis_obj.calls.append(("expire", key, ttl))

    def mock_xtrim(key, minid=None, approximate=False):
        mock_redis_obj.calls.append(("xtrim", key, minid))
        
    mock_redis_obj.xadd = mock_xadd
    mock_redis_obj.xrange = mock_xrange
    mock_redis_obj.expire = mock_expire
    mock_redis_obj.xtrim = mock_xtrim
    mock_redis_obj.ping = lambda: True
    
    mock_redis_lib = types.SimpleNamespace()
    mock_redis_lib.from_url = lambda *a, **k: mock_redis_obj
    monkeypatch.setitem(sys.modules, "redis", mock_redis_lib)
    
    # Importar main dinamicamente para usar a store
    from services.rule_engine.main import RedisStreamCorrelationStore
    
    store = RedisStreamCorrelationStore("redis://localhost", 300)
    event = {"seen_at": 1000, "id": 1}
    
    # Testar add e get
    events = store.add_event("session1", event)
    assert len(events) == 1
    
    # Verificar se chamou xadd, expire e xtrim
    calls = [c[0] for c in mock_redis_obj.calls]
    assert "xadd" in calls
    assert "expire" in calls
    assert "xtrim" in calls
    
    # Verificar TTL (2x window_seconds = 600)
    expire_call = [c for c in mock_redis_obj.calls if c[0] == "expire"][0]
    assert expire_call[2] == 600
