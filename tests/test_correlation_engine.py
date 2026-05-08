import pytest
import json
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
    assert kill_chain["highest_phase"] == 2
    assert kill_chain["current_phase"] == 2
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
    
    # Gerar 20 eventos suspeitos no mesmo tenant
    for _ in range(20):
        log = {"ip": "1.1.1.1", "event_type": "PORT_SCAN", "tenant_id": "t1"}
        res = engine.correlate(log, [])
    
    assert any("tenant_medium_volume" in r for r in res["reasons"])

def test_correlation_high_volume_single_ip():
    store = MockStore()
    engine = CorrelationEngine(store)
    
    events = [{"event_type": "NORMAL", "seen_at": 1000} for _ in range(10)]
    log = {"ip": "1.1.1.1", "event_type": "NORMAL"}
    
    correlation = engine.correlate(log, events)
    assert "high_volume_detected" in correlation["reasons"]
