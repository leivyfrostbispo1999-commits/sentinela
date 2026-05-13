import pytest
import os
from unittest.mock import patch, MagicMock
from services.rule_engine.response_engine import ResponseEngine

class MockStore:
    def __init__(self):
        self.counters = {}

    def increment_counter(self, key, expiry):
        self.counters[key] = self.counters.get(key, 0) + 1
        return self.counters[key]

def test_response_engine_brute_force_flow():
    engine = ResponseEngine(MockStore())
    alert = {
        "event_id": "evt-bf-123",
        "severity": "HIGH",
        "risco": 75,
        "event_type": "BRUTE_FORCE",
        "source_ip": "1.1.1.1"
    }
    
    actions = engine.decide_response(alert)
    
    action_types = [a["type"] for a in actions]
    assert "block_ip" in action_types
    assert "notify_slack" in action_types
    
    block_action = next(a for a in actions if a["type"] == "block_ip")
    assert block_action["mode"] == "DRY-RUN"
    assert block_action["status"] == "simulated"
    assert block_action["rollback_plan"] == "unblock_ip 1.1.1.1"

def test_response_engine_whitelist_blocking():
    engine = ResponseEngine(MockStore())
    # Mock whitelist
    engine.whitelist = {
        "protected_ips": ["127.0.0.1"],
        "protected_cidrs": ["10.0.0.0/8"]
    }
    
    # Test IP bloqueado
    alert_ip = {
        "event_id": "evt-wl-1",
        "severity": "HIGH",
        "risco": 80,
        "event_type": "BRUTE_FORCE",
        "source_ip": "127.0.0.1"
    }
    actions = engine.decide_response(alert_ip)
    block_action = next(a for a in actions if a["type"] == "block_ip")
    assert block_action["status"] == "blocked"
    assert block_action["blocked_reason"] == "blocked_by_whitelist"

    # Test CIDR bloqueado
    alert_cidr = {
        "event_id": "evt-wl-2",
        "severity": "HIGH",
        "risco": 80,
        "event_type": "BRUTE_FORCE",
        "source_ip": "10.1.2.3"
    }
    actions = engine.decide_response(alert_cidr)
    block_action = next(a for a in actions if a["type"] == "block_ip")
    assert block_action["status"] == "blocked"
    assert block_action["blocked_reason"] == "blocked_by_whitelist"

def test_response_engine_cooldown():
    store = MockStore()
    engine = ResponseEngine(store)
    
    alert = {
        "event_id": "evt-cd-1",
        "severity": "HIGH",
        "risco": 85,
        "event_type": "BRUTE_FORCE",
        "source_ip": "8.8.8.8"
    }
    
    # Primeira execução: OK
    actions1 = engine.decide_response(alert)
    block_action1 = next(a for a in actions1 if a["type"] == "block_ip")
    assert block_action1["status"] == "simulated"

    # Segunda execução (mesmo alert_id seria bloqueado pelo _already_responded, 
    # então vamos mudar o alert_id para testar especificamente o cooldown da ação/target)
    alert["event_id"] = "evt-cd-2"
    actions2 = engine.decide_response(alert)
    block_action2 = next(a for a in actions2 if a["type"] == "block_ip")
    assert block_action2["status"] == "blocked"
    assert block_action2["blocked_reason"] == "blocked_by_cooldown"

@patch.dict(os.environ, {"SENTINELA_SOAR_EXECUTE": "true"})
def test_response_engine_real_execution_requirements():
    import services.rule_engine.response_engine as re_module
    re_module.SOAR_EXECUTE = True
    
    engine = ResponseEngine(MockStore())
    
    # Risk < 70 -> Deve ser DRY-RUN mesmo com SOAR_EXECUTE=true
    alert_low_risk = {
        "event_id": "evt-risk-low",
        "severity": "HIGH",
        "risco": 50,
        "event_type": "BRUTE_FORCE",
        "source_ip": "9.9.9.9"
    }
    actions1 = engine.decide_response(alert_low_risk)
    block_action1 = next(a for a in actions1 if a["type"] == "block_ip")
    assert block_action1["mode"] == "DRY-RUN"

    # Risk >= 70 e Severity HIGH -> Deve ser REAL
    alert_high_risk = {
        "event_id": "evt-risk-high",
        "severity": "HIGH",
        "risco": 75,
        "event_type": "BRUTE_FORCE",
        "source_ip": "9.9.9.10"
    }
    actions2 = engine.decide_response(alert_high_risk)
    block_action2 = next(a for a in actions2 if a["type"] == "block_ip")
    assert block_action2["mode"] == "REAL"
    assert block_action2["status"] == "executed"
    
    re_module.SOAR_EXECUTE = False

def test_response_engine_rollback_plans():
    engine = ResponseEngine(MockStore())
    
    # Container
    alert_cont = {
        "event_id": "evt-rb-1",
        "severity": "CRITICAL",
        "risco": 90,
        "event_type": "CONTAINER_ESCAPE",
        "container_id": "docker-123"
    }
    actions = engine.decide_response(alert_cont)
    iso_action = next(a for a in actions if a["type"] == "isolate_container")
    assert iso_action["rollback_plan"] == "unisolate_container docker-123"

    # Host
    alert_host = {
        "event_id": "evt-rb-2",
        "severity": "CRITICAL",
        "risco": 95,
        "event_type": "LATERAL_MOVEMENT",
        "target_host": "prod-srv-01"
    }
    actions = engine.decide_response(alert_host)
    quarantine_action = next(a for a in actions if a["type"] == "quarantine_host")
    assert quarantine_action["rollback_plan"] == "restore_host prod-srv-01"
