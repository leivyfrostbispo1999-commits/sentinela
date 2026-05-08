import pytest
from services.rule_engine.response_engine import ResponseEngine

class MockStore:
    pass

def test_response_engine_decides_block_on_distributed_critical():
    engine = ResponseEngine(MockStore())
    alert = {
        "event_id": "evt-123",
        "severity": "CRITICAL",
        "distributed_attack": True,
        "event_type": "BRUTE_FORCE",
        "source_ip": "1.1.1.1",
        "tenant_id": "t1"
    }
    
    actions = engine.decide_response(alert)
    
    action_types = [a["type"] for a in actions]
    assert "block_ip_distributed" in action_types
    assert "escalate_to_incident" in action_types
    assert any(a["mode"] == "simulated" for a in actions)

def test_response_engine_low_severity_no_action():
    engine = ResponseEngine(MockStore())
    alert = {
        "severity": "LOW",
        "distributed_attack": False,
        "event_type": "NORMAL"
    }
    
    actions = engine.decide_response(alert)
    assert len(actions) == 0

def test_response_engine_mitre_specific_action():
    engine = ResponseEngine(MockStore())
    alert = {
        "severity": "HIGH",
        "mitre_id": "T1110", # Brute Force
        "source_ip": "2.2.2.2"
    }
    
    actions = engine.decide_response(alert)
    assert any(a["type"] == "block_ip" for a in actions)
