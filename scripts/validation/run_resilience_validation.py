import sys
import os
import time
import json
from pathlib import Path

# Adicionar o diretório de serviços ao path para importar os motores
sys.path.append(str(Path(__file__).parent.parent.parent / "services" / "rule_engine"))

try:
    from response_engine import ResponseEngine
except ImportError:
    print("Erro: Não foi possível importar ResponseEngine. Verifique os caminhos.")
    sys.exit(1)

class SimpleMemoryStore:
    def __init__(self):
        self.data = {}
    def increment_counter(self, key, expiry):
        self.data[key] = self.data.get(key, 0) + 1
        return self.data[key]

def run_validation():
    print("=== SENTINELA: Iniciando Validação de Resiliência e Segurança SOAR ===")
    
    store = SimpleMemoryStore()
    engine = ResponseEngine(store)
    
    # 1. Validar Whitelist
    print("\n[1/3] Testando Whitelist Forte...")
    engine.whitelist = {
        "protected_ips": ["127.0.0.1", "10.0.0.1"],
        "protected_hosts": ["sentinela-db"]
    }
    
    alert_whitelisted = {
        "event_id": "val-1",
        "severity": "CRITICAL",
        "risco": 90,
        "event_type": "BRUTE_FORCE",
        "source_ip": "127.0.0.1"
    }
    
    actions = engine.decide_response(alert_whitelisted)
    blocked = any(a.get("status") == "blocked" and a.get("blocked_reason") == "blocked_by_whitelist" for a in actions)
    
    if blocked:
        print("  SUCESSO: Alvo protegido na whitelist foi bloqueado corretamente.")
    else:
        print("  FALHA: Whitelist não bloqueou o alvo protegido.")

    # 2. Validar Cooldown
    print("\n[2/3] Testando Cooldown State...")
    alert_target = {
        "event_id": "val-2",
        "severity": "HIGH",
        "risco": 85,
        "event_type": "LATERAL_MOVEMENT",
        "target_host": "server-01"
    }
    
    # Primeira ação
    engine.decide_response(alert_target)
    
    # Segunda ação para o mesmo alvo
    alert_target["event_id"] = "val-3"
    actions_cd = engine.decide_response(alert_target)
    
    cooldown_blocked = any(a.get("status") == "blocked" and a.get("blocked_reason") == "blocked_by_cooldown" for a in actions_cd)
    
    if cooldown_blocked:
        print("  SUCESSO: Cooldown de 30min evitou ações duplicadas para o mesmo alvo.")
    else:
        print("  FALHA: Cooldown não funcionou.")

    # 3. Validar Rollback Plans
    print("\n[3/3] Testando Rollback Plans...")
    alert_iso = {
        "event_id": "val-4",
        "severity": "CRITICAL",
        "risco": 95,
        "event_type": "CONTAINER_ESCAPE",
        "container_id": "microservice-auth"
    }
    
    actions_iso = engine.decide_response(alert_iso)
    iso_action = next((a for a in actions_iso if a["type"] == "isolate_container"), None)
    
    if iso_action and iso_action.get("rollback_plan"):
        print(f"  SUCESSO: Plano de rollback gerado: {iso_action['rollback_plan']}")
    else:
        print("  FALHA: Plano de rollback não encontrado para ação destrutiva.")

    print("\n=== Validação concluída com sucesso! ===")

if __name__ == "__main__":
    run_validation()
