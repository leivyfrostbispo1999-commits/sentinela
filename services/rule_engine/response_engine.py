import os
import json
import uuid
import time
from datetime import datetime, timezone

# Configurações do SOAR via Ambiente
AUTO_RESPONSE_ENABLED = os.getenv("AUTO_RESPONSE_ENABLED", "true").lower() == "true"
AUTO_RESPONSE_MODE = os.getenv("AUTO_RESPONSE_MODE", "simulated") # simulated ou real
MIN_SEVERITY_FOR_AUTO = os.getenv("AUTO_RESPONSE_MIN_SEVERITY", "HIGH")
ENABLE_AUDIT = os.getenv("ENABLE_RESPONSE_AUDIT", "true").lower() == "true"

SEVERITY_LEVELS = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

class ResponseEngine:
    """
    Autonomous SOC - Motor de Resposta Governada (SOAR).
    Executa playbooks baseados em contexto de ameaça e risco.
    """
    def __init__(self, state_store):
        self.state_store = state_store
        self.actions_history = []

    def run_playbook(self, playbook_id, alert):
        """
        Executa uma sequência de ações (playbook) baseada no tipo de detecção.
        """
        severity = alert.get("severity", "LOW").upper()
        alert_id = alert.get("event_id")
        is_distributed = alert.get("distributed_attack", False)
        
        actions = []
        
        if playbook_id == "brute_force_response":
            action_type = "block_ip_distributed" if is_distributed else "block_ip"
            actions.append(self._execute_action(action_type, alert.get("source_ip"), "Mitigação de Brute Force", alert_id, severity))
            actions.append(self._execute_action("notify_slack", "SOC", "Brute Force detectado", alert_id, "LOW"))
            actions.append(self._execute_action("escalate_to_incident", alert_id, "Escalação SOC: Brute Force", alert_id, severity))

        elif playbook_id == "lateral_movement_response":
            actions.append(self._execute_action("quarantine_host", alert.get("target_host"), "Isolamento preventivo: Movimento Lateral", alert_id, "CRITICAL"))
            actions.append(self._execute_action("escalate_to_incident", alert_id, "Escalação SOC: Movimento Lateral", alert_id, severity))

        elif playbook_id == "cloud_abuse_response":
            actions.append(self._execute_action("disable_api_key", alert.get("access_key_id"), "Suspensão de acesso Cloud: Abuso de API", alert_id, "CRITICAL"))

        return actions

    def decide_response(self, alert):
        if not AUTO_RESPONSE_ENABLED:
            return []

        event_type = str(alert.get("event_type", "UNKNOWN")).upper()
        mitre_id = alert.get("mitre_id")
        severity = alert.get("severity", "LOW").upper()
        alert_id = alert.get("event_id")

        if self._already_responded(alert_id):
            return []

        # Suporte a MITRE ID direto (exigido pelos testes)
        if mitre_id == "T1110": # Brute Force
            return self.run_playbook("brute_force_response", alert)

        # Mapeamento dinâmico de Alerta -> Playbook
        if "BRUTE_FORCE" in event_type or "AUTH_FAILED" in event_type:
            return self.run_playbook("brute_force_response", alert)
        
        if "LATERAL_MOVEMENT" in event_type:
            return self.run_playbook("lateral_movement_response", alert)
            
        if "CLOUD_API_ABUSE" in event_type:
            return self.run_playbook("cloud_abuse_response", alert)

        # Resposta padrão para outros tipos HIGH/CRITICAL
        if SEVERITY_LEVELS.get(severity, 0) >= SEVERITY_LEVELS["HIGH"]:
            return [self._execute_action("investigate", alert_id, "Investigação manual requerida p/ severidade alta", alert_id, severity)]

        return []

    def _already_responded(self, alert_id):
        # Implementação de idempotência via State Store (Redis ou Memória)
        if not alert_id: return False
        key = f"soar:responded:{alert_id}"
        if hasattr(self.state_store, 'increment_counter'):
            count = self.state_store.increment_counter(key, 3600) # Expira em 1h
            return count > 1
        return False

    def _execute_action(self, action_type, target, reason, alert_id, severity="LOW"):
        # Estados: proposed, pending_approval, executed, rejected
        status = "proposed"
        
        # Lógica de Governança
        if severity == "CRITICAL" and AUTO_RESPONSE_MODE != "simulated":
            status = "pending_approval"
        elif severity == "LOW" or AUTO_RESPONSE_MODE == "simulated":
            status = "executed" if AUTO_RESPONSE_MODE == "real" else "simulated"
        else:
            status = "executed"

        action = {
            "action_id": str(uuid.uuid4()),
            "alert_id": alert_id,
            "type": action_type,
            "target": target,
            "reason": reason,
            "mode": AUTO_RESPONSE_MODE,
            "status": status,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "explanation": f"Ação disparada por política SOC: {reason}",
            "metadata": {
                "engine": "autonomous_soc_v1",
                "requires_human": status == "pending_approval"
            }
        }
        
        if ENABLE_AUDIT:
            self._audit_log(action)
        return action

    def _audit_log(self, action):
        # Em um cenário real, isso iria para a tabela response_actions do Postgres
        # Por enquanto, logamos no stdout (que o log_collector captura) e mantemos em memória
        self.actions_history.append(action)
        print(f"SOAR_ACTION_AUDIT: {json.dumps(action)}", flush=True)

    def get_history(self):
        return self.actions_history
