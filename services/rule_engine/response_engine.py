import os
import json
import uuid
import time

# Configurações do SOAR via Ambiente
AUTO_RESPONSE_ENABLED = os.getenv("AUTO_RESPONSE_ENABLED", "true").lower() == "true"
AUTO_RESPONSE_MODE = os.getenv("AUTO_RESPONSE_MODE", "simulated") # simulated ou real
MIN_SEVERITY_FOR_AUTO = os.getenv("AUTO_RESPONSE_MIN_SEVERITY", "HIGH")

SEVERITY_LEVELS = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

class ResponseEngine:
    """
    Motor de Resposta Automática (SOAR Básico).
    Decide e registra ações defensivas baseadas nos metadados do alerta.
    """
    def __init__(self, state_store):
        self.state_store = state_store

    def decide_response(self, alert):
        """
        Analisa o alerta e retorna uma lista de ações recomendadas/executadas.
        """
        if not AUTO_RESPONSE_ENABLED:
            return []

        severity = alert.get("severity", "LOW").upper()
        risk_score = int(alert.get("score_final") or 0)
        mitre_id = alert.get("mitre_id")
        is_distributed = alert.get("distributed_attack", False)
        event_type = alert.get("event_type", "UNKNOWN")
        source_ip = alert.get("source_ip") or alert.get("ip")
        tenant_id = alert.get("tenant_id", "default")

        actions = []

        # Regra 1: Ataques Distribuídos Críticos
        if is_distributed and SEVERITY_LEVELS.get(severity, 0) >= SEVERITY_LEVELS["HIGH"]:
            actions.append(self._create_action(
                action_type="block_ip_distributed",
                target=source_ip,
                reason=f"Participação em ataque distribuído ({event_type}) com severidade {severity}",
                alert_id=alert.get("event_id")
            ))
            actions.append(self._create_action(
                action_type="escalate_to_incident",
                target=f"Tenant:{tenant_id}",
                reason="Campanha coordenada detectada; requer intervenção imediata",
                alert_id=alert.get("event_id")
            ))

        # Regra 2: Brute Force ou Exploração (Kill Chain avançada)
        elif mitre_id in ["T1110", "T1068", "T1210"] and SEVERITY_LEVELS.get(severity, 0) >= SEVERITY_LEVELS["HIGH"]:
            actions.append(self._create_action(
                action_type="block_ip",
                target=source_ip,
                reason=f"Tentativa de {mitre_id} detectada com alto risco ({risk_score})",
                alert_id=alert.get("event_id")
            ))
            
        # Regra 3: Alertas Críticos Genéricos
        elif severity == "CRITICAL":
            actions.append(self._create_action(
                action_type="mark_for_urgent_review",
                target=source_ip,
                reason="Alerta de severidade CRITICAL sem regra de resposta específica",
                alert_id=alert.get("event_id")
            ))

        # Regra 4: Notificação Webhook (Sempre para High/Critical se configurado)
        if SEVERITY_LEVELS.get(severity, 0) >= SEVERITY_LEVELS["HIGH"]:
            actions.append(self._create_action(
                action_type="notify_external_soc",
                target="Webhook",
                reason="Notificação automática para integradores",
                alert_id=alert.get("event_id")
            ))

        return actions

    def _create_action(self, action_type, target, reason, alert_id):
        return {
            "action_id": str(uuid.uuid4()),
            "alert_id": alert_id,
            "type": action_type,
            "target": target,
            "reason": reason,
            "mode": AUTO_RESPONSE_MODE,
            "status": "simulated" if AUTO_RESPONSE_MODE == "simulated" else "executed",
            "timestamp": time.time()
        }
