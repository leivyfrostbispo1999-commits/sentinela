import os
import json
import uuid
import time
import yaml
import ipaddress
from datetime import datetime, timezone
from pathlib import Path

# Configurações do SOAR via Ambiente
AUTO_RESPONSE_ENABLED = os.getenv("AUTO_RESPONSE_ENABLED", "true").lower() == "true"
# SENTINELA_SOAR_EXECUTE=true ativa a execução REAL das ações destrutivas
SOAR_EXECUTE = os.getenv("SENTINELA_SOAR_EXECUTE", "false").lower() == "true"
MIN_SEVERITY_FOR_AUTO = os.getenv("AUTO_RESPONSE_MIN_SEVERITY", "HIGH")
ENABLE_AUDIT = os.getenv("ENABLE_RESPONSE_AUDIT", "true").lower() == "true"
WHITELIST_PATH = os.getenv("WHITELIST_PATH", "config/soar_whitelist.yml")

SEVERITY_LEVELS = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

class ResponseEngine:
    """
    Autonomous SOC - Motor de Resposta Governada (SOAR).
    Executa playbooks complexos e workflows baseados em contexto de ameaça.
    """
    def __init__(self, state_store):
        self.state_store = state_store
        self.actions_history = []
        self.whitelist = self._load_whitelist()

    def _load_whitelist(self):
        try:
            path = Path(WHITELIST_PATH)
            if path.exists():
                with open(path, "r", encoding="utf-8") as f:
                    return yaml.safe_load(f) or {}
        except Exception as e:
            print(f"Erro ao carregar whitelist: {e}")
        return {}

    def _is_whitelisted(self, target, tenant_id=None):
        if not target or target == "UNKNOWN":
            return False

        # Verificar IP e CIDR
        try:
            ip = ipaddress.ip_address(target)
            
            # IPs protegidos
            protected_ips = self.whitelist.get("protected_ips", [])
            if str(ip) in protected_ips:
                return True
            
            # CIDRs protegidos
            protected_cidrs = self.whitelist.get("protected_cidrs", [])
            for cidr in protected_cidrs:
                if ip in ipaddress.ip_network(cidr):
                    return True
        except ValueError:
            # Não é um IP, ignorar validação de rede
            pass

        # Verificar Hosts e Containers
        protected_hosts = self.whitelist.get("protected_hosts", [])
        if target in protected_hosts:
            return True

        protected_containers = self.whitelist.get("protected_containers", [])
        if target in protected_containers:
            return True

        # Verificar Tenants
        if tenant_id:
            protected_tenants = self.whitelist.get("protected_tenants", [])
            if tenant_id in protected_tenants:
                return True

        return False

    def _check_cooldown(self, action_type, target):
        """
        Verifica se a ação para o target está em cooldown (30 min).
        """
        key = f"soar:cooldown:{action_type}:{target}"
        if hasattr(self.state_store, 'increment_counter'):
            # Se já existe, o contador será > 1
            count = self.state_store.increment_counter(key, 1800) # 1800s = 30 min
            return count > 1
        return False

    def run_playbook(self, playbook_id, alert):
        """
        Executa uma sequência de ações (playbook) baseada no tipo de detecção.
        """
        severity = alert.get("severity", "LOW").upper()
        risk = int(alert.get("risco") or alert.get("risk") or 0)
        alert_id = alert.get("event_id")
        tenant_id = alert.get("tenant_id")
        
        # Condições de execução: severidade alta E risk >= 70
        can_execute_real = SEVERITY_LEVELS.get(severity, 0) >= SEVERITY_LEVELS["HIGH"] and risk >= 70

        actions = []
        
        if playbook_id == "brute_force_response":
            source_ip = alert.get("source_ip", "UNKNOWN")
            actions.append(self._execute_action("block_ip", source_ip, "Mitigação de Brute Force", alert_id, severity, risk, can_execute_real, tenant_id))
            actions.append(self._execute_action("notify_slack", "SOC-Alerts", f"Brute Force detectado de {source_ip}", alert_id, "LOW", risk, True))
            actions.append(self._execute_action("create_incident", alert_id, "Incidente: Tentativa de Brute Force", alert_id, severity, risk, True))

        elif playbook_id == "lateral_movement_response":
            target_host = alert.get("target_host", "UNKNOWN")
            actions.append(self._execute_action("quarantine_host", target_host, "Isolamento preventivo: Movimento Lateral", alert_id, "CRITICAL", risk, can_execute_real, tenant_id))
            actions.append(self._execute_action("escalate", "L2-Analyst", "Escalação SOC: Movimento Lateral Crítico", alert_id, severity, risk, True))
            actions.append(self._execute_action("notify_discord", "Security-Ops", f"Movimento Lateral detectado em {target_host}", alert_id, "HIGH", risk, True))

        elif playbook_id == "container_compromise_response":
            container_id = alert.get("container_id", "UNKNOWN")
            actions.append(self._execute_action("isolate_container", container_id, "Isolamento de container: Possível RCE/Comprometimento", alert_id, "CRITICAL", risk, can_execute_real, tenant_id))
            actions.append(self._execute_action("audit_response", container_id, "Auditoria detalhada de resposta iniciada", alert_id, "MEDIUM", risk, True))

        elif playbook_id == "cloud_abuse_response":
            access_key = alert.get("access_key_id", "UNKNOWN")
            actions.append(self._execute_action("block_ip", alert.get("source_ip", "UNKNOWN"), "Bloqueio de IP: Abuso de API Cloud", alert_id, "CRITICAL", risk, can_execute_real, tenant_id))
            actions.append(self._execute_action("create_incident", alert_id, f"Abuso de credencial Cloud: {access_key}", alert_id, "CRITICAL", risk, True))

        return actions

    def decide_response(self, alert):
        if not AUTO_RESPONSE_ENABLED:
            return []

        event_type = str(alert.get("event_type", "UNKNOWN")).upper()
        mitre_id = alert.get("mitre_id")
        severity = alert.get("severity", "LOW").upper()
        risk = int(alert.get("risco") or alert.get("risk") or 0)
        alert_id = alert.get("event_id")

        if self._already_responded(alert_id):
            return []

        # Mapeamento de Alerta -> Playbook
        if mitre_id == "T1110" or "BRUTE_FORCE" in event_type:
            return self.run_playbook("brute_force_response", alert)

        if "LATERAL_MOVEMENT" in event_type or mitre_id in ["T1021", "T1072"]:
            return self.run_playbook("lateral_movement_response", alert)
            
        if "CONTAINER" in event_type or "K8S" in event_type:
            return self.run_playbook("container_compromise_response", alert)

        if "CLOUD_API_ABUSE" in event_type:
            return self.run_playbook("cloud_abuse_response", alert)

        # Resposta padrão para outros tipos HIGH/CRITICAL
        if SEVERITY_LEVELS.get(severity, 0) >= SEVERITY_LEVELS["HIGH"]:
            return [self._execute_action("escalate", "L1-Analyst", "Investigação manual requerida", alert_id, severity, risk, True)]

        return []

    def _already_responded(self, alert_id):
        if not alert_id: return False
        key = f"soar:responded:{alert_id}"
        if hasattr(self.state_store, 'increment_counter'):
            count = self.state_store.increment_counter(key, 3600)
            return count > 1
        return False

    def _execute_action(self, action_type, target, reason, alert_id, severity="LOW", risk=0, can_execute_real=False, tenant_id=None):
        """
        Executa a ação com lógica de Dry-Run vs Real.
        """
        destructive_actions = ["block_ip", "quarantine_host", "isolate_container", "quarantine_container"]
        is_destructive = action_type in destructive_actions
        
        # Validação de Whitelist para ações destrutivas
        if is_destructive and self._is_whitelisted(target, tenant_id):
            return self._blocked_action(action_type, target, "blocked_by_whitelist", alert_id, severity)

        # Validação de Cooldown para ações destrutivas
        if is_destructive and self._check_cooldown(action_type, target):
            return self._blocked_action(action_type, target, "blocked_by_cooldown", alert_id, severity)

        # Modo de execução
        # Se for destrutiva, só é REAL se SOAR_EXECUTE for true E can_execute_real for true (risk >= 70)
        mode = "DRY-RUN"
        if is_destructive:
            if SOAR_EXECUTE and can_execute_real:
                mode = "REAL"
            else:
                mode = "DRY-RUN"
        else:
            # Ações não destrutivas (notificações, incidentes)
            mode = "REAL" if AUTO_RESPONSE_ENABLED else "DRY-RUN"

        # Lógica de Auditoria e Simulação de Execução
        execution_details = f"Ação {action_type} disparada para {target}. Motivo: {reason}."
        status = "executed" if mode == "REAL" else "simulated"
        
        if mode == "REAL" and is_destructive:
            # Simulação de interação com API externa (Firewall, EDR, Cloud)
            execution_details += " [EXECUTADO VIA API SENTINELA-SOAR]"
        
        # Plano de Rollback para ações destrutivas
        rollback_plan = None
        if is_destructive:
            if action_type == "block_ip":
                rollback_plan = f"unblock_ip {target}"
            elif action_type == "quarantine_host":
                rollback_plan = f"restore_host {target}"
            elif action_type == "isolate_container":
                rollback_plan = f"unisolate_container {target}"
        
        action = {
            "action_id": str(uuid.uuid4()),
            "alert_id": alert_id,
            "type": action_type,
            "target": target,
            "reason": reason,
            "mode": mode,
            "status": status,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "execution_log": execution_details,
            "rollback_plan": rollback_plan,
            "metadata": {
                "engine": "sentinela_soar_v3_hardened",
                "severity": severity,
                "risk": risk
            }
        }
        
        if ENABLE_AUDIT:
            self._audit_log(action)
        return action

    def _blocked_action(self, action_type, target, reason, alert_id, severity):
        action = {
            "action_id": str(uuid.uuid4()),
            "alert_id": alert_id,
            "type": action_type,
            "target": target,
            "status": "blocked",
            "blocked_reason": reason,
            "mode": "BLOCKED",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "execution_log": f"Ação {action_type} para {target} abortada: {reason}.",
            "metadata": {
                "engine": "sentinela_soar_v3_hardened",
                "severity": severity
            }
        }
        if ENABLE_AUDIT:
            self._audit_log(action)
        return action

    def _audit_log(self, action):
        # Auditoria persistida via logs estruturados (capturados por sinks)
        self.actions_history.append(action)
        prefix = f"SOAR_ACTION_{action['mode']}"
        print(f"{prefix}: {json.dumps(action)}", flush=True)

    def get_history(self):
        return self.actions_history
