import json
import uuid
import time
import os
from datetime import datetime, timezone
from collections import defaultdict, deque

# Thresholds configuráveis
DISTRIBUTED_SCAN_THRESHOLD = int(os.getenv("DISTRIBUTED_SCAN_SOURCE_THRESHOLD", "3"))
DISTRIBUTED_BRUTE_FORCE_THRESHOLD = int(os.getenv("DISTRIBUTED_BRUTE_FORCE_SOURCE_THRESHOLD", "3"))
TENANT_VOLUME_MEDIUM = int(os.getenv("TENANT_SUSPICIOUS_VOLUME_MEDIUM_THRESHOLD", "20"))
TENANT_VOLUME_HIGH = int(os.getenv("TENANT_SUSPICIOUS_VOLUME_HIGH_THRESHOLD", "50"))
DEFAULT_WINDOW = int(os.getenv("CORRELATION_WINDOW_SECONDS", "300"))

# Mapeamento estático MITRE para detecções básicas e Kill Chain
MITRE_TTP_MAPPING = {
    "PORT_SCAN": {"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery"},
    "BRUTE_FORCE": {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
    "FAILED_LOGIN": {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
    "IOC_MATCH": {"id": "T1071", "name": "Application Layer Protocol", "tactic": "Command and Control"},
    "ESCALATION": {"id": "T1068", "name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation"},
    "LATERAL_MOVEMENT": {"id": "T1210", "name": "Exploitation of Remote Services", "tactic": "Lateral Movement"},
    "DATA_EXFIL": {"id": "T1048", "name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration"}
}

KILL_CHAIN_PHASES = {
    "Discovery": 1,
    "Credential Access": 2,
    "Initial Access": 2,
    "Execution": 3,
    "Privilege Escalation": 3,
    "Defense Evasion": 3,
    "Lateral Movement": 4,
    "Command and Control": 5,
    "Exfiltration": 6,
    "Impact": 6
}

class CorrelationEngine:
    """
    Engine para correlação de eventos em tempo real e Attack Graph.
    Suporta:
    1. Kill Chain Engine (Grafo de progressão tática do IP)
    2. Ataques Distribuídos (múltiplos IPs com mesmo padrão/alvo)
    3. Correlação Temporal e Nível de Tenant
    """
    def __init__(self, state_store, window_seconds=None):
        self.state_store = state_store
        self.window_seconds = window_seconds or DEFAULT_WINDOW

    def correlate(self, log, events, threat_intel=None):
        """
        Analisa o log atual contra o histórico do IP e estado global para montar a Cadeia de Ataque.
        """
        ip = log.get("ip") or log.get("source_ip")
        tenant_id = log.get("tenant_id", "default")
        event_type = str(log.get("event_type", "UNKNOWN")).upper()
        target_ip = log.get("target_ip") or log.get("destination_ip") or "unknown"
        username = log.get("username") or log.get("user") or "unknown"
        
        reasons = []
        distributed_attack = False
        source_count = 1
        involved_sources = [ip]
        correlation_key = f"ip:{ip}"
        correlation_type = "single_ip"
        
        # 1. Attack Graph / Kill Chain Engine
        # Mapeia táticas passadas do IP e calcula a fase atual
        tactics_seen = set()
        highest_phase = 0
        kill_chain_path = []
        
        for e in events:
            etype = e.get("event_type", "UNKNOWN").upper()
            if etype in MITRE_TTP_MAPPING:
                tactic = MITRE_TTP_MAPPING[etype]["tactic"]
                if tactic not in tactics_seen:
                    tactics_seen.add(tactic)
                    phase = KILL_CHAIN_PHASES.get(tactic, 0)
                    kill_chain_path.append({"tactic": tactic, "phase": phase, "timestamp": e.get("seen_at", time.time())})
                    if phase > highest_phase:
                        highest_phase = phase
        
        # Ordena caminho pela timeline
        kill_chain_path = sorted(kill_chain_path, key=lambda x: x["timestamp"])
        path_tactics = [item["tactic"] for item in kill_chain_path]

        current_tactic = MITRE_TTP_MAPPING.get(event_type, {}).get("tactic")
        current_phase = KILL_CHAIN_PHASES.get(current_tactic, 0) if current_tactic else 0

        if current_tactic and current_tactic not in tactics_seen and tactics_seen:
            reasons.append(f"tactical_progression:from_{path_tactics[-1]}_to_{current_tactic}")
        
        if current_phase > 0 and current_phase > highest_phase:
            reasons.append(f"kill_chain_escalation:phase_{current_phase}")

        # Se for um evento crítico de Kill Chain > 3 (ex: Lateral Movement, Exfiltration),
        # sinalizamos a campanha inteira no Redis
        if current_phase >= 4:
            self.state_store.add_to_set(f"sentinela:killchain:critical_ips:{tenant_id}", ip, self.window_seconds * 24)

        # 2. Correlação Distribuída (Multi-IP)

        # 2.A Distributed Port Scan
        if event_type == "PORT_SCAN" or "SCAN" in event_type:
            scan_key = f"sentinela:correlation:target:{tenant_id}:{target_ip}:sources"
            sources = self.state_store.add_to_set(scan_key, ip, self.window_seconds)
            source_count = len(sources)
            involved_sources = list(sources)
            if source_count >= DISTRIBUTED_SCAN_THRESHOLD:
                distributed_attack = True
                correlation_type = "distributed_port_scan"
                reasons.append(f"distributed_port_scan:sources_{source_count}")

        # 2.B Distributed Brute Force
        if event_type in ("BRUTE_FORCE", "FAILED_LOGIN", "SSH_FAILED"):
            brute_key = f"sentinela:correlation:user:{tenant_id}:{username}:failed_logins"
            sources = self.state_store.add_to_set(brute_key, ip, self.window_seconds)
            source_count = len(sources)
            involved_sources = list(sources)
            if source_count >= DISTRIBUTED_BRUTE_FORCE_THRESHOLD:
                distributed_attack = True
                correlation_type = "distributed_brute_force"
                reasons.append(f"distributed_brute_force:sources_{source_count}")

        # 2.C Tenant-Level Coordinated Activity
        tenant_key = f"sentinela:correlation:tenant:{tenant_id}:suspicious_events"
        tenant_count = self.state_store.increment_counter(tenant_key, self.window_seconds)
        if tenant_count >= TENANT_VOLUME_HIGH:
            reasons.append(f"tenant_high_volume:{tenant_count}")
        elif tenant_count >= TENANT_VOLUME_MEDIUM:
            reasons.append(f"tenant_medium_volume:{tenant_count}")

        # 3. Cruzamento com Threat Intel
        if threat_intel:
            reasons.append(f"threat_intel_match:{threat_intel.get('category')}")

        # 4. Volume de Eventos (Single IP)
        if len(events) >= 10:
            reasons.append("high_volume_detected")
        elif len(events) >= 5:
            reasons.append("medium_volume_detected")

        mitre = get_mitre_mapping(event_type)
        if distributed_attack:
            # Sobrescreve confiança e recomendações para ataques distribuídos
            confidence = "high"
            recommendation = "Ataque distribuído detectado. Recomenda-se bloqueio em nível de borda ou tenant."
        else:
            confidence = "medium"
            recommendation = "Investigar comportamento do IP de origem."

        return {
            "correlation_id": str(uuid.uuid4()),
            "reasons": reasons,
            "tactics_seen": list(tactics_seen),
            "correlation_key": correlation_key,
            "correlation_type": correlation_type,
            "distributed_attack": distributed_attack,
            "source_count": source_count,
            "involved_sources": involved_sources,
            "target_ip": target_ip,
            "username": username,
            "tenant_id": tenant_id,
            "confidence": confidence,
            "recommendation": recommendation,
            "mitre_attack": mitre,
            "kill_chain": {
                "highest_phase": max(highest_phase, current_phase),
                "current_phase": current_phase,
                "current_tactic": current_tactic,
                "path": kill_chain_path
            }
        }

def get_mitre_mapping(event_type):
    return MITRE_TTP_MAPPING.get(str(event_type).upper(), {"id": None, "name": "Unknown", "tactic": "Unknown"})
