import json
import uuid
import time
import os
import hashlib
from datetime import datetime, timezone
from collections import defaultdict, deque
try:
    from mitre_utils import get_mitre_mapping
except ImportError:
    from services.rule_engine.mitre_utils import get_mitre_mapping

# Thresholds configuráveis
DISTRIBUTED_SCAN_THRESHOLD = int(os.getenv("DISTRIBUTED_SCAN_SOURCE_THRESHOLD", "3"))
DISTRIBUTED_BRUTE_FORCE_THRESHOLD = int(os.getenv("DISTRIBUTED_BRUTE_FORCE_SOURCE_THRESHOLD", "3"))
TENANT_VOLUME_MEDIUM = int(os.getenv("TENANT_SUSPICIOUS_VOLUME_MEDIUM_THRESHOLD", "20"))
TENANT_VOLUME_HIGH = int(os.getenv("TENANT_SUSPICIOUS_VOLUME_HIGH_THRESHOLD", "50"))
DEFAULT_WINDOW = int(os.getenv("CORRELATION_WINDOW_SECONDS", "300"))

# Mapeamento para Cyber Kill Chain solicitado
KILL_CHAIN_PHASES = {
    "Reconnaissance": 1,
    "Discovery": 1,
    "Initial Access": 2,
    "Execution": 3,
    "Persistence": 3,
    "Privilege Escalation": 3,
    "Defense Evasion": 3,
    "Credential Access": 4,
    "Lateral Movement": 5,
    "Collection": 6,
    "Command and Control": 7,
    "Exfiltration": 8,
    "Impact": 9
}

PHASE_NAMES = {
    1: "reconnaissance",
    2: "initial access",
    4: "credential access",
    5: "lateral movement",
    9: "impact"
}

class CorrelationEngine:
    """
    Engine para correlação de eventos em tempo real e Campaign Correlation.
    """
    def __init__(self, state_store, window_seconds=None):
        self.state_store = state_store
        self.window_seconds = window_seconds or DEFAULT_WINDOW

    def correlate(self, log, events, threat_intel=None):
        """
        Analisa o log atual e o histórico para gerar campanhas e identificar progressão.
        """
        ip = log.get("ip") or log.get("source_ip")
        tenant_id = log.get("tenant_id", "default")
        event_type = str(log.get("event_type", "UNKNOWN")).upper()
        target_ip = log.get("target_ip") or log.get("destination_ip") or "unknown"
        username = log.get("username") or log.get("user") or "unknown"
        
        # Atributos de Campanha Explícita (Simulator)
        explicit_campaign_id = log.get("campaign_id")
        explicit_campaign_name = log.get("campaign_name")
        
        reasons = []
        distributed_attack = False
        source_count = 1
        involved_sources = [ip]
        
        # 1. Attack Graph / Kill Chain Engine
        tactics_seen = set()
        techniques_seen = set()
        highest_phase = 0
        kill_chain_path = []
        
        for e in events:
            etype = e.get("event_type", "UNKNOWN").upper()
            mapping = get_mitre_mapping(etype)
            
            # Prioriza técnica vinda do log (campanha explícita)
            tech = e.get("technique") or mapping.get("name")
            tactic = e.get("tactic") or mapping.get("tactic")
            
            if tactic and tactic not in tactics_seen:
                tactics_seen.add(tactic)
                phase = KILL_CHAIN_PHASES.get(tactic, 0)
                kill_chain_path.append({
                    "tactic": tactic, 
                    "technique": tech,
                    "phase": phase, 
                    "phase_name": PHASE_NAMES.get(phase, "other"),
                    "timestamp": e.get("seen_at", time.time())
                })
                if phase > highest_phase:
                    highest_phase = phase
            if tech:
                techniques_seen.add(tech)
        
        kill_chain_path = sorted(kill_chain_path, key=lambda x: x["timestamp"])
        path_tactics = [item["tactic"] for item in kill_chain_path]

        mapping = get_mitre_mapping(event_type)
        current_tactic = log.get("tactic") or mapping.get("tactic")
        current_phase = KILL_CHAIN_PHASES.get(current_tactic, 0) if current_tactic else 0

        if current_tactic and tactics_seen and current_tactic not in tactics_seen:
            reasons.append(f"tactical_progression:from_{path_tactics[-1]}_to_{current_tactic}")
        
        if current_phase > 0 and current_phase > highest_phase:
            reasons.append(f"kill_chain_escalation:phase_{current_phase}")

        # 2. Correlação Distribuída e Campanha
        campaign_seed = f"campaign:{tenant_id}"
        correlation_type = "single_ip"

        if event_type == "PORT_SCAN" or "SCAN" in event_type:
            scan_key = f"sentinela:correlation:target:{tenant_id}:{target_ip}:sources"
            sources = self.state_store.add_to_set(scan_key, ip, self.window_seconds)
            source_count = len(sources)
            involved_sources = list(sources)
            if source_count >= DISTRIBUTED_SCAN_THRESHOLD:
                distributed_attack = True
                correlation_type = "distributed_port_scan"
                reasons.append(f"distributed_port_scan:sources_{source_count}")
                campaign_seed += f":target:{target_ip}:scan"

        if event_type in ("BRUTE_FORCE", "FAILED_LOGIN", "SSH_FAILED"):
            brute_key = f"sentinela:correlation:user:{tenant_id}:{username}:failed_logins"
            sources = self.state_store.add_to_set(brute_key, ip, self.window_seconds)
            source_count = len(sources)
            involved_sources = list(sources)
            if source_count >= DISTRIBUTED_BRUTE_FORCE_THRESHOLD:
                distributed_attack = True
                correlation_type = "distributed_brute_force"
                reasons.append(f"distributed_brute_force:sources_{source_count}")
                campaign_seed += f":user:{username}:brute"

        # Se não for distribuído, a campanha é atrelada ao IP
        if not distributed_attack:
            campaign_seed += f":ip:{ip}"
        
        # Se houver campanha explícita, usamos o ID dela, senão geramos um
        campaign_id = explicit_campaign_id or ("CMP-" + hashlib.md5(campaign_seed.encode()).hexdigest()[:8].upper())
        
        if explicit_campaign_id:
            reasons.append(f"explicit_campaign_emulation:{explicit_campaign_name}")

        # 2.C Tenant-Level Coordinated Activity
        tenant_key = f"sentinela:correlation:tenant:{tenant_id}:suspicious_events"
        tenant_count = self.state_store.increment_counter(tenant_key, self.window_seconds)
        if tenant_count >= TENANT_VOLUME_HIGH:
            reasons.append(f"tenant_high_volume:{tenant_count}")

        # 3. Volume de Eventos (Single Session)
        if len(events) >= 10:
            reasons.append("high_session_volume")
        elif len(events) >= 5:
            reasons.append("medium_session_volume")

        # 4. Score de Risco da Campanha
        risk_score = 10 # Base
        risk_score += (highest_phase * 8)
        risk_score += (len(involved_sources) * 5)
        risk_score += (len(tactics_seen) * 7)
        risk_score = min(100, risk_score)

        if threat_intel:
            reasons.append(f"threat_intel_match:{threat_intel.get('category')}")
            risk_score = min(100, risk_score + 20)

        return {
            "correlation_id": str(uuid.uuid4()),
            "campaign_id": campaign_id,
            "campaign_name": explicit_campaign_name,
            "reasons": reasons,
            "tactics_seen": list(tactics_seen),
            "techniques_seen": list(techniques_seen),
            "correlation_type": "campaign" if tactics_seen else correlation_type,
            "distributed_attack": distributed_attack,
            "source_count": source_count,
            "involved_sources": involved_sources,
            "risk_score": risk_score,
            "kill_chain": {
                "highest_phase": max(highest_phase, current_phase),
                "current_phase": current_phase,
                "current_phase_name": PHASE_NAMES.get(current_phase, "other"),
                "current_tactic": current_tactic,
                "path": kill_chain_path
            },
            "session_summary": {
                "event_count": len(events),
                "first_seen": events[0].get("seen_at") if events else time.time(),
                "last_seen": events[-1].get("seen_at") if events else time.time(),
                "duration_seconds": (events[-1].get("seen_at", 0) - events[0].get("seen_at", 0)) if len(events) > 1 else 0
            }
        }
