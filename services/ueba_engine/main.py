import json
import os
import time
import uuid
from datetime import datetime, timezone
from collections import defaultdict, deque
from kafka import KafkaConsumer, KafkaProducer

KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
RAW_LOGS_TOPIC = os.getenv("RAW_LOGS_TOPIC", "raw_logs")
ALERTS_TOPIC = os.getenv("ALERTS_TOPIC", "security_alerts")

# Configurações Heurísticas
VOLUME_THRESHOLD = int(os.getenv("UEBA_VOLUME_THRESHOLD", "50")) # Eventos por janela
WINDOW_SECONDS = int(os.getenv("UEBA_WINDOW_SECONDS", "300"))
UNUSUAL_HOUR_START = int(os.getenv("UEBA_UNUSUAL_HOUR_START", "22"))
UNUSUAL_HOUR_END = int(os.getenv("UEBA_UNUSUAL_HOUR_END", "6"))

class UEBAEngine:
    def __init__(self):
        # Memória de curto prazo para baselines simples
        # {tenant: {ip: deque([timestamps])}}
        self.ip_history = defaultdict(lambda: defaultdict(lambda: deque(maxlen=200)))
        # {tenant: {user: deque([timestamps])}}
        self.user_history = defaultdict(lambda: defaultdict(lambda: deque(maxlen=200)))

    def analyze(self, log):
        alerts = []
        tenant_id = log.get("tenant_id", "default")
        source_ip = log.get("source_ip") or log.get("ip")
        user = log.get("username") or log.get("user")
        now = time.time()
        
        # 1. Detecção por Volume (IP)
        if source_ip:
            history = self.ip_history[tenant_id][source_ip]
            history.append(now)
            # Limpa expirados
            while history and now - history[0] > WINDOW_SECONDS:
                history.popleft()
            
            if len(history) > VOLUME_THRESHOLD:
                alerts.append(self._build_ueba_alert(
                    log, "ANOMALOUS_VOLUME_IP", 
                    f"Volume anômalo de eventos detectado para o IP {source_ip}",
                    score=60 + min(40, len(history) - VOLUME_THRESHOLD)
                ))

        # 2. Detecção por Horário Incomum
        current_hour = datetime.now(timezone.utc).hour
        if current_hour >= UNUSUAL_HOUR_START or current_hour <= UNUSUAL_HOUR_END:
            if log.get("event_type") in ("FAILED_LOGIN", "AUTH_FAILED"):
                alerts.append(self._build_ueba_alert(
                    log, "UNUSUAL_HOUR_ACTIVITY",
                    f"Atividade de autenticação em horário incomum ({current_hour}h UTC)",
                    score=45
                ))

        # 3. Detecção de Múltiplas Falhas (Baseline do Usuário)
        if user and log.get("event_type") in ("FAILED_LOGIN", "AUTH_FAILED"):
            history = self.user_history[tenant_id][user]
            history.append(now)
            while history and now - history[0] > WINDOW_SECONDS:
                history.popleft()
            
            if len(history) >= 5:
                alerts.append(self._build_ueba_alert(
                    log, "USER_BEHAVIOR_ANOMALY",
                    f"Sequência incomum de falhas para o usuário {user}",
                    score=55
                ))

        return alerts

    def _build_ueba_alert(self, log, ueba_type, message, score):
        return {
            "event_id": str(uuid.uuid4()),
            "tenant_id": log.get("tenant_id", "default"),
            "ts": datetime.now(timezone.utc).isoformat(),
            "source_ip": log.get("source_ip") or log.get("ip"),
            "ip": log.get("source_ip") or log.get("ip"),
            "status": "UEBA_ANOMALY",
            "event_type": ueba_type,
            "risco": score,
            "score_final": score,
            "severity": "MEDIUM" if score < 75 else "HIGH",
            "mitre_id": "T1087", # Account Discovery como fallback
            "mitre_name": "Account Discovery",
            "mitre_tactic": "Discovery",
            "human_summary": f"UEBA: {message}",
            "explanation": f"Detecção heurística baseada em comportamento: {message}",
            "detection_source": "ueba_engine",
            "correlation_key": f"ueba:{log.get('source_ip') or log.get('ip')}",
            "raw_event": log
        }

def run():
    consumer = KafkaConsumer(
        RAW_LOGS_TOPIC,
        bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
        group_id="ueba-engine-v1",
        auto_offset_reset="latest",
        value_deserializer=lambda m: json.loads(m.decode("utf-8"))
    )
    
    producer = KafkaProducer(
        bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
        value_serializer=lambda v: json.dumps(v).encode("utf-8")
    )

    engine = UEBAEngine()
    print("UEBA Engine iniciado")

    for message in consumer:
        log = message.value
        ueba_alerts = engine.analyze(log)
        for alert in ueba_alerts:
            producer.send(ALERTS_TOPIC, alert)
        producer.flush()

if __name__ == "__main__":
    run()
