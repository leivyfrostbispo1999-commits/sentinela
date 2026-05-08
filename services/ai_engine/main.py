import json
import os
import time
import uuid
import numpy as np
from kafka import KafkaConsumer, KafkaProducer
from datetime import datetime, timezone
from collections import defaultdict, deque
from sklearn.ensemble import IsolationForest

# Configurações do Pipeline de IA
KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
ENRICHED_LOGS_TOPIC = "enriched_logs"
SECURITY_ALERTS_TOPIC = "security_alerts"

# Parâmetros de Feature Engineering
WINDOW_SIZE = 50  # Quantos eventos manter para baseline por entidade

class RealAIEngine:
    def __init__(self):
        self.producer = KafkaProducer(
            bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
            value_serializer=lambda v: json.dumps(v).encode("utf-8")
        )
        # Modelo Real de Detecção de Anomalias
        self.clf = IsolationForest(contamination=0.05, random_state=42)
        # Estado para Feature Engineering
        self.entity_state = defaultdict(lambda: deque(maxlen=WINDOW_SIZE))
        self.is_trained = False
        print("Real AI Engine iniciado com Isolation Forest e Feature Engineering.")

    def extract_features(self, log):
        """
        AI-Native XDR Feature Engineering:
        Converte logs cross-domain em vetores numéricos p/ Isolation Forest.
        """
        ip = log.get("source_ip") or log.get("ip")
        tenant = log.get("tenant_id", "default")
        event_type = str(log.get("event_type", "UNKNOWN")).upper()
        key = f"{tenant}:{ip}"
        
        history = self.entity_state[key]
        history.append(log)
        
        # 1. Identity Features
        failed_logins = sum(1 for e in history if "FAILED" in str(e.get("event_type")).upper())
        identity_score = failed_logins / len(history)

        # 2. Endpoint Features (Process)
        process_events = [e for e in history if "PROCESS" in str(e.get("event_type")).upper() or "SHELL" in str(e.get("event_type")).upper()]
        spawn_rate = len(process_events) / len(history)
        suspicious_cmds = sum(1 for e in process_events if any(x in str(e.get("command_line")).lower() for x in ["mimikatz", "sudo", "curl"]))
        command_score = suspicious_cmds / (len(process_events) or 1)

        # 3. Network Features
        ports = set(e.get("port") for e in history if e.get("port"))
        port_entropy = min(1.0, len(ports) / 20.0)
        hosts = set(e.get("target_host") for e in history if e.get("target_host"))
        host_entropy = min(1.0, len(hosts) / 5.0)

        # 4. Cloud Features
        cloud_events = [e for e in history if "CLOUD" in str(e.get("event_type")).upper()]
        cloud_abuse = sum(1 for e in cloud_events if "ABUSE" in str(e.get("event_type")).upper() or "Delete" in str(e.get("api_call", "")))
        cloud_score = cloud_abuse / (len(cloud_events) or 1)

        # 5. Enrichment Features
        base_threat = (log.get("threat_score") or 0) / 100.0
        
        # Vector: [Identity, ProcessRate, CommandRisk, PortEntropy, HostEntropy, CloudRisk, BaseThreat]
        return [identity_score, spawn_rate, command_score, port_entropy, host_entropy, cloud_score, base_threat]

    def train_initial_baseline(self):
        # Dados sintéticos de baseline 'normal' de 7 dimensões
        X_train = np.random.uniform(0, 0.15, (100, 7)) 
        self.clf.fit(X_train)
        self.is_trained = True

    def process_logs(self):
        if not self.is_trained:
            self.train_initial_baseline()

        consumer = KafkaConsumer(
            ENRICHED_LOGS_TOPIC,
            bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
            group_id="ai-real-engine-xdr-v1",
            auto_offset_reset="latest",
            value_deserializer=lambda m: json.loads(m.decode("utf-8"))
        )

        print(f"AI Engine Real monitorando {ENRICHED_LOGS_TOPIC}...")
        for message in consumer:
            log = message.value
            
            try:
                features = self.extract_features(log)
                # Reshape para inferência [1, n_features]
                X = np.array(features).reshape(1, -1)
                
                # Isolation Forest: 1 = normal, -1 = anomalia
                # decision_function: menor o valor, mais anômalo
                score_raw = self.clf.decision_function(X)[0]
                is_anomaly = self.clf.predict(X)[0] == -1
                
                # Normaliza para 0 a 1 (onde 1 é muito anômalo)
                anomaly_probability = 1.0 - (score_raw + 0.5) # Heurística de mapeamento
                anomaly_probability = max(0.0, min(1.0, anomaly_probability))

                if is_anomaly or anomaly_probability > 0.75:
                    self._generate_alert(log, anomaly_probability, features)
                    
            except Exception as e:
                print(f"Erro no pipeline de IA: {e}")

    def _generate_alert(self, log, probability, features):
        event_id = f"ai-ml-{uuid.uuid4().hex[:6]}"
        ip = log.get("source_ip") or log.get("ip")
        
        # Explicação via 'Copilot-like' logic
        explanation = f"ML INSIGHT: Anomalia detectada via Isolation Forest (Prob: {probability:.2f}). "
        if features[0] > 0.5: explanation += "Alta taxa de falhas de login. "
        if features[1] > 0.4: explanation += "Incomum diversidade geográfica. "
        if features[2] > 0.6: explanation += "Padrão de varredura de portas detectado no histórico. "

        alert = {
            "event_id": event_id,
            "tenant_id": log.get("tenant_id", "default"),
            "source_ip": ip,
            "event_type": "ML_ANOMALY_ISO_FOREST",
            "severity": "HIGH" if probability > 0.85 else "MEDIUM",
            "risco": int(probability * 100),
            "ai_anomaly_score": probability,
            "human_summary": explanation,
            "explanation": f"Isolation Forest Real-time Inference. Vector: {features}",
            "detection_source": "ai_engine_ml_v2",
            "ts": datetime.now(timezone.utc).isoformat(),
            "raw_event": log,
            "ml_features": {
                "failed_login_freq": features[0],
                "country_entropy": features[1],
                "port_diversity": features[2],
                "base_threat": features[3]
            }
        }
        self.producer.send(SECURITY_ALERTS_TOPIC, alert)
        self.producer.flush()
        print(f"AI ML Alerta: {event_id} (Score: {probability:.2f})")

if __name__ == "__main__":
    engine = RealAIEngine()
    engine.process_logs()
