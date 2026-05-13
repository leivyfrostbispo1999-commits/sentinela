import json
import os
import time
import uuid
import numpy as np
import psycopg2
from datetime import datetime, timezone
from collections import defaultdict, deque
from sklearn.ensemble import IsolationForest

# Configurações
DB_CONFIG = {
    "host": os.getenv("DB_HOST", "db"),
    "port": int(os.getenv("DB_PORT", "5432")),
    "dbname": os.getenv("DB_NAME", "postgres"),
    "user": os.getenv("DB_USER", "postgres"),
    "password": os.getenv("DB_PASSWORD", "root"),
}

WINDOW_SIZE = 100

class LiteAIEngine:
    def __init__(self):
        self.clf = IsolationForest(contamination=0.05, random_state=42)
        self.is_trained = False
        print("Lite AI Engine Adaptativo iniciado (Modo Banco de Dados).")

    def get_connection(self):
        return psycopg2.connect(**DB_CONFIG)

    def fetch_latest_alerts(self):
        try:
            conn = self.get_connection()
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM alertas ORDER BY ts DESC LIMIT 500")
                columns = [desc[0] for desc in cur.description]
                rows = cur.fetchall()
                alerts = [dict(zip(columns, row)) for row in rows]
            conn.close()
            return alerts
        except Exception as e:
            print(f"Erro ao buscar alertas: {e}")
            return []

    def extract_features(self, alert):
        # Feature Engineering simplificada para Modo Lite
        score = float(alert.get("score_final") or alert.get("risco") or 0) / 100.0
        is_brute = 1.0 if "BRUTE" in str(alert.get("event_type")).upper() else 0.0
        is_critical = 1.0 if alert.get("severity") == "CRITICAL" else 0.0
        occ_count = min(1.0, float(alert.get("occurrence_count") or 1) / 10.0)
        
        # Vetor: [Score, BruteForceFlag, CriticalFlag, OccurrenceDensity]
        return [score, is_brute, is_critical, occ_count]

    def train_baseline(self):
        # Baseline normal para 4 dimensões
        X_train = np.random.uniform(0, 0.2, (50, 4))
        self.clf.fit(X_train)
        self.is_trained = True

    def run_inference(self):
        if not self.is_trained:
            self.train_baseline()

        while True:
            alerts = self.fetch_latest_alerts()
            if not alerts:
                print("Aguardando alertas no banco...")
                time.sleep(30)
                continue

            for alert in alerts:
                # Evitar re-processar alertas de IA
                if alert.get("detection_source") == "ai_engine_lite":
                    continue

                features = self.extract_features(alert)
                X = np.array(features).reshape(1, -1)
                
                score_raw = self.clf.decision_function(X)[0]
                is_anomaly = self.clf.predict(X)[0] == -1
                
                prob = max(0.0, min(1.0, 1.0 - (score_raw + 0.5)))

                if is_anomaly and prob > 0.7:
                    self.save_anomaly(alert, prob, features)

            print(f"Ciclo de inferência concluído. {len(alerts)} alertas analisados.")
            time.sleep(60)

    def save_anomaly(self, original_alert, prob, features):
        try:
            conn = self.get_connection()
            with conn.cursor() as cur:
                event_id = f"ai-lite-{uuid.uuid4().hex[:6]}"
                summary = f"IA INSIGHT: Anomalia comportamental (Score: {prob:.2f}). Padrão detectado no IP {original_alert.get('source_ip')}."
                
                cur.execute("""
                    INSERT INTO alertas (event_id, source_ip, event_type, severity, score_final, human_summary, detection_source, ts, tenant_id)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, NOW(), %s)
                    ON CONFLICT (event_id) DO NOTHING
                """, (
                    event_id,
                    original_alert.get("source_ip"),
                    "AI_LITE_ANOMALY",
                    "HIGH" if prob > 0.8 else "MEDIUM",
                    int(prob * 100),
                    summary,
                    "ai_engine_lite",
                    original_alert.get("tenant_id", "default")
                ))
            conn.commit()
            conn.close()
            print(f"Anomalia salva: {event_id} para IP {original_alert.get('source_ip')}")
        except Exception as e:
            print(f"Erro ao salvar anomalia: {e}")

if __name__ == "__main__":
    engine = LiteAIEngine()
    engine.run_inference()
