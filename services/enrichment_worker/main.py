import json
import os
import time
import uuid
import random
from kafka import KafkaConsumer, KafkaProducer

KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
RAW_LOGS_TOPIC = os.getenv("RAW_LOGS_TOPIC", "raw_logs")
ENRICHED_LOGS_TOPIC = os.getenv("ENRICHED_LOGS_TOPIC", "enriched_logs")

# Mocks para demonstração comercial (em produção usaria MaxMind/AbuseIPDB API)
GEOIP_DB = {
    "45.67.89.12": {"country": "Russia", "city": "Moscow", "lat": 55.75, "lon": 37.61, "asn": "AS12345 PAO Rostelecom"},
    "185.220.101.44": {"country": "Germany", "city": "Berlin", "lat": 52.52, "lon": 13.40, "asn": "AS20473 Zwiebelfreunde e.V."},
    "203.0.113.45": {"country": "Netherlands", "city": "Amsterdam", "lat": 52.36, "lon": 4.89, "asn": "AS16509 Amazon.com"},
}

REPUTATION_CACHE = {
    "45.67.89.12": {"abuse_score": 95, "tags": ["botnet", "brute-force"]},
    "185.220.101.44": {"abuse_score": 80, "tags": ["tor-exit-node"]},
    "203.0.113.45": {"abuse_score": 10, "tags": []},
}

class EnrichmentWorker:
    def __init__(self):
        self.producer = KafkaProducer(
            bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
            value_serializer=lambda v: json.dumps(v).encode("utf-8")
        )

    def enrich(self, log):
        ip = log.get("source_ip") or log.get("ip")
        
        # 1. GeoIP & ASN Enrichment
        geo = GEOIP_DB.get(ip, {
            "country": random.choice(["USA", "Brazil", "China", "India"]),
            "city": "Unknown",
            "lat": 0,
            "lon": 0,
            "asn": "AS0 Unknown"
        })
        log["enrichment_geoip"] = geo
        
        # 2. Threat Intel Reputation (AbuseIPDB Mock)
        reputation = REPUTATION_CACHE.get(ip, {
            "abuse_score": random.randint(0, 40),
            "tags": []
        })
        log["enrichment_threat"] = reputation
        
        # 3. Dynamic Threat Scoring
        base_score = reputation["abuse_score"]
        if geo["country"] in ["Russia", "China", "North Korea"]:
            base_score += 15
        
        log["threat_score"] = min(100, base_score)
        
        return log

    def run(self):
        consumer = KafkaConsumer(
            RAW_LOGS_TOPIC,
            bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
            group_id="enrichment-group-v1",
            auto_offset_reset="latest",
            value_deserializer=lambda m: json.loads(m.decode("utf-8"))
        )
        
        print(f"Enrichment Worker iniciado. Consumindo de {RAW_LOGS_TOPIC}...")
        for message in consumer:
            try:
                raw_log = message.value
                enriched_log = self.enrich(raw_log)
                self.producer.send(ENRICHED_LOGS_TOPIC, enriched_log)
                self.producer.flush()
            except Exception as e:
                print(f"Erro ao enriquecer log: {e}")

if __name__ == "__main__":
    worker = EnrichmentWorker()
    worker.run()
