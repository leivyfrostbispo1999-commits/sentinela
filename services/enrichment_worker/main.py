import json
import os
import time
import uuid
import random
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from kafka import KafkaConsumer, KafkaProducer
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST, REGISTRY
from opentelemetry import trace
from tracing_helper import setup_tracing, extract_context, inject_context

KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
RAW_LOGS_TOPIC = os.getenv("RAW_LOGS_TOPIC", "raw_logs")
ENRICHED_LOGS_TOPIC = os.getenv("ENRICHED_LOGS_TOPIC", "enriched_logs")
METRICS_PORT = int(os.getenv("METRICS_PORT", "8000"))

# Métricas
ENRICHED_TOTAL = Counter("enrichment_events_total", "Total de eventos enriquecidos")
ENRICHMENT_LATENCY = Histogram("enrichment_latency_seconds", "Latência do processo de enriquecimento")
ERRORS_TOTAL = Counter("enrichment_errors_total", "Total de erros no enriquecimento")

# Tracing
TRACER = setup_tracing()

# Mocks para demonstração comercial
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

class OpsHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"OK")
        elif self.path == "/metrics":
            data = generate_latest(REGISTRY)
            self.send_response(200)
            self.send_header("Content-Type", CONTENT_TYPE_LATEST)
            self.end_headers()
            self.wfile.write(data)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, *args):
        return

class EnrichmentWorker:
    def __init__(self):
        self.producer = KafkaProducer(
            bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
            value_serializer=lambda v: json.dumps(v).encode("utf-8")
        )

    def enrich(self, log):
        with ENRICHMENT_LATENCY.time():
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
            ENRICHED_TOTAL.inc()
            return log

    def start_ops_server(self):
        server = ThreadingHTTPServer(("0.0.0.0", METRICS_PORT), OpsHandler)
        print(f"Ops Server (Health/Metrics) iniciado na porta {METRICS_PORT}")
        server.serve_forever()

    def run(self):
        # Inicia servidor de métricas e healthcheck em thread separada
        threading.Thread(target=self.start_ops_server, daemon=True).start()
        
        consumer = KafkaConsumer(
            RAW_LOGS_TOPIC,
            bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
            group_id="enrichment-group-temporal-v2",
            auto_offset_reset="latest",
            value_deserializer=lambda m: json.loads(m.decode("utf-8"))
        )
        
        print(f"Enrichment Worker iniciado. Consumindo de {RAW_LOGS_TOPIC}...")
        for message in consumer:
            try:
                # Extrai contexto do trace anterior
                ctx = extract_context(message.headers)
                
                with TRACER.start_as_current_span("enrich_event", context=ctx) as span:
                    raw_log = message.value
                    span.set_attribute("event_id", raw_log.get("event_id"))
                    span.set_attribute("ip", raw_log.get("ip"))
                    
                    print(f"Processando evento: {raw_log.get('event_id')} do IP {raw_log.get('ip')}")
                    enriched_log = self.enrich(raw_log)
                    
                    # Injeta contexto para o próximo salto
                    headers = {}
                    inject_context(headers)
                    kafka_headers = [(k, v.encode("utf-8")) for k, v in headers.items()]
                    
                    self.producer.send(ENRICHED_LOGS_TOPIC, enriched_log, headers=kafka_headers)
                    self.producer.flush()
            except Exception as e:
                ERRORS_TOTAL.inc()
                print(f"Erro ao enriquecer log: {e}")

if __name__ == "__main__":
    worker = EnrichmentWorker()
    worker.run()
