import json
import time
import uuid
import os
import random
from kafka import KafkaProducer
from datetime import datetime, timezone

KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
RAW_LOGS_TOPIC = os.getenv("RAW_LOGS_TOPIC", "raw_logs")

def generate_load(events_per_second=10, duration_seconds=60):
    producer = KafkaProducer(
        bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
        value_serializer=lambda v: json.dumps(v).encode("utf-8")
    )
    
    total_events = events_per_second * duration_seconds
    print(f"Iniciando teste de carga: {events_per_second} EPS por {duration_seconds}s (Total: {total_events})")
    
    start_time = time.time()
    sent_count = 0
    
    ips = [f"192.168.1.{i}" for i in range(1, 100)]
    event_types = ["HTTP_REQUEST", "DNS_QUERY", "FAILED_LOGIN", "PORT_SCAN"]

    for _ in range(total_events):
        event = {
            "event_id": str(uuid.uuid4()),
            "source_ip": random.choice(ips),
            "event_type": random.choice(event_types),
            "service": "load-test",
            "ts": datetime.now(timezone.utc).isoformat(),
            "is_performance_test": True
        }
        producer.send(RAW_LOGS_TOPIC, event)
        sent_count += 1
        
        # Controle de EPS
        elapsed = time.time() - start_time
        expected = sent_count / events_per_second
        if elapsed < expected:
            time.sleep(expected - elapsed)
            
    producer.flush()
    total_time = time.time() - start_time
    print(f"Teste concluído! {sent_count} eventos enviados em {total_time:.2f}s (Média: {sent_count/total_time:.2f} EPS)")

if __name__ == "__main__":
    generate_load(events_per_second=50, duration_seconds=30)
