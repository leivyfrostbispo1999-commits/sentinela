import json
import os
import random
import sys
import time
import uuid
from datetime import datetime, timezone

from kafka import KafkaProducer


KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
RAW_LOGS_TOPIC = os.getenv("RAW_LOGS_TOPIC", "raw_logs")
EVENT_INTERVAL_SECONDS = float(os.getenv("EVENT_INTERVAL_SECONDS", "1.2"))
MAX_BACKOFF_SECONDS = float(os.getenv("MAX_BACKOFF_SECONDS", "15"))

IPS = [
    "192.168.1.45",
    "10.0.0.87",
    "172.16.0.23",
    "45.67.89.12",
    "172.16.5.67",
    "192.168.1.120",
    "10.0.0.34",
    "172.16.5.101",
    "203.0.113.10",
    "198.51.100.22",
]


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def log_json(level, message, **fields):
    payload = {
        "ts": now_iso(),
        "level": level,
        "component": "log_collector",
        "message": message,
        **fields,
    }
    print(json.dumps(payload, ensure_ascii=False), flush=True)


def backoff_delay(attempt):
    return min(MAX_BACKOFF_SECONDS, 1.5 * (2 ** min(attempt, 4)))


def create_producer():
    attempt = 0
    while True:
        try:
            producer = KafkaProducer(
                bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
                value_serializer=lambda value: json.dumps(value, ensure_ascii=False).encode("utf-8"),
            )
            log_json("INFO", "Kafka conectado", topic=RAW_LOGS_TOPIC)
            return producer
        except Exception as exc:
            delay = backoff_delay(attempt)
            log_json("WARN", "Aguardando Kafka", error=str(exc), retry_in_seconds=delay)
            time.sleep(delay)
            attempt += 1


def build_event():
    ip = random.choice(IPS)
    event_choice = random.random()
    base_event = {
        "event_id": str(uuid.uuid4()),
        "ts": now_iso(),
        "timestamp": time.time(),
        "ip": ip,
    }

    if event_choice < 0.35:
        return {
            **base_event,
            "event": "ssh_failed",
            "event_type": "ssh_failed",
            "service": "SSH",
            "port": 22,
            "attempts": random.randint(5, 25),
        }

    if event_choice < 0.65:
        return {
            **base_event,
            "event": "port_scan",
            "event_type": "port_scan",
            "service": "TCP",
            "port": random.choice([22, 80, 443, 3389, 5432, 8080]),
            "ports_scanned": random.randint(12, 80),
        }

    if event_choice < 0.82:
        return {
            **base_event,
            "event": "suspicious_login",
            "event_type": "suspicious_login",
            "service": "AUTH",
            "port": random.choice([22, 443, 8080]),
            "failed_attempts": random.randint(2, 4),
            "geo_change": random.choice([True, False]),
        }

    service, port = random.choice([("HTTP", 80), ("HTTPS", 443), ("DNS", 53)])
    return {
        **base_event,
        "event": "http_request",
        "event_type": "http_request",
        "service": service,
        "port": port,
        "bytes": random.randint(256, 4096),
    }


def run():
    producer = create_producer()
    log_json("INFO", "Gerador de logs iniciado")

    while True:
        event = build_event()

        try:
            producer.send(RAW_LOGS_TOPIC, event)
            producer.flush(timeout=2)
            log_json(
                "INFO",
                "Evento publicado",
                topic=RAW_LOGS_TOPIC,
                event_id=event["event_id"],
                ip=event["ip"],
                event_type=event["event_type"],
                service=event["service"],
                port=event["port"],
            )
            time.sleep(EVENT_INTERVAL_SECONDS)
        except Exception as exc:
            log_json("ERROR", "Falha ao publicar evento", error=str(exc))
            producer = create_producer()


if __name__ == "__main__":
    try:
        run()
    except KeyboardInterrupt:
        log_json("INFO", "Log collector encerrado")
        sys.exit(0)
