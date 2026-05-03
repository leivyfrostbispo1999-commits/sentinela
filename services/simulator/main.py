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
MAX_BACKOFF_SECONDS = float(os.getenv("MAX_BACKOFF_SECONDS", "15"))

THREAT_INTEL_IPS = [
    "45.67.89.12",
    "185.220.101.44",
    "91.219.236.15",
    "103.27.202.66",
    "172.16.5.67",
]

PERSISTENT_ATTACKERS = [
    "203.0.113.45",
    "198.51.100.88",
    "203.0.113.10",
]

NORMAL_IPS = [
    "192.168.1.10",
    "10.0.0.5",
    "172.16.0.2",
    "192.168.0.8",
    "10.20.30.40",
]

SENSITIVE_PORTS = [22, 23, 3389, 445, 5432, 3306, 6379, 9200]
NORMAL_PORTS = [53, 80, 123, 443, 8080]

SERVICES = {
    22: "ssh",
    23: "telnet",
    53: "dns",
    80: "http",
    123: "ntp",
    443: "https",
    445: "smb",
    3306: "mysql",
    3389: "rdp",
    5432: "postgres",
    6379: "redis",
    8080: "http-alt",
    9200: "elasticsearch",
}


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def log_json(level, message, **fields):
    payload = {
        "ts": now_iso(),
        "level": level,
        "component": "simulator",
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


def build_event(ip, event_type, port):
    return {
        "event_id": str(uuid.uuid4()),
        "ip": ip,
        "event_type": event_type,
        "port": port,
        "service": SERVICES.get(port, "unknown"),
        "timestamp": now_iso(),
        "ts": now_iso(),
    }


def send_event(producer, ip, event_type, port):
    event = build_event(ip, event_type, port)
    producer.send(RAW_LOGS_TOPIC, event)
    producer.flush(timeout=2)
    log_json(
        "INFO",
        "Evento enviado",
        ip=ip,
        event_type=event_type,
        port=port,
        service=event["service"],
    )


def short_pause():
    time.sleep(random.uniform(0.35, 1.4))


def simulate_multistage_attack(producer, ip):
    log_json("WARN", "Sequência multiestágio iniciada", ip=ip)

    for _ in range(random.randint(3, 6)):
        send_event(producer, ip, "PORT_SCAN", random.choice(SENSITIVE_PORTS))
        short_pause()

    for _ in range(random.randint(3, 7)):
        send_event(producer, ip, "BRUTE_FORCE", random.choice([22, 23, 3389]))
        short_pause()

    for _ in range(random.randint(1, 3)):
        send_event(producer, ip, "SUSPICIOUS", random.choice(SENSITIVE_PORTS))
        short_pause()


def simulate_burst(producer, ip):
    log_json("WARN", "Burst de ataque iniciado", ip=ip)
    for _ in range(random.randint(8, 13)):
        event_type = random.choice(["PORT_SCAN", "BRUTE_FORCE", "SUSPICIOUS"])
        port = random.choice(SENSITIVE_PORTS)
        send_event(producer, ip, event_type, port)
        time.sleep(random.uniform(0.12, 0.45))


def simulate_normal_traffic(producer):
    ip = random.choice(NORMAL_IPS)
    event_type = random.choice(["NORMAL", "HTTP_REQUEST", "DNS_QUERY"])
    port = random.choice(NORMAL_PORTS)
    send_event(producer, ip, event_type, port)


def run():
    producer = create_producer()
    log_json("INFO", "SENTINELA simulator started")

    while True:
        try:
            scenario = random.random()

            if scenario < 0.25:
                simulate_normal_traffic(producer)
            elif scenario < 0.55:
                simulate_multistage_attack(producer, random.choice(PERSISTENT_ATTACKERS))
            elif scenario < 0.82:
                simulate_multistage_attack(producer, random.choice(THREAT_INTEL_IPS))
            else:
                simulate_burst(producer, random.choice(THREAT_INTEL_IPS + PERSISTENT_ATTACKERS))

            time.sleep(random.uniform(1.0, 3.2))
        except Exception as exc:
            log_json("ERROR", "Falha no simulador; reconectando", error=str(exc))
            producer = create_producer()


if __name__ == "__main__":
    try:
        run()
    except KeyboardInterrupt:
        log_json("INFO", "Simulador encerrado")
        sys.exit(0)
