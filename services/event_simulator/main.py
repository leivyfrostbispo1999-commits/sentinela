import json
import os
import random
import time
import uuid
from datetime import datetime, timezone

import requests

try:
    from kafka import KafkaProducer
except Exception:
    KafkaProducer = None


CORE_API_URL = os.getenv("CORE_API_URL", "http://dashboard_api:5000").rstrip("/")
API_TOKEN = os.getenv("SENTINELA_API_TOKEN", "sentinela-demo-token")
TENANT_ID = os.getenv("TENANT_ID", "default")
MODE = os.getenv("SIMULATOR_MODE", "baseline").strip().lower()
MIN_INTERVAL = float(os.getenv("SIMULATOR_MIN_INTERVAL_SECONDS", "2.0"))
MAX_INTERVAL = float(os.getenv("SIMULATOR_MAX_INTERVAL_SECONDS", "3.0"))
KAFKA_ENABLED = os.getenv("KAFKA_ENABLED", "false").lower() == "true"
KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
KAFKA_TOPIC = os.getenv("KAFKA_TOPIC", "sentinela.events.simulated")

EVENTS = [
    ("FAILED_LOGIN", "MEDIUM", 45, "T1110"),
    ("PORT_SCAN", "LOW", 35, "T1046"),
    ("BRUTE_FORCE", "HIGH", 72, "T1110"),
    ("LATERAL_MOVEMENT", "HIGH", 78, "T1021"),
    ("PRIV_ESCALATION", "CRITICAL", 90, "T1068"),
]
SOURCES = ["45.67.89.12", "185.220.101.44", "91.219.236.15", "203.0.113.10"]
HOSTS = ["edge-fw-01", "vpn-gw-01", "app-node-02", "db-core-01"]
USERS = ["admin", "svc-backup", "analyst", "root"]


def kafka_producer():
    if not KAFKA_ENABLED or not KafkaProducer:
        return None
    try:
        return KafkaProducer(
            bootstrap_servers=KAFKA_BOOTSTRAP,
            value_serializer=lambda value: json.dumps(value).encode("utf-8"),
            linger_ms=250,
            retries=1,
            max_block_ms=1500,
        )
    except Exception:
        return None


def build_event(counter):
    if MODE == "attack_wave":
        event_type, severity, score, mitre = EVENTS[counter % len(EVENTS)]
        source = SOURCES[0]
        correlation_id = "wave-" + datetime.now(timezone.utc).strftime("%Y%m%d%H%M")
    else:
        event_type, severity, score, mitre = random.choice(EVENTS[:3])
        source = random.choice(SOURCES)
        correlation_id = f"{source}-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M')}"

    host = random.choice(HOSTS)
    username = random.choice(USERS)
    now = datetime.now(timezone.utc).isoformat()
    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": now,
        "source_ip": source,
        "target_ip": "10.0.0." + str(random.randint(10, 80)),
        "target_host": host,
        "hostname": host,
        "username": username,
        "target_user": username,
        "event_type": event_type,
        "severity": severity,
        "score": score,
        "score_final": score,
        "threat_score": score,
        "mitre_id": mitre,
        "mitre_technique": mitre,
        "correlation_id": correlation_id,
        "tenant_id": TENANT_ID,
        "detection_source": "event_simulator_safe_mode",
        "service": "ssh" if event_type in {"FAILED_LOGIN", "BRUTE_FORCE"} else "network",
    }


def publish_api(event):
    response = requests.post(
        f"{CORE_API_URL}/ingest/events",
        json={"events": [event]},
        headers={"X-SENTINELA-TOKEN": API_TOKEN},
        timeout=5,
    )
    response.raise_for_status()


def main():
    producer = kafka_producer()
    counter = 0
    while True:
        event = build_event(counter)
        try:
            publish_api(event)
            if producer:
                producer.send(KAFKA_TOPIC, event)
                producer.flush(timeout=1)
            print(json.dumps({"status": "sent", "event_type": event["event_type"], "correlation_id": event["correlation_id"]}), flush=True)
        except Exception as exc:
            print(json.dumps({"status": "error", "error": str(exc)}), flush=True)
        counter += 1
        time.sleep(random.uniform(MIN_INTERVAL, MAX_INTERVAL))


if __name__ == "__main__":
    main()
