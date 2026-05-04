import argparse
import json
import os
import sys
import time
import uuid
from datetime import datetime, timezone

try:
    from kafka import KafkaProducer
except ImportError:
    print("Dependencia ausente: instale kafka-python ou execute dentro de ambiente com requirements do projeto.")
    sys.exit(1)


KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
RAW_LOGS_TOPIC = os.getenv("RAW_LOGS_TOPIC", "raw_logs")
DEFAULT_ATTACKER_IP = os.getenv("REPLAY_ATTACKER_IP", "203.0.113.45")
SCENARIOS = {"brute_force", "port_scan", "ioc_match", "critical_chain", "false_positive", "multi_ip", "multi_ip_campaign"}


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def build_event(replay_id, event_type, username="usuario", port=22, service="ssh", sequence=0, ip=None, destination_ip="10.10.10.10"):
    source_ip = ip or DEFAULT_ATTACKER_IP
    timestamp = now_iso()
    return {
        "event_id": str(uuid.uuid4()),
        "ip": source_ip,
        "source_ip": source_ip,
        "event_type": event_type,
        "username": username,
        "port": port,
        "service": service,
        "destination_ip": destination_ip,
        "timestamp": timestamp,
        "ts": timestamp,
        "is_replay_event": True,
        "replay_id": replay_id,
        "sequence": sequence,
        "simulated_only": True,
    }


def scenario_events(name, replay_id):
    if name == "brute_force":
        return [
            build_event(replay_id, "FAILED_LOGIN", "usuario", sequence=1),
            build_event(replay_id, "FAILED_LOGIN", "usuario", sequence=2),
            build_event(replay_id, "FAILED_LOGIN", "operador", sequence=3),
            build_event(replay_id, "FAILED_LOGIN", "admin", sequence=4),
            build_event(replay_id, "BRUTE_FORCE", "admin", sequence=5),
        ]
    if name == "port_scan":
        return [
            build_event(replay_id, "PORT_SCAN", "scanner", port=22, service="ssh", sequence=1),
            build_event(replay_id, "PORT_SCAN", "scanner", port=80, service="http", sequence=2),
            build_event(replay_id, "PORT_SCAN", "scanner", port=443, service="https", sequence=3),
            build_event(replay_id, "PORT_SCAN", "scanner", port=5432, service="postgres", sequence=4),
        ]
    if name == "ioc_match":
        return [
            build_event(replay_id, "HTTP_REQUEST", "web", port=80, service="http", sequence=1),
            build_event(replay_id, "IOC_MATCH", "web", port=0, service="security", sequence=2),
            build_event(replay_id, "SUSPICIOUS", "root", port=3389, service="rdp", sequence=3),
        ]
    if name == "false_positive":
        return [
            build_event(replay_id, "HTTP_REQUEST", "healthcheck", port=443, service="https", sequence=1, ip="198.51.100.23"),
            build_event(replay_id, "HTTP_REQUEST", "healthcheck", port=443, service="https", sequence=2, ip="198.51.100.23"),
        ]
    if name == "multi_ip":
        return [
            build_event(replay_id, "PORT_SCAN", "scanner", port=22, service="ssh", sequence=1, ip="203.0.113.45"),
            build_event(replay_id, "FAILED_LOGIN", "admin", port=22, service="ssh", sequence=2, ip="203.0.113.46"),
            build_event(replay_id, "BRUTE_FORCE", "admin", port=22, service="ssh", sequence=3, ip="203.0.113.46"),
            build_event(replay_id, "IOC_MATCH", "web", port=0, service="security", sequence=4, ip="203.0.113.47"),
        ]
    if name == "multi_ip_campaign":
        return [
            build_event(replay_id, "PORT_SCAN", "scanner", port=22, service="ssh", sequence=1, ip="203.0.113.45", destination_ip="10.10.10.10"),
            build_event(replay_id, "FAILED_LOGIN", "admin", port=22, service="ssh", sequence=2, ip="203.0.113.46", destination_ip="10.10.10.10"),
            build_event(replay_id, "FAILED_LOGIN", "admin", port=22, service="ssh", sequence=3, ip="203.0.113.47", destination_ip="10.10.10.10"),
            build_event(replay_id, "BRUTE_FORCE", "admin", port=22, service="ssh", sequence=4, ip="203.0.113.48", destination_ip="10.10.10.10"),
            build_event(replay_id, "IOC_MATCH", "admin", port=0, service="security", sequence=5, ip="203.0.113.46", destination_ip="10.10.10.10"),
            build_event(replay_id, "ESCALATION", "admin", port=22, service="ssh", sequence=6, ip="203.0.113.47", destination_ip="10.10.10.10"),
        ]
    return [
        build_event(replay_id, "PORT_SCAN", "scanner", port=22, service="ssh", sequence=1),
        build_event(replay_id, "PORT_SCAN", "scanner", port=80, service="http", sequence=2),
        build_event(replay_id, "FAILED_LOGIN", "usuario", sequence=3),
        build_event(replay_id, "FAILED_LOGIN", "admin", sequence=4),
        build_event(replay_id, "BRUTE_FORCE", "admin", sequence=5),
        build_event(replay_id, "IOC_MATCH", "admin", port=0, service="security", sequence=6),
        build_event(replay_id, "SUSPICIOUS", "root", port=3389, service="rdp", sequence=7),
    ]


def create_producer():
    return KafkaProducer(
        bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
        value_serializer=lambda value: json.dumps(value, ensure_ascii=False).encode("utf-8"),
    )


def parse_args():
    parser = argparse.ArgumentParser(description="Replay seguro de eventos simulados do SENTINELA SOC 6.0.")
    parser.add_argument("--scenario", choices=sorted(SCENARIOS), default="critical_chain")
    parser.add_argument("--delay", type=float, default=0.6, help="Intervalo entre eventos em segundos.")
    return parser.parse_args()


def main():
    args = parse_args()
    replay_id = os.getenv("REPLAY_ID", f"replay-{args.scenario}-{uuid.uuid4().hex[:8]}")
    sequence = scenario_events(args.scenario, replay_id)

    print(f"SENTINELA SOC 6.0 replay seguro iniciado | scenario={args.scenario} | replay_id={replay_id}")
    print(f"Kafka={KAFKA_BOOTSTRAP_SERVERS} | topic={RAW_LOGS_TOPIC}")
    print("Nenhum ataque real, rede externa, firewall ou bloqueio real sera executado.")

    producer = create_producer()
    for event in sequence:
        producer.send(RAW_LOGS_TOPIC, event)
        producer.flush(timeout=5)
        print(json.dumps({
            "sent": True,
            "scenario": args.scenario,
            "replay_id": event["replay_id"],
            "source_ip": event["source_ip"],
            "destination_ip": event["destination_ip"],
            "event_type": event["event_type"],
            "username": event["username"],
            "port": event["port"],
            "service": event["service"],
            "sequence": event["sequence"],
        }, ensure_ascii=False))
        time.sleep(max(args.delay, 0))

    print("Replay finalizado. Aguarde alguns segundos e confira o dashboard em modo DEMO.")


if __name__ == "__main__":
    main()
