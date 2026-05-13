import argparse
import json
import os
import sys
import time
import uuid
import yaml
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

def scenario_events(name, replay_id):
    if name == "brute_force":
        return [
            build_event(replay_id, {"event_type": "FAILED_LOGIN", "username": "usuario"}, sequence=1),
            build_event(replay_id, {"event_type": "FAILED_LOGIN", "username": "usuario"}, sequence=2),
            build_event(replay_id, {"event_type": "FAILED_LOGIN", "username": "operador"}, sequence=3),
            build_event(replay_id, {"event_type": "FAILED_LOGIN", "username": "admin"}, sequence=4),
            build_event(replay_id, {"event_type": "BRUTE_FORCE", "username": "admin"}, sequence=5),
        ]
    if name == "port_scan":
        return [
            build_event(replay_id, {"event_type": "PORT_SCAN", "username": "scanner", "port": 22, "service": "ssh"}, sequence=1),
            build_event(replay_id, {"event_type": "PORT_SCAN", "username": "scanner", "port": 80, "service": "http"}, sequence=2),
            build_event(replay_id, {"event_type": "PORT_SCAN", "username": "scanner", "port": 443, "service": "https"}, sequence=3),
            build_event(replay_id, {"event_type": "PORT_SCAN", "username": "scanner", "port": 5432, "service": "postgres"}, sequence=4),
        ]
    if name == "critical_chain":
        return [
            build_event(replay_id, {"event_type": "PORT_SCAN", "port": 22}, sequence=1),
            build_event(replay_id, {"event_type": "PORT_SCAN", "port": 80}, sequence=2),
            build_event(replay_id, {"event_type": "FAILED_LOGIN", "username": "usuario"}, sequence=3),
            build_event(replay_id, {"event_type": "FAILED_LOGIN", "username": "admin"}, sequence=4),
            build_event(replay_id, {"event_type": "BRUTE_FORCE", "username": "admin"}, sequence=5),
            build_event(replay_id, {"event_type": "IOC_MATCH"}, sequence=6),
            build_event(replay_id, {"event_type": "SUSPICIOUS"}, sequence=7),
        ]
    if name == "multi_ip_campaign":
        return [
            build_event(replay_id, {"event_type": "PORT_SCAN", "username": "scanner", "source_ip": "203.0.113.45", "destination_ip": "10.10.10.10"}, sequence=1),
            build_event(replay_id, {"event_type": "FAILED_LOGIN", "username": "admin", "source_ip": "203.0.113.46", "destination_ip": "10.10.10.10"}, sequence=2),
            build_event(replay_id, {"event_type": "BRUTE_FORCE", "username": "admin", "source_ip": "203.0.113.47", "destination_ip": "10.10.10.10"}, sequence=3),
        ]
    # Default fallback
    return [
        build_event(replay_id, {"event_type": "PORT_SCAN", "port": 22}, sequence=1),
        build_event(replay_id, {"event_type": "FAILED_LOGIN", "username": "admin"}, sequence=2),
        build_event(replay_id, {"event_type": "BRUTE_FORCE", "username": "admin"}, sequence=3),
    ]

def now_iso():
    return datetime.now(timezone.utc).isoformat()

def build_event(replay_id, event_data, sequence=0):
    timestamp = now_iso()
    source_ip = event_data.get("source_ip") or event_data.get("ip") or DEFAULT_ATTACKER_IP
    return {
        "event_id": str(uuid.uuid4()),
        "ip": source_ip,
        "source_ip": source_ip,
        "event_type": event_data.get("event_type", "UNKNOWN"),
        "username": event_data.get("username", "usuario"),
        "port": event_data.get("port", 22),
        "service": event_data.get("service", "ssh"),
        "destination_ip": event_data.get("destination_ip", "10.10.10.10"),
        "timestamp": timestamp,
        "ts": timestamp,
        "is_replay_event": True,
        "replay_id": replay_id,
        "sequence": sequence,
        "mitre_id": event_data.get("mitre_id"),
        "simulated_only": True,
        "campaign_id": event_data.get("campaign_id") or replay_id,
        "attack_session_id": event_data.get("attack_session_id") or replay_id,
        "tactic": event_data.get("tactic"),
        "technique_id": event_data.get("technique_id") or event_data.get("mitre_id"),
        "stage": event_data.get("stage") or sequence,
    }

def load_scenario(path):
    with open(path, 'r', encoding='utf-8') as f:
        if path.endswith('.yml') or path.endswith('.yaml'):
            return yaml.safe_load(f)
        return json.load(f)

def run_replay(producer, events, scenario_name, delay=0.6):
    replay_id = f"replay-{scenario_name}-{uuid.uuid4().hex[:8]}"
    print(f"Iniciando replay: {scenario_name} (ID: {replay_id})")
    
    for i, event_data in enumerate(events):
        event = build_event(replay_id, event_data, sequence=i+1)
        producer.send(RAW_LOGS_TOPIC, event)
        producer.flush(timeout=5)
        print(f"Sent [{i+1}/{len(events)}]: {event['event_type']} from {event['source_ip']}")
        time.sleep(delay)

def main():
    parser = argparse.ArgumentParser(description="Replay Evoluído de Ataques para SENTINELA.")
    parser.add_argument("--file", help="Caminho para arquivo YAML/JSON de cenário.")
    parser.add_argument("--delay", type=float, default=0.5, help="Delay entre eventos.")
    args = parser.parse_args()

    producer = KafkaProducer(
        bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
        value_serializer=lambda v: json.dumps(v).encode("utf-8")
    )

    if args.file:
        scenario = load_scenario(args.file)
        run_replay(producer, scenario['events'], scenario.get('name', 'file-replay'), args.delay)
    else:
        # Cenário Padrão: Multi-stage Attack Chain
        default_events = [
            {"event_type": "PORT_SCAN", "port": 22, "service": "ssh"},
            {"event_type": "PORT_SCAN", "port": 80, "service": "http"},
            {"event_type": "FAILED_LOGIN", "username": "admin"},
            {"event_type": "FAILED_LOGIN", "username": "root"},
            {"event_type": "BRUTE_FORCE", "username": "admin", "mitre_id": "T1110"},
            {"event_type": "ESCALATION", "mitre_id": "T1068"},
            {"event_type": "IOC_MATCH", "service": "security", "mitre_id": "T1071"}
        ]
        run_replay(producer, default_events, "multi-stage-chain", args.delay)

if __name__ == "__main__":
    main()
