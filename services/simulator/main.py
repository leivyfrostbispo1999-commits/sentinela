import json
import os
import random
import sys
import time
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

from kafka import KafkaProducer
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, generate_latest


KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
RAW_LOGS_TOPIC = os.getenv("RAW_LOGS_TOPIC", "raw_logs")
DEFAULT_TENANT_ID = os.getenv("DEFAULT_TENANT_ID", "default")
MAX_BACKOFF_SECONDS = float(os.getenv("MAX_BACKOFF_SECONDS", "15"))
METRICS_PORT = int(os.getenv("METRICS_PORT", "8000"))
SERVICE_READY = False

SIMULATED_EVENTS = Counter("sentinela_simulator_events_total", "Eventos simulados publicados", ["scenario", "event_type"])
SIMULATOR_FAILURES = Counter("sentinela_service_failures_total", "Falhas por serviço", ["service"])
SERVICE_READY_GAUGE = Gauge("sentinela_service_ready", "Readiness do serviço", ["service"])

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
    global SERVICE_READY
    attempt = 0
    while True:
        try:
            producer = KafkaProducer(
                bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
                value_serializer=lambda value: json.dumps(value, ensure_ascii=False).encode("utf-8"),
            )
            log_json("INFO", "Kafka conectado", topic=RAW_LOGS_TOPIC)
            SERVICE_READY = True
            SERVICE_READY_GAUGE.labels(service="simulator").set(1)
            return producer
        except Exception as exc:
            SERVICE_READY = False
            SERVICE_READY_GAUGE.labels(service="simulator").set(0)
            SIMULATOR_FAILURES.labels(service="simulator").inc()
            delay = backoff_delay(attempt)
            log_json("WARN", "Aguardando Kafka", error=str(exc), retry_in_seconds=delay)
            time.sleep(delay)
            attempt += 1


def build_event(ip, event_type, port, scenario="generic", **extra):
    return {
        "event_id": str(uuid.uuid4()),
        "tenant_id": extra.get("tenant_id", DEFAULT_TENANT_ID),
        "correlation_id": extra.get("correlation_id", str(uuid.uuid4())),
        "ip": ip,
        "source_ip": ip,
        "event_type": event_type,
        "event": event_type.lower(),
        "port": port,
        "service": SERVICES.get(port, "unknown"),
        "timestamp": now_iso(),
        "ts": now_iso(),
        "scenario": scenario,
        "target_host": extra.get("target_host", "sentinela-prod-sim"),
        "target_ip": extra.get("target_ip", random.choice(["10.10.1.20", "10.10.2.15", "10.10.3.8"])),
        "username": extra.get("username"),
        "bytes": extra.get("bytes"),
        "destination_ip": extra.get("destination_ip"),
        "geo_change": extra.get("geo_change"),
    }


def send_event(producer, ip, event_type, port, scenario="generic", **extra):
    event = build_event(ip, event_type, port, scenario=scenario, **extra)
    producer.send(RAW_LOGS_TOPIC, event)
    producer.flush(timeout=2)
    SIMULATED_EVENTS.labels(scenario=scenario, event_type=event_type).inc()
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
        send_event(producer, ip, "PORT_SCAN", random.choice(SENSITIVE_PORTS), scenario="multi_stage")
        short_pause()

    for _ in range(random.randint(3, 7)):
        send_event(producer, ip, "BRUTE_FORCE", random.choice([22, 23, 3389]), scenario="multi_stage", username=random.choice(["admin", "root", "svc-backup"]))
        short_pause()

    for _ in range(random.randint(1, 3)):
        send_event(producer, ip, "SUSPICIOUS", random.choice(SENSITIVE_PORTS), scenario="multi_stage")
        short_pause()


def simulate_burst(producer, ip):
    log_json("WARN", "Burst de ataque iniciado", ip=ip)
    for _ in range(random.randint(8, 13)):
        event_type = random.choice(["PORT_SCAN", "BRUTE_FORCE", "SUSPICIOUS"])
        port = random.choice(SENSITIVE_PORTS)
        send_event(producer, ip, event_type, port, scenario="burst")
        time.sleep(random.uniform(0.12, 0.45))


def simulate_brute_force(producer, ip):
    for _ in range(random.randint(8, 16)):
        send_event(producer, ip, "BRUTE_FORCE", random.choice([22, 3389]), scenario="brute_force", username=random.choice(["admin", "root", "administrator"]))
        time.sleep(random.uniform(0.08, 0.22))


def simulate_port_scan(producer, ip):
    for port in random.sample(SENSITIVE_PORTS + NORMAL_PORTS, k=random.randint(6, 10)):
        send_event(producer, ip, "PORT_SCAN", port, scenario="port_scan")
        time.sleep(random.uniform(0.05, 0.18))


def simulate_beaconing(producer, ip):
    destination = random.choice(["198.51.100.200", "203.0.113.77", "185.220.101.44"])
    for _ in range(random.randint(4, 8)):
        send_event(producer, ip, "BEACONING", 443, scenario="beaconing", destination_ip=destination, bytes=random.randint(120, 480))
        time.sleep(random.uniform(0.18, 0.5))


def simulate_lateral_movement(producer, ip):
    for port in [445, 3389, 5985, 22]:
        send_event(producer, ip, "LATERAL_MOVEMENT", port, scenario="lateral_movement", username=random.choice(["svc-deploy", "admin", "backup"]))
        time.sleep(random.uniform(0.12, 0.35))


def simulate_login_anomaly(producer, ip):
    for _ in range(random.randint(3, 6)):
        send_event(producer, ip, "SUSPICIOUS_LOGIN", random.choice([22, 443, 8080]), scenario="login_anomaly", username=random.choice(["financeiro", "admin", "devops"]), geo_change=True)
        time.sleep(random.uniform(0.18, 0.4))


def simulate_exfiltration(producer, ip):
    for _ in range(random.randint(3, 7)):
        send_event(producer, ip, "EXFILTRATION", random.choice([443, 8080]), scenario="exfiltration", destination_ip=random.choice(["198.51.100.220", "203.0.113.88"]), bytes=random.randint(500000, 2500000))
        time.sleep(random.uniform(0.1, 0.28))


def simulate_normal_traffic(producer):
    ip = random.choice(NORMAL_IPS)
    event_type = random.choice(["NORMAL", "HTTP_REQUEST", "DNS_QUERY"])
    port = random.choice(NORMAL_PORTS)
    send_event(producer, ip, event_type, port, scenario="normal")


def simulate_endpoint_telemetry(producer, ip):
    target_host = random.choice(["prod-server-01", "dev-workstation-12", "k8s-node-main"])
    process_name = random.choice(["bash", "curl", "powershell.exe", "apt", "python3", "whoami"])
    parent_process = random.choice(["sshd", "systemd", "explorer.exe"])
    
    # Simula Process Creation (eBPF style)
    event_type = random.choice(["ENDPOINT_PROCESS_START", "SHELL_SPAWN", "CREDENTIAL_ACCESS"])
    cmd = f"/usr/bin/{process_name} -c 'malicious_script.sh'" if event_type != "CREDENTIAL_ACCESS" else "mimikatz.exe"
    
    send_event(producer, ip, event_type, 0, scenario="xdr_endpoint", 
               target_host=target_host, process_name=process_name, parent_process=parent_process,
               pid=random.randint(1000, 65000), command_line=cmd)

def simulate_cloud_telemetry(producer, ip):
    account_id = "123456789012"
    api_call = random.choice(["DescribeInstances", "ListS3Buckets", "AssumeRole", "CreateUser", "DeleteLogGroup", "DeleteTrail"])
    
    event_type = "CLOUD_API_CALL" if "Delete" not in api_call else "CLOUD_API_ABUSE"
    
    # Simula CloudTrail Event
    send_event(producer, ip, event_type, 443, scenario="xdr_cloud",
               cloud_provider="AWS", cloud_account=account_id, aws_region="us-east-1",
               api_call=api_call, user_agent="Boto3/1.26.0 Python/3.10", access_key_id="AKIA...SIM")

def simulate_privilege_escalation(producer, ip):
    target_host = "db-server-secure"
    send_event(producer, ip, "PRIVILEGE_ESCALATION", 0, scenario="xdr_identity",
               target_host=target_host, username="root", method="sudo_exploit")

def run():
    start_ops_server()
    producer = create_producer()
    log_json("INFO", "SENTINELA simulator started with AI-native XDR capabilities")

    while True:
        try:
            scenario = random.random()

            if scenario < 0.15:
                simulate_normal_traffic(producer)
            elif scenario < 0.25:
                simulate_brute_force(producer, random.choice(PERSISTENT_ATTACKERS))
            elif scenario < 0.35:
                simulate_port_scan(producer, random.choice(PERSISTENT_ATTACKERS))
            elif scenario < 0.50:
                simulate_endpoint_telemetry(producer, random.choice(PERSISTENT_ATTACKERS))
            elif scenario < 0.65:
                simulate_cloud_telemetry(producer, random.choice(PERSISTENT_ATTACKERS))
            elif scenario < 0.75:
                simulate_privilege_escalation(producer, random.choice(PERSISTENT_ATTACKERS))
            elif scenario < 0.85:
                simulate_lateral_movement(producer, random.choice(PERSISTENT_ATTACKERS))
            elif scenario < 0.92:
                simulate_login_anomaly(producer, random.choice(PERSISTENT_ATTACKERS + THREAT_INTEL_IPS))
            else:
                simulate_multistage_attack(producer, random.choice(PERSISTENT_ATTACKERS))

            time.sleep(random.uniform(0.5, 2.0))
        except Exception as exc:
            SIMULATOR_FAILURES.labels(service="simulator").inc()
            log_json("ERROR", "Falha no simulador; reconectando", error=str(exc))
            producer = create_producer()


class OpsHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            self.send_response(200 if SERVICE_READY else 503)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            payload = {"status": "ok"} if SERVICE_READY else {"status": "error", "dependencies": {"kafka": "unavailable"}}
            self.wfile.write(json.dumps(payload).encode("utf-8"))
            return
        if self.path == "/metrics":
            data = generate_latest()
            self.send_response(200)
            self.send_header("Content-Type", CONTENT_TYPE_LATEST)
            self.end_headers()
            self.wfile.write(data)
            return
        self.send_response(404)
        self.end_headers()

    def log_message(self, *args):
        return


def start_ops_server():
    server = ThreadingHTTPServer(("0.0.0.0", METRICS_PORT), OpsHandler)
    Thread(target=server.serve_forever, daemon=True).start()


if __name__ == "__main__":
    try:
        run()
    except KeyboardInterrupt:
        log_json("INFO", "Simulador encerrado")
        sys.exit(0)
