import json
import os
import random
import sys
import time
import uuid
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

try:
    import yaml
except ImportError:
    yaml = None

from kafka import KafkaProducer
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, generate_latest


KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
RAW_LOGS_TOPIC = os.getenv("RAW_LOGS_TOPIC", "raw_logs")
DEFAULT_TENANT_ID = os.getenv("DEFAULT_TENANT_ID", "default")
MAX_BACKOFF_SECONDS = float(os.getenv("MAX_BACKOFF_SECONDS", "15"))
METRICS_PORT = int(os.getenv("METRICS_PORT", "8000"))
ENABLE_CAMPAIGNS = os.getenv("ENABLE_CAMPAIGNS", "true").lower() == "true"
CAMPAIGNS_PATH = Path(os.getenv("CAMPAIGNS_PATH", "campaigns/default_campaigns.yml"))
SERVICE_READY = False

SIMULATED_EVENTS = Counter("sentinela_simulator_events_total", "Eventos simulados publicados", ["scenario", "event_type"])
SIMULATOR_FAILURES = Counter("sentinela_service_failures_total", "Falhas por serviço", ["service"])
SERVICE_READY_GAUGE = Gauge("sentinela_service_ready", "Readiness do serviço", ["service"])
CAMPAIGNS_ACTIVE = Gauge("sentinela_simulator_campaigns_active", "Campanhas ativas no momento")

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

CAMPAIGNS_DATA = []

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
        "campaign_id": extra.get("campaign_id"),
        "campaign_name": extra.get("campaign_name"),
        "step_id": extra.get("step_id"),
        "tactic": extra.get("tactic"),
        "technique": extra.get("technique"),
        "api_call": extra.get("api_call"),
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
        campaign_id=extra.get("campaign_id")
    )


def load_campaigns():
    global CAMPAIGNS_DATA
    if not yaml:
        log_json("ERROR", "PyYAML não instalado. Desativando campanhas.")
        return []
    
    if not CAMPAIGNS_PATH.exists():
        log_json("WARN", "Arquivo de campanhas não encontrado", path=str(CAMPAIGNS_PATH))
        return []

    try:
        with open(CAMPAIGNS_PATH, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
            campaigns = data.get("campaigns", [])
            # Validação básica
            valid_campaigns = []
            for c in campaigns:
                if not c.get("name") or not c.get("steps"):
                    log_json("ERROR", "Campanha inválida no YAML (faltando name ou steps)", campaign=c.get("name"))
                    continue
                valid_campaigns.append(c)
            
            log_json("INFO", "Campanhas carregadas com sucesso", count=len(valid_campaigns))
            return valid_campaigns
    except Exception as e:
        log_json("ERROR", "Falha ao carregar YAML de campanhas", error=str(e))
        # Falha segura: retorna lista vazia para não quebrar o simulador
        return []

class CampaignRunner(threading.Thread):
    def __init__(self, producer, campaign):
        super().__init__()
        self.producer = producer
        self.campaign = campaign
        self.campaign_id = str(uuid.uuid4())
        self.daemon = True

    def run(self):
        name = self.campaign["name"]
        attacker_ip = random.choice(self.campaign.get("attacker_pool", PERSISTENT_ATTACKERS))
        target_host = self.campaign.get("target_host", "sentinela-prod-sim")
        
        log_json("WARN", "Iniciando campanha de ataque", 
                 campaign_name=name, campaign_id=self.campaign_id, attacker=attacker_ip)
        
        CAMPAIGNS_ACTIVE.inc()
        try:
            for step in self.campaign["steps"]:
                step_id = step.get("step_id", "unnamed_step")
                tactic = step.get("tactic", "Unknown")
                technique = step.get("technique", "Unknown")
                event_type = step.get("event_type", "SUSPICIOUS")
                port = step.get("port", 0)
                delay = step.get("delay_after", 5)
                
                send_event(
                    self.producer, 
                    attacker_ip, 
                    event_type, 
                    port, 
                    scenario="campaign",
                    campaign_id=self.campaign_id,
                    campaign_name=name,
                    step_id=step_id,
                    tactic=tactic,
                    technique=technique,
                    target_host=target_host,
                    api_call=step.get("api_call")
                )
                
                time.sleep(delay)
            
            log_json("INFO", "Campanha concluída com sucesso", 
                     campaign_name=name, campaign_id=self.campaign_id)
        except Exception as e:
            log_json("ERROR", "Erro durante execução da campanha", 
                     campaign_id=self.campaign_id, error=str(e))
        finally:
            CAMPAIGNS_ACTIVE.dec()

def simulate_normal_traffic(producer):
    ip = random.choice(NORMAL_IPS)
    event_type = random.choice(["NORMAL", "HTTP_REQUEST", "DNS_QUERY"])
    port = random.choice(NORMAL_PORTS)
    send_event(producer, ip, event_type, port, scenario="normal")

def simulate_endpoint_telemetry(producer, ip):
    target_host = random.choice(["prod-server-01", "dev-workstation-12", "k8s-node-main"])
    process_name = random.choice(["bash", "curl", "powershell.exe", "apt", "python3", "whoami"])
    parent_process = random.choice(["sshd", "systemd", "explorer.exe"])
    
    event_type = random.choice(["ENDPOINT_PROCESS_START", "SHELL_SPAWN", "CREDENTIAL_ACCESS"])
    cmd = f"/usr/bin/{process_name} -c 'malicious_script.sh'" if event_type != "CREDENTIAL_ACCESS" else "mimikatz.exe"
    
    send_event(producer, ip, event_type, 0, scenario="xdr_endpoint", 
               target_host=target_host, process_name=process_name, parent_process=parent_process,
               pid=random.randint(1000, 65000), command_line=cmd)

def run():
    start_ops_server()
    producer = create_producer()
    log_json("INFO", "SENTINELA simulator started with Advanced Threat Emulation")

    campaigns = []
    if ENABLE_CAMPAIGNS:
        campaigns = load_campaigns()

    while True:
        try:
            # Chance de iniciar uma campanha se houver campanhas carregadas
            if ENABLE_CAMPAIGNS and campaigns and random.random() < 0.05:
                campaign = random.choice(campaigns)
                if campaign.get("enabled", True):
                    runner = CampaignRunner(producer, campaign)
                    runner.start()

            # Tráfego normal e eventos isolados (Legado compatível)
            scenario = random.random()
            if scenario < 0.40:
                simulate_normal_traffic(producer)
            elif scenario < 0.60:
                simulate_endpoint_telemetry(producer, random.choice(PERSISTENT_ATTACKERS))
            elif scenario < 0.80:
                # Simula um evento aleatório de IP malicioso conhecido
                send_event(producer, random.choice(THREAT_INTEL_IPS), "SUSPICIOUS", random.choice(SENSITIVE_PORTS), scenario="isolated_threat")
            
            time.sleep(random.uniform(1.0, 3.0))
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
    threading.Thread(target=server.serve_forever, daemon=True).start()


if __name__ == "__main__":
    try:
        run()
    except KeyboardInterrupt:
        log_json("INFO", "Simulador encerrado")
        sys.exit(0)
