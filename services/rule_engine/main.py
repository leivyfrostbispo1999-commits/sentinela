import json
import os
import sys
import time
import uuid
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path

import yaml
from kafka import KafkaConsumer, KafkaProducer
from threat_intel import check_ip


KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
RAW_LOGS_TOPIC = os.getenv("RAW_LOGS_TOPIC", "raw_logs")
ALERTS_TOPIC = os.getenv("ALERTS_TOPIC", "security_alerts")
ENABLE_BLOCK = os.getenv("ENABLE_BLOCK", "false").lower() == "true"
MAX_BACKOFF_SECONDS = float(os.getenv("MAX_BACKOFF_SECONDS", "15"))
RULES_PATH = Path(os.getenv("RULES_PATH", "rules.yaml"))

STATE_WINDOW_SECONDS = int(os.getenv("CORRELATION_WINDOW_SECONDS", "300"))
HOSTILE_CAMPAIGN_THRESHOLD = 8
SENSITIVE_PORTS = {22, 23, 3389, 445, 5432, 3306, 6379, 9200}
CRITICAL_STATUSES = {"ATAQUE MULTIETAPA", "CAMPANHA HOSTIL", "BRUTE FORCE CRITICO", "BRUTE FORCE CRÍTICO", "IOC DETECTADO"}

ip_events = defaultdict(lambda: deque())
threat_cache = {}


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def log_json(level, message, **fields):
    payload = {
        "ts": now_iso(),
        "level": level,
        "component": "rule_engine",
        "message": message,
        **fields,
    }
    print(json.dumps(payload, ensure_ascii=False), flush=True)


def backoff_delay(attempt):
    return min(MAX_BACKOFF_SECONDS, 1.5 * (2 ** min(attempt, 4)))


def load_rules():
    fallback = {
        "rules": [
            {"name": "ataque_multi_etapa", "enabled": True, "priority": 80, "conditions": ["PORT_SCAN", "BRUTE_FORCE"], "min_risk": 97, "risk": 97, "status": "ATAQUE MULTIETAPA", "tags": ["fallback"]},
            {"name": "campanha_hostil", "enabled": True, "priority": 70, "threshold": 7, "min_risk": 95, "risk": 95, "status": "CAMPANHA HOSTIL", "tags": ["fallback"]},
        ]
    }
    try:
        with RULES_PATH.open("r", encoding="utf-8") as file:
            ruleset = yaml.safe_load(file) or fallback
            rules = [rule for rule in ruleset.get("rules", []) if isinstance(rule, dict)]
            log_json("INFO", "Regras YAML carregadas", path=str(RULES_PATH), total_rules=len(rules))
            return rules
    except Exception as exc:
        log_json("WARN", "Falha ao carregar rules.yaml; usando regras internas", error=str(exc))
        return fallback["rules"]


def normalize_event_type(log):
    return str(log.get("event_type") or log.get("event") or "unknown").strip().upper()


def normalize_port(port):
    try:
        return int(port)
    except (TypeError, ValueError):
        return None


def prune_state(ip, now):
    events = ip_events[ip]
    while events and now - events[0]["seen_at"] > STATE_WINDOW_SECONDS:
        events.popleft()
    return events


def update_state(log):
    ip = log["ip"]
    now = time.time()
    events = prune_state(ip, now)
    current = {
        "seen_at": now,
        "event_type": normalize_event_type(log),
        "port": normalize_port(log.get("port")),
        "service": str(log.get("service") or "unknown").upper(),
    }
    events.append(current)
    return list(events)


def event_type_matches(item_event_type, condition):
    event = item_event_type.replace("-", "_").replace(" ", "_").upper()
    condition = str(condition).replace("-", "_").replace(" ", "_").upper()

    if condition == "BRUTE_FORCE":
        return "BRUTE" in event or event in {"SSH_FAILED", "LOGIN_FAILED", "AUTH_FAILED"}
    if condition == "PORT_SCAN":
        return "PORT_SCAN" in event or event == "SCAN"
    if condition in {"SUSPICIOUS", "ATIVIDADE_SUSPEITA"}:
        return event in {"SUSPICIOUS", "SUSPICIOUS_LOGIN", "ATIVIDADE_SUSPEITA", "LOGIN_SUSPEITO"}

    return event == condition


def event_matches(item, condition):
    if isinstance(condition, str):
        return event_type_matches(item["event_type"], condition)

    if not isinstance(condition, dict):
        return False

    event_types = condition.get("event_type") or condition.get("event_types")
    if event_types:
        if isinstance(event_types, str):
            event_types = [event_types]
        if not any(event_type_matches(item["event_type"], event_type) for event_type in event_types):
            return False

    ports = condition.get("port") or condition.get("ports")
    if ports:
        if not isinstance(ports, list):
            ports = [ports]
        normalized_ports = {normalize_port(port) for port in ports}
        if item.get("port") not in normalized_ports:
            return False

    if condition.get("sensitive_ports") and item.get("port") not in SENSITIVE_PORTS:
        return False

    services = condition.get("service") or condition.get("services")
    if services:
        if isinstance(services, str):
            services = [services]
        normalized_services = {str(service).upper() for service in services}
        if item.get("service") not in normalized_services:
            return False

    return True


def rule_window_events(events, rule):
    window = int(rule.get("window_seconds") or STATE_WINDOW_SECONDS)
    now = time.time()
    return [item for item in events if now - item["seen_at"] <= window]


def sequence_matches(events, conditions):
    index = 0
    for item in events:
        if event_matches(item, conditions[index]):
            index += 1
            if index == len(conditions):
                return True
    return False


def apply_yaml_rules(events, rules):
    matches = []
    for rule in rules:
        if rule.get("enabled", True) is False:
            continue

        scoped_events = rule_window_events(events, rule)
        conditions = rule.get("conditions", [])
        threshold = int(rule.get("threshold") or 0)

        matched = False
        if conditions and threshold:
            count = sum(1 for item in scoped_events if any(event_matches(item, condition) for condition in conditions))
            matched = count >= threshold
        elif conditions:
            matched = sequence_matches(scoped_events, conditions)
        elif threshold:
            matched = len(scoped_events) >= threshold

        if matched:
            matches.append(rule)

    return sorted(matches, key=lambda item: int(item.get("priority") or 0), reverse=True)


def build_correlation(events, log):
    ip = log["ip"]
    service = str(log.get("service") or "unknown").upper()
    port = normalize_port(log.get("port"))
    event_type = normalize_event_type(log)

    same_service = [item for item in events if item.get("service") == service]
    same_port = [item for item in events if item.get("port") == port and port is not None]
    same_type = [item for item in events if event_type_matches(item.get("event_type", ""), event_type)]

    if len(same_service) >= 3:
        return f"{ip}|service:{service}", f"Mesmo IP com múltiplos eventos no serviço {service} dentro da janela temporal"

    if len(same_port) >= 3:
        return f"{ip}|port:{port}", f"Mesmo IP com múltiplos eventos na porta {port} dentro da janela temporal"

    if len(same_type) >= 3:
        return f"{ip}|event_type:{event_type}", f"Mesmo IP repetindo o tipo de evento {event_type} dentro da janela temporal"

    return f"{ip}|event:{event_type}", "Correlação primária por IP e tipo de evento dentro da janela temporal"


def base_status_and_score(event_type):
    event = event_type.replace("-", "_").replace(" ", "_")

    if "BRUTE" in event or event in {"SSH_FAILED", "LOGIN_FAILED", "AUTH_FAILED"}:
        return "BRUTE FORCE", 78

    if "PORT_SCAN" in event or event == "SCAN":
        return "PORT SCAN", 68

    if event in {"SUSPICIOUS", "SUSPICIOUS_LOGIN", "ATIVIDADE_SUSPEITA", "LOGIN_SUSPEITO"}:
        return "ATIVIDADE SUSPEITA", 58

    if event in {"NORMAL", "HTTP_REQUEST", "HEALTHCHECK", "DNS_QUERY"}:
        return "TRÁFEGO NORMAL", 18

    return "TRÁFEGO NORMAL", 25


def has_multistage_sequence(events):
    saw_scan = False
    for item in events:
        event_type = item["event_type"].replace("-", "_").replace(" ", "_")
        if "PORT_SCAN" in event_type or event_type == "SCAN":
            saw_scan = True
        if saw_scan and ("BRUTE" in event_type or event_type in {"SSH_FAILED", "LOGIN_FAILED", "AUTH_FAILED"}):
            return True
    return False


def simulated_external_threat_lookup(ip):
    cached = threat_cache.get(ip)
    now = time.time()
    if cached and now - cached["cached_at"] < 1800:
        return cached["result"]

    last_octet = 0
    try:
        last_octet = int(str(ip).split(".")[-1])
    except (TypeError, ValueError):
        pass

    result = None
    if str(ip).startswith(("198.51.100.", "203.0.113.")) and last_octet % 2 == 0:
        result = {
            "reputation_score": 84,
            "category": "EXTERNAL_REPUTATION",
            "description": "API externa simulada indicou reputação suspeita",
            "source": "external",
        }

    threat_cache[ip] = {"cached_at": now, "result": result}
    return result


def enrich_threat_intel(ip):
    local = check_ip(ip)
    if local:
        return {**local, "source": "local"}

    return simulated_external_threat_lookup(ip)


def calculate_risk(log, events, threat_match, rules):
    event_type = normalize_event_type(log)
    port = normalize_port(log.get("port"))
    status, risk = base_status_and_score(event_type)
    reasons = []
    matched_rules = apply_yaml_rules(events, rules)

    if port in SENSITIVE_PORTS:
        risk += 10
        reasons.append("porta_sensivel")

    frequency = len(events)
    if frequency >= HOSTILE_CAMPAIGN_THRESHOLD:
        risk += 18
        reasons.append("frequencia_alta")
    elif frequency >= 4:
        risk += 8
        reasons.append("frequencia_media")

    for rule in matched_rules:
        status = rule.get("status", status)
        risk = max(risk, int(rule.get("min_risk") or rule.get("risk") or risk))
        reasons.append(f"regra_yaml:{rule.get('name', 'sem_nome')}")
        for tag in rule.get("tags", []):
            reasons.append(f"tag:{tag}")

    if threat_match:
        status = "IOC DETECTADO" if status not in {"ATAQUE MULTIETAPA", "CAMPANHA HOSTIL"} else status
        risk += 22
        risk = max(risk, 98)
        reasons.append("threat_intel")

    if status == "TRÁFEGO NORMAL":
        risk = min(risk, 34)

    return status, max(0, min(100, risk)), reasons


def simulated_auto_response(status, risk, threat_intel_match):
    should_block = risk >= 95 or status in CRITICAL_STATUSES or threat_intel_match

    if should_block and ENABLE_BLOCK:
        log_json("WARN", "ENABLE_BLOCK=true solicitado, mas bloqueio real permanece desativado por segurança")

    if should_block:
        return "simulated_block", True

    return "none", False


def build_alert(log, status, risk, events, risk_reasons, auto_response, simulated_block, threat, correlation_key, correlation_reason):
    event_id = log.get("event_id") or str(uuid.uuid4())
    log["event_id"] = event_id

    threat_intel_match = threat is not None
    event_type = normalize_event_type(log)
    port = normalize_port(log.get("port"))
    service = log.get("service") or "unknown"

    return {
        "event_id": event_id,
        "ts": log.get("ts") or log.get("timestamp") or now_iso(),
        "ip": log["ip"],
        "status": status,
        "risco": risk,
        "score_final": risk,
        "service": service,
        "port": port,
        "event_type": event_type,
        "ip_event_count": len(events),
        "risk_reasons": risk_reasons,
        "threat_intel_match": threat_intel_match,
        "threat_category": threat.get("category") if threat else None,
        "threat_description": threat.get("description") if threat else None,
        "threat_reputation_score": threat.get("reputation_score") if threat else None,
        "threat_source": threat.get("source") if threat else None,
        "correlation_window_seconds": STATE_WINDOW_SECONDS,
        "correlation_key": correlation_key,
        "correlation_reason": correlation_reason,
        "auto_response": auto_response,
        "simulated_block": simulated_block,
        "should_blacklist": simulated_block,
        "raw_event": log,
    }


def create_consumer():
    attempt = 0
    while True:
        try:
            consumer = KafkaConsumer(
                RAW_LOGS_TOPIC,
                bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
                group_id="rule-engine-live",
                auto_offset_reset="latest",
                enable_auto_commit=True,
                value_deserializer=lambda message: json.loads(message.decode("utf-8")),
            )
            log_json("INFO", "Kafka conectado", topic=RAW_LOGS_TOPIC)
            return consumer
        except Exception as exc:
            delay = backoff_delay(attempt)
            log_json("WARN", "Aguardando Kafka consumer", error=str(exc), retry_in_seconds=delay)
            time.sleep(delay)
            attempt += 1


def create_producer():
    attempt = 0
    while True:
        try:
            producer = KafkaProducer(
                bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
                value_serializer=lambda value: json.dumps(value, ensure_ascii=False).encode("utf-8"),
            )
            log_json("INFO", "Kafka producer conectado", topic=ALERTS_TOPIC)
            return producer
        except Exception as exc:
            delay = backoff_delay(attempt)
            log_json("WARN", "Aguardando Kafka producer", error=str(exc), retry_in_seconds=delay)
            time.sleep(delay)
            attempt += 1


def process_log(log, producer, rules):
    if "event_id" not in log:
        log["event_id"] = str(uuid.uuid4())

    ip = log.get("ip")
    if not ip:
        log_json("WARN", "Evento descartado sem IP", event_id=log["event_id"], raw_event=log)
        return

    events = update_state(log)
    threat = enrich_threat_intel(ip)
    status, risk, risk_reasons = calculate_risk(log, events, threat, rules)
    correlation_key, correlation_reason = build_correlation(events, log)
    auto_response, simulated_block = simulated_auto_response(status, risk, threat is not None)
    alert = build_alert(log, status, risk, events, risk_reasons, auto_response, simulated_block, threat, correlation_key, correlation_reason)

    producer.send(ALERTS_TOPIC, alert)
    producer.flush(timeout=2)

    log_json(
        "INFO",
        "Alerta publicado",
        event_id=alert["event_id"],
        ip=ip,
        status=status,
        risco=risk,
        service=alert["service"],
        port=alert["port"],
        event_type=alert["event_type"],
        ip_event_count=alert["ip_event_count"],
        threat_intel_match=alert["threat_intel_match"],
        simulated_block=simulated_block,
        threat_source=alert["threat_source"],
        correlation_key=alert["correlation_key"],
    )


def run():
    log_json("INFO", "Motor de regras Sentinela iniciado", enable_block=ENABLE_BLOCK)
    rules = load_rules()

    while True:
        try:
            consumer = create_consumer()
            producer = create_producer()
            for message in consumer:
                process_log(message.value, producer, rules)
        except Exception as exc:
            log_json("ERROR", "Erro no loop do Rule Engine; reconectando", error=str(exc))
            time.sleep(backoff_delay(0))


if __name__ == "__main__":
    try:
        run()
    except KeyboardInterrupt:
        log_json("INFO", "Rule Engine encerrado")
        sys.exit(0)
