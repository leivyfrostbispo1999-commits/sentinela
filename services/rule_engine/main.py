import json
import hashlib
import os
import socket
import sys
import time
import uuid
from collections import defaultdict, deque
from urllib.parse import urlparse
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
ALERT_DEDUP_WINDOW_SECONDS = int(os.getenv("ALERT_DEDUP_WINDOW_SECONDS", "60"))
ALERT_RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("ALERT_RATE_LIMIT_WINDOW_SECONDS", "60"))
ALERT_AGGREGATION_WINDOW_SECONDS = int(os.getenv("ALERT_AGGREGATION_WINDOW_SECONDS", "120"))
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
REDIS_STATE_ENABLED = os.getenv("REDIS_STATE_ENABLED", "true").lower() == "true"
HOSTILE_CAMPAIGN_THRESHOLD = 8
SENSITIVE_PORTS = {22, 23, 3389, 445, 5432, 3306, 6379, 9200}
CRITICAL_STATUSES = {"ATAQUE MULTIETAPA", "CAMPANHA HOSTIL", "BRUTE FORCE CRITICO", "BRUTE FORCE CRÍTICO", "IOC DETECTADO"}
SEVERITY_PRIORITY = {
    "TRÁFEGO NORMAL": 0,
    "TRAFego NORMAL": 0,
    "ATIVIDADE SUSPEITA": 1,
    "PORT SCAN": 1,
    "BRUTE FORCE": 2,
    "IOC DETECTADO": 3,
    "ATAQUE MULTIETAPA": 4,
    "CAMPANHA HOSTIL": 4,
    "BRUTE FORCE CRITICO": 4,
    "BRUTE FORCE CRÍTICO": 4,
}

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


def parse_epoch(value):
    if isinstance(value, (int, float)):
        return float(value)
    if not value:
        return time.time()
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed.timestamp()
    except Exception:
        return time.time()


def epoch_to_iso(value):
    return datetime.fromtimestamp(float(value), timezone.utc).isoformat()


def unique_preserve_order(values):
    seen = set()
    ordered = []
    for value in values:
        if value is None:
            continue
        marker = json.dumps(value, sort_keys=True, ensure_ascii=False) if isinstance(value, (dict, list)) else value
        if marker in seen:
            continue
        seen.add(marker)
        ordered.append(value)
    return ordered


def sort_values(values):
    normalized = []
    for value in values:
        if value is None:
            continue
        if isinstance(value, int):
            normalized.append(value)
        else:
            try:
                normalized.append(int(value))
            except Exception:
                normalized.append(str(value))
    return normalized


def stable_alert_instance_id(aggregation_key, first_seen_epoch):
    bucket = int(float(first_seen_epoch) // max(1, ALERT_AGGREGATION_WINDOW_SECONDS))
    seed = f"{aggregation_key}|{bucket}"
    return str(uuid.uuid5(uuid.NAMESPACE_URL, seed))


def alert_signature(alert):
    parts = [
        str(alert.get("ip") or ""),
        str(alert.get("event_type") or ""),
        str(alert.get("status") or ""),
        str(alert.get("port") or ""),
        str(alert.get("threat_category") or ""),
    ]
    return "|".join(parts)


def alert_aggregation_key(alert):
    return f"{alert.get('ip') or 'unknown'}|status:{alert.get('status') or 'unknown'}"


def summarize_bucket(aggregation_key, status, entries, base_alert):
    if not entries:
        entries = [base_alert]

    occurrence_count = len(entries)
    first_seen_epoch = min(item["seen_at"] for item in entries)
    last_seen_epoch = max(item["seen_at"] for item in entries)
    ports = unique_preserve_order(sort_values(item.get("port") for item in entries))
    services = unique_preserve_order([str(item.get("service") or "unknown").lower() for item in entries])
    event_types = unique_preserve_order([str(item.get("event_type") or "unknown").upper() for item in entries])
    max_risk = max(int(item.get("risk") or 0) for item in entries)
    threat_candidates = [item for item in entries if item.get("threat_intel_match") or item.get("threat_category")]
    threat_item = threat_candidates[-1] if threat_candidates else base_alert
    simulated_block = any(bool(item.get("simulated_block")) for item in entries)
    action_soc = "BLOQUEIO SIMULADO" if simulated_block else ("INVESTIGANDO" if max_risk >= 70 or threat_candidates else "MONITORADO")
    aggregated = occurrence_count > 1 or len(ports) > 1 or len(services) > 1 or len(event_types) > 1
    dedup_key = base_alert.get("dedup_key") or alert_signature(base_alert)
    event_id = stable_alert_instance_id(aggregation_key, first_seen_epoch)

    return {
        "event_id": event_id,
        "aggregation_key": aggregation_key,
        "dedup_key": dedup_key,
        "occurrence_count": occurrence_count,
        "first_seen": epoch_to_iso(first_seen_epoch),
        "last_seen": epoch_to_iso(last_seen_epoch),
        "aggregated": aggregated,
        "ports": ports,
        "services": services,
        "event_types": event_types,
        "max_risk": max_risk,
        "threat_category": threat_item.get("threat_category"),
        "threat_description": threat_item.get("threat_description"),
        "threat_reputation_score": threat_item.get("threat_reputation_score"),
        "threat_source": threat_item.get("threat_source"),
        "simulated_block": simulated_block,
        "action_soc": action_soc,
        "status": status,
        "window_seconds": ALERT_AGGREGATION_WINDOW_SECONDS,
        "rate_limit_window_seconds": ALERT_RATE_LIMIT_WINDOW_SECONDS,
        "dedup_window_seconds": ALERT_DEDUP_WINDOW_SECONDS,
    }


def normalize_aggregate_entry(entry):
    normalized = dict(entry)
    normalized["seen_at"] = float(normalized.get("seen_at", time.time()))
    normalized["port"] = normalize_port(normalized.get("port"))
    normalized["risk"] = int(normalized.get("risk") or 0)
    normalized["service"] = str(normalized.get("service") or "unknown").lower()
    normalized["event_type"] = str(normalized.get("event_type") or "unknown").upper()
    normalized["simulated_block"] = bool(normalized.get("simulated_block"))
    normalized["threat_intel_match"] = bool(normalized.get("threat_intel_match"))
    return normalized


class InMemoryCorrelationStore:
    def __init__(self, window_seconds):
        self.window_seconds = window_seconds
        self.ip_events = defaultdict(lambda: deque())
        self.alert_buckets = defaultdict(lambda: deque())

    def add_event(self, ip, event):
        now = event["seen_at"]
        events = self.ip_events[ip]
        while events and now - events[0]["seen_at"] > self.window_seconds:
            events.popleft()
        events.append(event)
        return list(events)

    def record_aggregate(self, aggregation_key, status, alert):
        now = float(alert["seen_at"])
        bucket = self.alert_buckets[aggregation_key]
        while bucket and now - bucket[0]["seen_at"] > ALERT_AGGREGATION_WINDOW_SECONDS:
            bucket.popleft()
        bucket.append(normalize_aggregate_entry(alert))
        return summarize_bucket(aggregation_key, status, list(bucket), alert)


class RedisCorrelationStore:
    def __init__(self, redis_url, window_seconds):
        parsed = urlparse(redis_url)
        self.host = parsed.hostname or "redis"
        self.port = parsed.port or 6379
        self.db = int((parsed.path or "/0").strip("/") or 0)
        self.window_seconds = window_seconds
        self.key_prefix = "sentinela:rule_engine:events:"
        self.aggregate_prefix = "sentinela:rule_engine:alerts:"
        self.timeout = 0.8
        self._select_db()

    def _encode_command(self, *parts):
        encoded = [str(part).encode("utf-8") for part in parts]
        payload = f"*{len(encoded)}\r\n".encode("ascii")
        for part in encoded:
            payload += f"${len(part)}\r\n".encode("ascii") + part + b"\r\n"
        return payload

    def _read_line(self, sock):
        data = b""
        while not data.endswith(b"\r\n"):
            chunk = sock.recv(1)
            if not chunk:
                raise ConnectionError("conexão Redis encerrada")
            data += chunk
        return data[:-2]

    def _read_response(self, sock):
        marker = sock.recv(1)
        if not marker:
            raise ConnectionError("resposta Redis vazia")
        if marker == b"+":
            return self._read_line(sock).decode("utf-8")
        if marker == b"-":
            raise RuntimeError(self._read_line(sock).decode("utf-8"))
        if marker == b":":
            return int(self._read_line(sock))
        if marker == b"$":
            length = int(self._read_line(sock))
            if length == -1:
                return None
            payload = b""
            while len(payload) < length:
                payload += sock.recv(length - len(payload))
            sock.recv(2)
            return payload.decode("utf-8")
        raise RuntimeError(f"resposta Redis não suportada: {marker!r}")

    def _execute(self, *parts):
        with socket.create_connection((self.host, self.port), timeout=self.timeout) as sock:
            if self.db:
                sock.sendall(self._encode_command("SELECT", self.db))
                self._read_response(sock)
            sock.sendall(self._encode_command(*parts))
            return self._read_response(sock)

    def _select_db(self):
        self._execute("PING")

    def add_event(self, ip, event):
        key = f"{self.key_prefix}{ip}"
        now = event["seen_at"]
        raw_events = self._execute("GET", key)
        events = json.loads(raw_events) if raw_events else []
        events = [item for item in events if now - float(item.get("seen_at", 0)) <= self.window_seconds]
        events.append(event)
        self._execute("SET", key, json.dumps(events, ensure_ascii=False), "EX", self.window_seconds * 2)
        return events

    def record_aggregate(self, aggregation_key, status, alert):
        key = f"{self.aggregate_prefix}{aggregation_key}"
        now = float(alert["seen_at"])
        raw_bucket = self._execute("GET", key)
        entries = json.loads(raw_bucket) if raw_bucket else []
        entries = [normalize_aggregate_entry(item) for item in entries if now - float(item.get("seen_at", 0)) <= ALERT_AGGREGATION_WINDOW_SECONDS]
        entries.append(normalize_aggregate_entry(alert))
        self._execute("SET", key, json.dumps(entries, ensure_ascii=False), "EX", ALERT_AGGREGATION_WINDOW_SECONDS * 2)
        return summarize_bucket(aggregation_key, status, entries, alert)


def create_state_store():
    if REDIS_STATE_ENABLED:
        try:
            store = RedisCorrelationStore(REDIS_URL, STATE_WINDOW_SECONDS)
            log_json("INFO", "State store Redis habilitado", redis_url=REDIS_URL)
            return store
        except Exception as exc:
            log_json("WARN", "Redis indisponível; usando state store em memória", error=str(exc))
    return InMemoryCorrelationStore(STATE_WINDOW_SECONDS)


STATE_STORE = create_state_store()


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


def update_state(log):
    ip = log["ip"]
    now = time.time()
    current = {
        "seen_at": now,
        "event_type": normalize_event_type(log),
        "port": normalize_port(log.get("port")),
        "service": str(log.get("service") or "unknown").upper(),
    }
    return STATE_STORE.add_event(ip, current)


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
    service = str(log.get("service") or "unknown").lower()
    seen_at = parse_epoch(log.get("ts") or log.get("timestamp") or time.time())
    ts_value = epoch_to_iso(seen_at)

    base_alert = {
        "event_id": event_id,
        "ip": log["ip"],
        "status": status,
        "risk": risk,
        "seen_at": seen_at,
        "port": port,
        "service": service,
        "event_type": event_type,
        "threat_intel_match": threat_intel_match,
        "threat_category": threat.get("category") if threat else None,
        "threat_description": threat.get("description") if threat else None,
        "threat_reputation_score": threat.get("reputation_score") if threat else None,
        "threat_source": threat.get("source") if threat else None,
        "simulated_block": simulated_block,
        "action_soc": "BLOQUEIO SIMULADO" if simulated_block else ("INVESTIGANDO" if risk >= 70 or threat_intel_match else "MONITORADO"),
        "dedup_key": alert_signature({
            "ip": log["ip"],
            "status": status,
            "event_type": event_type,
            "port": port,
            "threat_category": threat.get("category") if threat else None,
        }),
    }

    aggregation_key = alert_aggregation_key(base_alert)
    aggregate_state = STATE_STORE.record_aggregate(aggregation_key, status, base_alert)

    return {
        "event_id": aggregate_state["event_id"],
        "ts": ts_value,
        "ip": log["ip"],
        "status": status,
        "risco": max(risk, aggregate_state["max_risk"]),
        "score_final": max(risk, aggregate_state["max_risk"]),
        "service": service,
        "port": port,
        "event_type": event_type,
        "ip_event_count": len(events),
        "risk_reasons": risk_reasons,
        "threat_intel_match": threat_intel_match,
        "threat_category": aggregate_state["threat_category"],
        "threat_description": aggregate_state["threat_description"],
        "threat_reputation_score": aggregate_state["threat_reputation_score"],
        "threat_source": aggregate_state["threat_source"],
        "correlation_window_seconds": STATE_WINDOW_SECONDS,
        "correlation_key": correlation_key,
        "correlation_reason": correlation_reason,
        "auto_response": auto_response,
        "action_soc": aggregate_state["action_soc"],
        "simulated_block": simulated_block or aggregate_state["simulated_block"],
        "should_blacklist": simulated_block,
        "raw_event": log,
        "occurrence_count": aggregate_state["occurrence_count"],
        "first_seen": aggregate_state["first_seen"],
        "last_seen": aggregate_state["last_seen"],
        "aggregated": aggregate_state["aggregated"],
        "ports": aggregate_state["ports"],
        "services": aggregate_state["services"],
        "event_types": aggregate_state["event_types"],
        "aggregation_key": aggregate_state["aggregation_key"],
        "dedup_key": aggregate_state["dedup_key"],
        "rate_limit_window_seconds": aggregate_state["rate_limit_window_seconds"],
        "dedup_window_seconds": aggregate_state["dedup_window_seconds"],
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
        occurrence_count=alert["occurrence_count"],
        aggregated=alert["aggregated"],
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
