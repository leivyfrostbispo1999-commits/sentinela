import json
import hashlib
import os
import re
import socket
import sys
import time
import uuid
from collections import defaultdict, deque
from urllib.parse import urlparse
from datetime import datetime, timezone
from pathlib import Path

try:
    import yaml
except ImportError:
    yaml = None
from kafka import KafkaConsumer, KafkaProducer
from threat_intel import check_ip


KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
RAW_LOGS_TOPIC = os.getenv("RAW_LOGS_TOPIC", "raw_logs")
ALERTS_TOPIC = os.getenv("ALERTS_TOPIC", "security_alerts")
ENABLE_BLOCK = os.getenv("ENABLE_BLOCK", "false").lower() == "true"
MAX_BACKOFF_SECONDS = float(os.getenv("MAX_BACKOFF_SECONDS", "15"))
RULES_PATH = Path(os.getenv("RULES_PATH", "sentinela_rules.yml"))

STATE_WINDOW_SECONDS = int(os.getenv("CORRELATION_WINDOW_SECONDS", "300"))
ALERT_DEDUP_WINDOW_SECONDS = int(os.getenv("ALERT_DEDUP_WINDOW_SECONDS", "60"))
ALERT_RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("ALERT_RATE_LIMIT_WINDOW_SECONDS", "60"))
ALERT_AGGREGATION_WINDOW_SECONDS = int(os.getenv("ALERT_AGGREGATION_WINDOW_SECONDS", "120"))
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
REDIS_STATE_ENABLED = os.getenv("REDIS_STATE_ENABLED", "true").lower() == "true"
HOSTILE_CAMPAIGN_THRESHOLD = 8
SENSITIVE_PORTS = {22, 23, 3389, 445, 5432, 3306, 6379, 9200}
PRIVILEGED_USERS = {"admin", "root", "administrator"}
ASSET_CRITICALITY_BY_SERVICE = {
    "ssh": "high",
    "rdp": "high",
    "postgres": "high",
    "mysql": "high",
    "redis": "critical",
    "elasticsearch": "high",
    "security": "critical",
}
SCORE_WEIGHTS = {
    "failed_login": 10,
    "admin_user_attempt": 25,
    "brute_force_pattern": 40,
    "suspicious_ip": 20,
    "repeated_events_short_window": 30,
}
MITRE_MAPPINGS = {
    "PORT_SCAN": {"mitre_id": "T1046", "mitre_name": "Network Service Discovery", "mitre_tactic": "Discovery"},
    "SCAN": {"mitre_id": "T1046", "mitre_name": "Network Service Discovery", "mitre_tactic": "Discovery"},
    "BRUTE_FORCE": {"mitre_id": "T1110", "mitre_name": "Brute Force", "mitre_tactic": "Credential Access"},
    "FAILED_LOGIN": {"mitre_id": "T1110", "mitre_name": "Brute Force", "mitre_tactic": "Credential Access"},
    "SSH_FAILED": {"mitre_id": "T1110", "mitre_name": "Brute Force", "mitre_tactic": "Credential Access"},
    "LOGIN_FAILED": {"mitre_id": "T1110", "mitre_name": "Brute Force", "mitre_tactic": "Credential Access"},
    "AUTH_FAILED": {"mitre_id": "T1110", "mitre_name": "Brute Force", "mitre_tactic": "Credential Access"},
    "SUSPICIOUS": {"mitre_id": "T1087", "mitre_name": "Account Discovery", "mitre_tactic": "Discovery"},
    "SUSPICIOUS_LOGIN": {"mitre_id": "T1087", "mitre_name": "Account Discovery", "mitre_tactic": "Discovery"},
    "IOC_MATCH": {"mitre_id": "T1071", "mitre_name": "Application Layer Protocol", "mitre_tactic": "Command and Control"},
    "IOC DETECTADO": {"mitre_id": "T1071", "mitre_name": "Application Layer Protocol", "mitre_tactic": "Command and Control"},
    "ESCALATION": {"mitre_id": "T1068", "mitre_name": "Exploitation for Privilege Escalation", "mitre_tactic": "Privilege Escalation"},
}
MITRE_BY_ID = {value["mitre_id"]: value for value in MITRE_MAPPINGS.values()}
REAL_MITRE_ID_PATTERN = re.compile(r"^T\d{4}(?:\.\d{3})?$")
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
            {"name": "port_scan", "description": "Detecta varredura de portas", "enabled": True, "priority": 20, "event_type": "PORT_SCAN", "score": 25, "severity": "LOW", "mitre_id": "T1046", "threshold": 1, "window_seconds": 60, "tags": ["reconnaissance"], "correlation_key": "source_ip", "action": "monitor"},
            {"name": "ssh_brute_force", "description": "Detecta múltiplas falhas de login SSH em curto intervalo", "enabled": True, "priority": 40, "event_type": "FAILED_LOGIN", "score": 40, "severity": "HIGH", "mitre_id": "T1110", "threshold": 5, "window_seconds": 60, "tags": ["ssh", "credential_access"], "correlation_key": "source_ip", "action": "simulated_block"},
            {"name": "brute_force", "description": "Detecta padrão explícito de brute force", "enabled": True, "priority": 45, "event_type": "BRUTE_FORCE", "score": 40, "severity": "HIGH", "mitre_id": "T1110", "threshold": 3, "window_seconds": 60, "tags": ["credential_access"], "correlation_key": "source_ip", "action": "simulated_block"},
            {"name": "ioc_match", "description": "Detecta correspondência com IOC local", "enabled": True, "priority": 90, "event_type": "IOC_MATCH", "score": 85, "severity": "CRITICAL", "mitre_id": "T1071", "threshold": 1, "window_seconds": 300, "tags": ["ioc", "threat_intel"], "correlation_key": "source_ip", "action": "simulated_block"},
            {"name": "ataque_multi_etapa", "enabled": True, "priority": 80, "conditions": ["PORT_SCAN", "BRUTE_FORCE"], "min_risk": 97, "risk": 97, "status": "ATAQUE MULTIETAPA", "tags": ["fallback"]},
            {"name": "campanha_hostil", "enabled": True, "priority": 70, "threshold": 7, "min_risk": 95, "risk": 95, "status": "CAMPANHA HOSTIL", "tags": ["fallback"]},
        ]
    }

    def normalize_rules(rules):
        normalized = []
        for rule in rules:
            if not isinstance(rule, dict):
                log_json("WARN", "Regra YAML ignorada: item inválido")
                continue
            if rule.get("enabled", True) is False:
                log_json("INFO", "Regra YAML desabilitada ignorada", rule=rule.get("name"))
                continue
            if not rule.get("name"):
                log_json("WARN", "Regra YAML ignorada: nome ausente", rule=rule)
                continue
            if not rule.get("event_type") and not rule.get("conditions") and not rule.get("threshold"):
                log_json("WARN", "Regra YAML ignorada: condição ausente", rule=rule.get("name"))
                continue
            score = rule.get("score", rule.get("risk", rule.get("min_risk", 0)))
            try:
                score = int(score or 0)
            except (TypeError, ValueError):
                log_json("WARN", "Regra YAML com score inválido; usando 0", rule=rule.get("name"), score=rule.get("score"))
                score = 0
            normalized.append({
                **rule,
                "score": score,
                "severity": str(rule.get("severity") or severity_from_score(score)).upper(),
                "threshold": int(rule.get("threshold") or 1),
                "window_seconds": int(rule.get("window_seconds") or os.getenv("CORRELATION_WINDOW_SECONDS", "300")),
                "tags": rule.get("tags") if isinstance(rule.get("tags"), list) else [],
                "correlation_key": rule.get("correlation_key", "source_ip"),
                "action": rule.get("action", "monitor"),
            })
        return normalized

    if yaml is None:
        log_json("WARN", "PyYAML indisponível; usando regras internas")
        return normalize_rules(fallback["rules"])

    candidates = unique_preserve_order([RULES_PATH, Path("rules.yaml"), Path("sentinela_rules.yml")])
    try:
        for candidate in candidates:
            if not candidate.exists():
                continue
            with candidate.open("r", encoding="utf-8") as file:
                ruleset = yaml.safe_load(file) or fallback
                rules = [rule for rule in ruleset.get("rules", []) if isinstance(rule, dict)]
                normalized = normalize_rules(rules)
                if not normalized:
                    log_json("WARN", "YAML sem regras válidas; usando regras internas", path=str(candidate))
                    return normalize_rules(fallback["rules"])
                log_json("INFO", "Regras YAML carregadas", path=str(candidate), total_rules=len(normalized))
                return normalized
    except Exception as exc:
        log_json("WARN", "Falha ao carregar YAML; usando regras internas", error=str(exc))
    log_json("WARN", "Arquivo YAML não encontrado; usando regras internas", path=str(RULES_PATH))
    return normalize_rules(fallback["rules"])


def normalize_event_type(log):
    return str(log.get("event_type") or log.get("event") or "unknown").strip().upper()


def normalize_mitre_key(value):
    return str(value or "").replace("-", "_").replace(" ", "_").upper()


def mitre_for_event(event_type, status=None, threat_match=None, simulated_block=False, rules=None):
    rules = rules or []
    event_key = normalize_mitre_key(event_type)
    for rule in rules:
        if rule.get("enabled", True) is False:
            continue
        mitre_id = str(rule.get("mitre_id") or "").upper()
        if normalize_mitre_key(rule.get("event_type")) == event_key and REAL_MITRE_ID_PATTERN.match(mitre_id):
            base = MITRE_BY_ID.get(str(rule.get("mitre_id")).upper(), {})
            return {
                "mitre_id": rule.get("mitre_id"),
                "mitre_name": rule.get("mitre_name") or base.get("mitre_name") or rule.get("name", "Regra customizada"),
                "mitre_tactic": rule.get("mitre_tactic") or base.get("mitre_tactic") or "Custom Detection",
            }
    if threat_match:
        return MITRE_MAPPINGS["IOC_MATCH"]
    if status and normalize_mitre_key(status) in MITRE_MAPPINGS:
        return MITRE_MAPPINGS[normalize_mitre_key(status)]
    return MITRE_MAPPINGS.get(event_key, {"mitre_id": None, "mitre_name": None, "mitre_tactic": None})


def normalize_source_ip(log):
    return str(log.get("source_ip") or log.get("ip") or "").strip()


def normalize_username(value):
    return str(value or "").strip().lower()


def is_failed_login(event_type):
    event = str(event_type or "").replace("-", "_").replace(" ", "_").upper()
    return event in {"FAILED_LOGIN", "SSH_FAILED", "LOGIN_FAILED", "AUTH_FAILED"} or "FAILED_LOGIN" in event


def is_brute_force(event_type):
    event = str(event_type or "").replace("-", "_").replace(" ", "_").upper()
    return "BRUTE" in event or event in {"SSH_FAILED", "LOGIN_FAILED", "AUTH_FAILED"}


def is_suspicious_event(event_type):
    event = str(event_type or "").replace("-", "_").replace(" ", "_").upper()
    return event in {"SUSPICIOUS", "SUSPICIOUS_LOGIN", "ATIVIDADE_SUSPEITA", "LOGIN_SUSPEITO"} or "SUSPICIOUS" in event


def normalize_port(port):
    try:
        return int(port)
    except (TypeError, ValueError):
        return None


def update_state(log):
    ip = normalize_source_ip(log)
    now = time.time()
    current = {
        "seen_at": now,
        "event_type": normalize_event_type(log),
        "port": normalize_port(log.get("port")),
        "service": str(log.get("service") or "unknown").upper(),
        "username": normalize_username(log.get("username") or log.get("user")),
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
    ip = normalize_source_ip(log)
    service = str(log.get("service") or "unknown").upper()
    port = normalize_port(log.get("port"))
    event_type = normalize_event_type(log)
    username = normalize_username(log.get("username") or log.get("user"))

    same_service = [item for item in events if item.get("service") == service]
    same_port = [item for item in events if item.get("port") == port and port is not None]
    same_type = [item for item in events if event_type_matches(item.get("event_type", ""), event_type)]
    failed_logins = [item for item in events if is_failed_login(item.get("event_type")) or is_brute_force(item.get("event_type"))]
    privileged_attempts = [item for item in events if item.get("username") in PRIVILEGED_USERS]

    if len(failed_logins) >= 3 and (username in PRIVILEGED_USERS or privileged_attempts):
        return f"{ip}|credential_attack:privileged", "Combinação de brute force com tentativa contra usuário privilegiado"

    if len(failed_logins) >= 3:
        return f"{ip}|failed_login", "Múltiplas falhas de login do mesmo IP dentro da janela temporal"

    if username in PRIVILEGED_USERS:
        return f"{ip}|privileged_user:{username}", f"Tentativa contra usuário privilegiado {username}"

    if len(same_service) >= 3:
        return f"{ip}|service:{service}", f"Mesmo IP com múltiplos eventos no serviço {service} dentro da janela temporal"

    if len(same_port) >= 3:
        return f"{ip}|port:{port}", f"Mesmo IP com múltiplos eventos na porta {port} dentro da janela temporal"

    if len(same_type) >= 3:
        return f"{ip}|event_type:{event_type}", f"Mesmo IP repetindo o tipo de evento {event_type} dentro da janela temporal"

    return f"{ip}|event:{event_type}", "Correlação primária por IP e tipo de evento dentro da janela temporal"


def base_status_and_score(event_type):
    event = event_type.replace("-", "_").replace(" ", "_")

    if "BRUTE" in event or event in {"SSH_FAILED", "LOGIN_FAILED", "AUTH_FAILED", "FAILED_LOGIN"}:
        return "BRUTE FORCE", 42

    if "PORT_SCAN" in event or event == "SCAN":
        return "PORT SCAN", 28

    if event in {"SUSPICIOUS", "SUSPICIOUS_LOGIN", "ATIVIDADE_SUSPEITA", "LOGIN_SUSPEITO"}:
        return "ATIVIDADE SUSPEITA", 34

    if event in {"NORMAL", "HTTP_REQUEST", "HEALTHCHECK", "DNS_QUERY"}:
        return "TRÁFEGO NORMAL", 8

    return "TRÁFEGO NORMAL", 12


def severity_from_score(score):
    score = int(score or 0)
    if score >= 90:
        return "CRITICAL"
    if score >= 70:
        return "HIGH"
    if score >= 50:
        return "MEDIUM"
    return "LOW"


def calculate_threat_score(log, events, threat_match=None):
    event_type = normalize_event_type(log)
    username = normalize_username(log.get("username") or log.get("user"))
    recent_events = list(events)
    failed_count = sum(1 for item in recent_events if is_failed_login(item.get("event_type")) or is_brute_force(item.get("event_type")))
    same_type_count = sum(1 for item in recent_events if event_type_matches(item.get("event_type", ""), event_type))
    reasons = []
    score = 0

    if is_failed_login(event_type):
        score += SCORE_WEIGHTS["failed_login"]
        reasons.append("failed_login:+10")

    if username in PRIVILEGED_USERS:
        score += SCORE_WEIGHTS["admin_user_attempt"]
        reasons.append("admin_user_attempt:+25")

    if is_brute_force(event_type) or failed_count >= 4:
        score += SCORE_WEIGHTS["brute_force_pattern"]
        reasons.append("brute_force_pattern:+40")

    if threat_match or is_suspicious_event(event_type):
        score += SCORE_WEIGHTS["suspicious_ip"]
        reasons.append("suspicious_ip:+20")

    if len(recent_events) >= 4 or same_type_count >= 3:
        score += SCORE_WEIGHTS["repeated_events_short_window"]
        reasons.append("repeated_events_short_window:+30")

    progressive_score = min(30, max(0, len(recent_events) - 1) * 5)
    if progressive_score:
        score += progressive_score
        reasons.append(f"progressive_score:+{progressive_score}")

    score = max(0, min(100, score))
    return {
        "source_ip": normalize_source_ip(log),
        "threat_score": score,
        "severity": severity_from_score(score),
        "reasons": unique_preserve_order(reasons),
        "last_seen": epoch_to_iso(time.time()),
        "event_count": len(recent_events),
    }


def has_multistage_sequence(events):
    saw_scan = False
    for item in events:
        event_type = item["event_type"].replace("-", "_").replace(" ", "_")
        if "PORT_SCAN" in event_type or event_type == "SCAN":
            saw_scan = True
        if saw_scan and ("BRUTE" in event_type or event_type in {"SSH_FAILED", "LOGIN_FAILED", "AUTH_FAILED"}):
            return True
    return False


def target_context(log, port=None, service=None):
    raw_service = service or str(log.get("service") or "unknown").lower()
    target_port = port if port is not None else normalize_port(log.get("target_port") or log.get("dst_port") or log.get("port"))
    criticality = str(log.get("asset_criticality") or ASSET_CRITICALITY_BY_SERVICE.get(raw_service, "medium")).lower()
    impact = {
        "critical": "Possivel impacto em componente critico do laboratorio SOC.",
        "high": "Possivel impacto em ativo sensivel ou servico administrativo.",
        "medium": "Impacto operacional moderado no ambiente local.",
        "low": "Impacto esperado baixo no ambiente local.",
    }.get(criticality, "Impacto operacional moderado no ambiente local.")
    return {
        "target_host": log.get("target_host") or log.get("host") or log.get("container") or "sentinela-local",
        "target_ip": log.get("target_ip") or log.get("destination_ip") or log.get("dst_ip") or "127.0.0.1",
        "target_user": log.get("target_user") or log.get("username") or log.get("user"),
        "target_service": raw_service,
        "target_port": target_port,
        "target_container": log.get("target_container") or log.get("container"),
        "target_application": log.get("target_application") or log.get("application") or "sentinela-lab",
        "environment": log.get("environment") or "local-demo",
        "asset_owner": log.get("asset_owner") or "SOC Lab",
        "asset_criticality": criticality,
        "business_impact": log.get("business_impact") or impact,
    }


def response_plan(score, threat_intel_match, simulated_block):
    if simulated_block or threat_intel_match or score >= 90:
        return {
            "recommended_action": "Recomendar bloqueio temporario da origem e abertura de ticket de investigacao",
            "action_reason": "Score elevado, IOC ou multiplas evidencias justificam contencao em ambiente real.",
            "response_playbook": "PB-SOC-003-contencao-ip-suspeito",
            "execution_mode": "simulation",
            "execution_status": "not_executed",
            "execution_notes": "Ambiente local de demonstracao; nenhuma acao real foi executada.",
        }
    if score >= 70:
        return {
            "recommended_action": "Investigar origem, validar autenticacao e preservar evidencias",
            "action_reason": "Severidade alta requer triagem e validacao por analista.",
            "response_playbook": "PB-SOC-002-investigacao-credenciais",
            "execution_mode": "simulation",
            "execution_status": "not_executed",
            "execution_notes": "Ambiente local de demonstracao; nenhuma acao real foi executada.",
        }
    return {
        "recommended_action": "Monitorar recorrencia e revisar logs do ativo afetado",
        "action_reason": "Evidencia sem confirmacao suficiente para contencao.",
        "response_playbook": "PB-SOC-001-triagem-alerta",
        "execution_mode": "simulation",
        "execution_status": "not_executed",
        "execution_notes": "Ambiente local de demonstracao; nenhuma acao real foi executada.",
    }


def alert_kind(score, event_count=1, source_ip_count=1):
    if source_ip_count > 1 and event_count >= 6:
        return "campaign"
    if event_count >= 3 or score >= 70:
        return "incident_candidate"
    return "alert"


def calculate_score_breakdown(log, events, threat_match, rules):
    event_type = normalize_event_type(log)
    port = normalize_port(log.get("port"))
    service = str(log.get("service") or "unknown").lower()
    status, base_score = base_status_and_score(event_type)
    recent_events = list(events)
    matched_rules = apply_yaml_rules(events, rules or [])
    target = target_context(log, port, service)
    sensitive_port_score = 8 if port in SENSITIVE_PORTS else 0
    event_volume_score = min(18, max(0, len(recent_events) - 1) * 3)
    time_window_score = 8 if len(recent_events) >= 4 else (4 if len(recent_events) >= 2 else 0)
    ioc_score = 22 if threat_match else 0
    asset_criticality_score = {"critical": 16, "high": 12, "medium": 6, "low": 2}.get(target["asset_criticality"], 6)
    mitre_correlation_score = 8 if matched_rules or event_type in {"BRUTE_FORCE", "FAILED_LOGIN", "PORT_SCAN", "IOC_MATCH"} else 0
    repeated_activity_score = 10 if len(recent_events) >= 5 else (5 if len(recent_events) >= 3 else 0)
    confidence_score = min(12, 4 + (4 if matched_rules else 0) + (4 if threat_match else 0))
    yaml_score = max([int(rule.get("score") or rule.get("risk") or rule.get("min_risk") or 0) for rule in matched_rules] or [0])
    final_score = min(
        100,
        base_score
        + sensitive_port_score
        + event_volume_score
        + time_window_score
        + ioc_score
        + asset_criticality_score
        + mitre_correlation_score
        + repeated_activity_score
        + confidence_score,
    )
    if yaml_score:
        final_score = max(final_score, min(88, yaml_score))
    if threat_match and len(recent_events) >= 4 and port in SENSITIVE_PORTS:
        final_score = max(final_score, 92)
    if has_multistage_sequence(recent_events) and len(recent_events) >= 4:
        final_score = max(final_score, 90)
    if not threat_match and not (has_multistage_sequence(recent_events) and len(recent_events) >= 6):
        final_score = min(final_score, 89)
    elif not threat_match:
        final_score = min(final_score, 94)
    elif threat_match and not (len(recent_events) >= 10 and target["asset_criticality"] == "critical"):
        final_score = min(final_score, 96)
    elif threat_match and len(recent_events) >= 10 and target["asset_criticality"] == "critical":
        final_score = min(final_score, 99)
    factors = []
    if sensitive_port_score:
        factors.append(f"porta sensivel {port}")
    if event_volume_score:
        factors.append(f"{len(recent_events)} eventos na janela")
    if ioc_score:
        factors.append("IOC associado")
    if asset_criticality_score >= 12:
        factors.append(f"ativo de criticidade {target['asset_criticality']}")
    if matched_rules:
        factors.append("regra interna correlacionada")
    if repeated_activity_score:
        factors.append("atividade repetida da mesma origem")
    if not factors:
        factors.append("evidencia simples de baixo impacto")
    return {
        "status": status,
        "base_score": base_score,
        "sensitive_port_score": sensitive_port_score,
        "event_volume_score": event_volume_score,
        "time_window_score": time_window_score,
        "ioc_score": ioc_score,
        "asset_criticality_score": asset_criticality_score,
        "mitre_correlation_score": mitre_correlation_score,
        "repeated_activity_score": repeated_activity_score,
        "confidence_score": confidence_score,
        "final_score": final_score,
        "score_explanation": f"Score {final_score}: " + ", ".join(factors) + ".",
        "matched_rules": matched_rules,
        "target_context": target,
    }


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
    breakdown = calculate_score_breakdown(log, events, threat_match, rules)
    status = breakdown["status"]
    risk = int(breakdown["final_score"])
    reasons = []
    matched_rules = breakdown["matched_rules"]
    score_data = calculate_threat_score(log, events, threat_match)

    if port in SENSITIVE_PORTS:
        reasons.append("porta_sensivel")

    frequency = len(events)
    if frequency >= HOSTILE_CAMPAIGN_THRESHOLD:
        reasons.append("frequencia_alta")
    elif frequency >= 4:
        reasons.append("frequencia_media")

    for rule in matched_rules:
        status = rule.get("status", status)
        reasons.append(f"regra_yaml:{rule.get('name', 'sem_nome')}")
        for tag in rule.get("tags", []):
            reasons.append(f"tag:{tag}")

    if threat_match:
        status = "IOC DETECTADO" if status not in {"ATAQUE MULTIETAPA", "CAMPANHA HOSTIL"} else status
        reasons.append("threat_intel")

    if score_data["severity"] in {"HIGH", "CRITICAL"} and status == "TRÁFEGO NORMAL":
        status = "ATIVIDADE SUSPEITA"

    if status == "TRÁFEGO NORMAL" and score_data["threat_score"] < 30:
        risk = min(risk, 34)

    reasons.extend(score_data["reasons"])

    return status, max(0, min(100, risk)), unique_preserve_order(reasons)


def human_summary_for_alert(alert):
    ip = alert.get("source_ip") or alert.get("ip") or "IP desconhecido"
    event_type = alert.get("event_type") or "evento desconhecido"
    score = alert.get("threat_score") or alert.get("score_final") or alert.get("risco") or 0
    severity = alert.get("severity") or severity_from_score(score)
    mitre = alert.get("mitre_id")
    service = alert.get("service") or "serviço não identificado"
    port = alert.get("port")
    replay = " O evento faz parte de um replay simulado." if alert.get("is_replay_event") or alert.get("replay_id") else ""
    block = " O SENTINELA registrou apenas bloqueio simulado, sem ação real de firewall." if alert.get("simulated_block") else " A ação atual é monitoramento/investigação simulada."
    reason = alert.get("correlation_reason") or "correlação por IP e janela temporal"
    mitre_text = f" Técnica MITRE {mitre} ({alert.get('mitre_name')})." if mitre else ""
    port_text = f" na porta {port}/{service}" if port is not None else f" no serviço {service}"
    target = alert.get("target_host") or alert.get("target_ip") or "alvo nao identificado"
    score_text = alert.get("score_explanation") or f"Score {score}"
    return f"O IP {ip} gerou {event_type}{port_text} contra {target}. A correlação indicou {reason}. {score_text} Severidade {severity}.{mitre_text}{replay}{block}"


def simulated_auto_response(status, risk, threat_intel_match):
    should_block = risk >= 95 or status in CRITICAL_STATUSES or threat_intel_match

    if should_block and ENABLE_BLOCK:
        log_json("WARN", "ENABLE_BLOCK=true solicitado, mas bloqueio real permanece desativado por segurança")

    if should_block:
        return "simulated_block", True

    return "none", False


def build_alert(log, status, risk, events, risk_reasons, auto_response, simulated_block, threat, correlation_key, correlation_reason, rules=None):
    event_id = log.get("event_id") or str(uuid.uuid4())
    log["event_id"] = event_id

    threat_intel_match = threat is not None
    event_type = normalize_event_type(log)
    port = normalize_port(log.get("port"))
    service = str(log.get("service") or "unknown").lower()
    seen_at = parse_epoch(log.get("ts") or log.get("timestamp") or time.time())
    ts_value = epoch_to_iso(seen_at)

    score_data = calculate_threat_score(log, events, threat)
    score_breakdown = calculate_score_breakdown(log, events, threat, rules or [])
    risk = max(int(risk or 0), int(score_breakdown["final_score"]))
    correlation_reasons = unique_preserve_order([correlation_reason, *risk_reasons, *score_data["reasons"]])
    source_ip = normalize_source_ip(log)
    base_alert = {
        "event_id": event_id,
        "ip": source_ip,
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
    mitre = mitre_for_event(event_type, status=status, threat_match=threat_intel_match, simulated_block=simulated_block, rules=rules)
    matched_rule = (score_breakdown.get("matched_rules") or [None])[0] or {}
    target = score_breakdown["target_context"]
    response = response_plan(risk, threat_intel_match, simulated_block)

    alert = {
        "event_id": aggregate_state["event_id"],
        "ts": ts_value,
        "ip": source_ip,
        "source_ip": source_ip,
        "status": status,
        "risco": max(risk, aggregate_state["max_risk"]),
        "score_final": max(risk, aggregate_state["max_risk"]),
        "threat_score": score_data["threat_score"],
        "severity": severity_from_score(max(risk, aggregate_state["max_risk"])),
        **mitre,
        "mitre_techniques": ([{"id": mitre["mitre_id"], "name": mitre["mitre_name"], "tactic": mitre["mitre_tactic"]}] if mitre.get("mitre_id") else []),
        "internal_rule_id": matched_rule.get("id") or matched_rule.get("name") or f"SENTINELA-{event_type}",
        "internal_rule_name": matched_rule.get("description") or matched_rule.get("name") or f"Deteccao {event_type}",
        "correlation_rule": correlation_key,
        "detection_source": "rule_engine",
        "alert_type": alert_kind(risk, event_count=len(events)),
        "score_breakdown": {key: value for key, value in score_breakdown.items() if key not in {"matched_rules", "target_context", "status"}},
        "score_explanation": score_breakdown["score_explanation"],
        **target,
        **response,
        "reasons": score_data["reasons"],
        "correlation_reasons": correlation_reasons,
        "service": service,
        "port": port,
        "event_type": event_type,
        "ip_event_count": len(events),
        "event_count": len(events),
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
        "is_replay_event": bool(log.get("is_replay_event")),
        "replay_id": log.get("replay_id"),
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
    alert["human_summary"] = human_summary_for_alert(alert)
    alert["explanation"] = alert["human_summary"]
    return alert


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

    ip = normalize_source_ip(log)
    if not ip:
        log_json("WARN", "Evento descartado sem IP", event_id=log["event_id"], raw_event=log)
        return
    log["ip"] = ip

    events = update_state(log)
    threat = enrich_threat_intel(ip)
    status, risk, risk_reasons = calculate_risk(log, events, threat, rules)
    correlation_key, correlation_reason = build_correlation(events, log)
    auto_response, simulated_block = simulated_auto_response(status, risk, threat is not None)
    alert = build_alert(log, status, risk, events, risk_reasons, auto_response, simulated_block, threat, correlation_key, correlation_reason, rules)

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
