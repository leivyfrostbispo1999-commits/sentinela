import json
import os
import sys
import time
import uuid
from datetime import datetime, timezone
from urllib.parse import urlencode
from urllib.request import Request, urlopen

import psycopg2
from kafka import KafkaConsumer


KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
ALERTS_TOPIC = os.getenv("ALERTS_TOPIC", "security_alerts")
DB_CONFIG = {
    "host": os.getenv("DB_HOST", "db"),
    "port": int(os.getenv("DB_PORT", "5432")),
    "dbname": os.getenv("DB_NAME", "postgres"),
    "user": os.getenv("DB_USER", "postgres"),
    "password": os.getenv("DB_PASSWORD", "root"),
}
MAX_BACKOFF_SECONDS = float(os.getenv("MAX_BACKOFF_SECONDS", "15"))
ENABLE_NOTIFICATIONS = os.getenv("ENABLE_NOTIFICATIONS", "false").lower() == "true"
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL", "")
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")
SENTINELA_VERSION = "SENTINELA SOC 6.0"
INCIDENT_WINDOW_SECONDS = int(os.getenv("INCIDENT_WINDOW_SECONDS", "600"))
SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def log_json(level, message, **fields):
    payload = {
        "ts": now_iso(),
        "level": level,
        "component": "alert_sink",
        "message": message,
        **fields,
    }
    print(json.dumps(payload, ensure_ascii=False), flush=True)


def backoff_delay(attempt):
    return min(MAX_BACKOFF_SECONDS, 1.5 * (2 ** min(attempt, 4)))


def connect_postgres():
    attempt = 0
    while True:
        try:
            conn = psycopg2.connect(**DB_CONFIG)
            conn.autocommit = False
            log_json("INFO", "Postgres conectado", host=DB_CONFIG["host"], port=DB_CONFIG["port"])
            return conn
        except Exception as exc:
            delay = backoff_delay(attempt)
            log_json("WARN", "Aguardando Postgres", error=str(exc), retry_in_seconds=delay)
            time.sleep(delay)
            attempt += 1


def ensure_schema(conn):
    with conn.cursor() as cur:
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS alertas (
                id SERIAL PRIMARY KEY,
                event_id UUID UNIQUE,
                ip TEXT,
                status TEXT,
                risco INTEGER,
                score_final INTEGER,
                source_ip TEXT,
                threat_score INTEGER DEFAULT 0,
                severity TEXT DEFAULT 'LOW',
                mitre_id TEXT,
                mitre_name TEXT,
                mitre_tactic TEXT,
                human_summary TEXT,
                explanation TEXT,
                reasons JSONB,
                correlation_reasons JSONB,
                event_count INTEGER DEFAULT 0,
                replay_id TEXT,
                is_replay_event BOOLEAN DEFAULT FALSE,
                ts TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                "timestamp" TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                service TEXT,
                port INTEGER,
                event_type TEXT,
                ip_event_count INTEGER DEFAULT 0,
                risk_reasons JSONB,
                threat_intel_match BOOLEAN DEFAULT FALSE,
                threat_category TEXT,
                threat_description TEXT,
                threat_reputation_score INTEGER,
                threat_source TEXT,
                correlation_window_seconds INTEGER,
                correlation_key TEXT,
                correlation_reason TEXT,
                auto_response TEXT DEFAULT 'none',
                action_soc TEXT,
                simulated_block BOOLEAN DEFAULT FALSE,
                is_demo BOOLEAN DEFAULT FALSE,
                occurrence_count INTEGER DEFAULT 1,
                first_seen TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                aggregated BOOLEAN DEFAULT FALSE,
                ports JSONB,
                services JSONB,
                event_types JSONB,
                raw_event JSONB
            )
            """
        )
        cur.execute("ALTER TABLE alertas ADD COLUMN IF NOT EXISTS event_id UUID UNIQUE")
        cur.execute("ALTER TABLE alertas ADD COLUMN IF NOT EXISTS score_final INTEGER")
        cur.execute("ALTER TABLE alertas ADD COLUMN IF NOT EXISTS source_ip TEXT")
        cur.execute("ALTER TABLE alertas ADD COLUMN IF NOT EXISTS threat_score INTEGER DEFAULT 0")
        cur.execute("ALTER TABLE alertas ADD COLUMN IF NOT EXISTS severity TEXT DEFAULT 'LOW'")
        cur.execute("ALTER TABLE alertas ADD COLUMN IF NOT EXISTS mitre_id TEXT")
        cur.execute("ALTER TABLE alertas ADD COLUMN IF NOT EXISTS mitre_name TEXT")
        cur.execute("ALTER TABLE alertas ADD COLUMN IF NOT EXISTS mitre_tactic TEXT")
        cur.execute("ALTER TABLE alertas ADD COLUMN IF NOT EXISTS human_summary TEXT")
        cur.execute("ALTER TABLE alertas ADD COLUMN IF NOT EXISTS explanation TEXT")
        cur.execute("ALTER TABLE alertas ADD COLUMN IF NOT EXISTS reasons JSONB")
        cur.execute("ALTER TABLE alertas ADD COLUMN IF NOT EXISTS correlation_reasons JSONB")
        cur.execute("ALTER TABLE alertas ADD COLUMN IF NOT EXISTS event_count INTEGER DEFAULT 0")
        cur.execute("ALTER TABLE alertas ADD COLUMN IF NOT EXISTS replay_id TEXT")
        cur.execute("ALTER TABLE alertas ADD COLUMN IF NOT EXISTS is_replay_event BOOLEAN DEFAULT FALSE")
        cur.execute("ALTER TABLE alertas ADD COLUMN IF NOT EXISTS service TEXT")
        cur.execute("ALTER TABLE alertas ADD COLUMN IF NOT EXISTS port INTEGER")
        cur.execute("ALTER TABLE alertas ADD COLUMN IF NOT EXISTS event_type TEXT")
        cur.execute("ALTER TABLE alertas ADD COLUMN IF NOT EXISTS ip_event_count INTEGER DEFAULT 0")
        cur.execute("ALTER TABLE alertas ADD COLUMN IF NOT EXISTS risk_reasons JSONB")
        cur.execute("ALTER TABLE alertas ADD COLUMN IF NOT EXISTS threat_intel_match BOOLEAN DEFAULT FALSE")
        cur.execute("ALTER TABLE alertas ADD COLUMN IF NOT EXISTS threat_category TEXT")
        cur.execute("ALTER TABLE alertas ADD COLUMN IF NOT EXISTS threat_description TEXT")
        cur.execute("ALTER TABLE alertas ADD COLUMN IF NOT EXISTS threat_reputation_score INTEGER")
        cur.execute("ALTER TABLE alertas ADD COLUMN IF NOT EXISTS threat_source TEXT")
        cur.execute("ALTER TABLE alertas ADD COLUMN IF NOT EXISTS correlation_window_seconds INTEGER")
        cur.execute("ALTER TABLE alertas ADD COLUMN IF NOT EXISTS correlation_key TEXT")
        cur.execute("ALTER TABLE alertas ADD COLUMN IF NOT EXISTS correlation_reason TEXT")
        cur.execute("ALTER TABLE alertas ADD COLUMN IF NOT EXISTS auto_response TEXT DEFAULT 'none'")
        cur.execute("ALTER TABLE alertas ADD COLUMN IF NOT EXISTS action_soc TEXT")
        cur.execute("ALTER TABLE alertas ADD COLUMN IF NOT EXISTS simulated_block BOOLEAN DEFAULT FALSE")
        cur.execute("ALTER TABLE alertas ADD COLUMN IF NOT EXISTS is_demo BOOLEAN DEFAULT FALSE")
        cur.execute("ALTER TABLE alertas ADD COLUMN IF NOT EXISTS occurrence_count INTEGER DEFAULT 1")
        cur.execute("ALTER TABLE alertas ADD COLUMN IF NOT EXISTS first_seen TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP")
        cur.execute("ALTER TABLE alertas ADD COLUMN IF NOT EXISTS last_seen TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP")
        cur.execute("ALTER TABLE alertas ADD COLUMN IF NOT EXISTS aggregated BOOLEAN DEFAULT FALSE")
        cur.execute("ALTER TABLE alertas ADD COLUMN IF NOT EXISTS ports JSONB")
        cur.execute("ALTER TABLE alertas ADD COLUMN IF NOT EXISTS services JSONB")
        cur.execute("ALTER TABLE alertas ADD COLUMN IF NOT EXISTS event_types JSONB")
        cur.execute("ALTER TABLE alertas ADD COLUMN IF NOT EXISTS raw_event JSONB")
        cur.execute("ALTER TABLE alertas ADD COLUMN IF NOT EXISTS mitre_techniques JSONB DEFAULT '[]'::jsonb")
        cur.execute("ALTER TABLE alertas ADD COLUMN IF NOT EXISTS internal_rule_id TEXT")
        cur.execute("ALTER TABLE alertas ADD COLUMN IF NOT EXISTS internal_rule_name TEXT")
        cur.execute("ALTER TABLE alertas ADD COLUMN IF NOT EXISTS correlation_rule TEXT")
        cur.execute("ALTER TABLE alertas ADD COLUMN IF NOT EXISTS response_playbook TEXT")
        cur.execute("ALTER TABLE alertas ADD COLUMN IF NOT EXISTS detection_source TEXT")
        cur.execute("ALTER TABLE alertas ADD COLUMN IF NOT EXISTS alert_type TEXT DEFAULT 'alert'")
        cur.execute("ALTER TABLE alertas ADD COLUMN IF NOT EXISTS score_breakdown JSONB")
        cur.execute("ALTER TABLE alertas ADD COLUMN IF NOT EXISTS score_explanation TEXT")
        cur.execute("ALTER TABLE alertas ADD COLUMN IF NOT EXISTS target_host TEXT")
        cur.execute("ALTER TABLE alertas ADD COLUMN IF NOT EXISTS target_ip TEXT")
        cur.execute("ALTER TABLE alertas ADD COLUMN IF NOT EXISTS target_user TEXT")
        cur.execute("ALTER TABLE alertas ADD COLUMN IF NOT EXISTS target_service TEXT")
        cur.execute("ALTER TABLE alertas ADD COLUMN IF NOT EXISTS target_port INTEGER")
        cur.execute("ALTER TABLE alertas ADD COLUMN IF NOT EXISTS target_container TEXT")
        cur.execute("ALTER TABLE alertas ADD COLUMN IF NOT EXISTS target_application TEXT")
        cur.execute("ALTER TABLE alertas ADD COLUMN IF NOT EXISTS environment TEXT")
        cur.execute("ALTER TABLE alertas ADD COLUMN IF NOT EXISTS asset_owner TEXT")
        cur.execute("ALTER TABLE alertas ADD COLUMN IF NOT EXISTS asset_criticality TEXT")
        cur.execute("ALTER TABLE alertas ADD COLUMN IF NOT EXISTS business_impact TEXT")
        cur.execute("ALTER TABLE alertas ADD COLUMN IF NOT EXISTS recommended_action TEXT")
        cur.execute("ALTER TABLE alertas ADD COLUMN IF NOT EXISTS action_reason TEXT")
        cur.execute("ALTER TABLE alertas ADD COLUMN IF NOT EXISTS execution_mode TEXT DEFAULT 'simulation'")
        cur.execute("ALTER TABLE alertas ADD COLUMN IF NOT EXISTS execution_status TEXT DEFAULT 'not_executed'")
        cur.execute("ALTER TABLE alertas ADD COLUMN IF NOT EXISTS execution_notes TEXT")
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS blacklist (
                ip TEXT PRIMARY KEY,
                reason TEXT NOT NULL,
                first_seen TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                offense_count INTEGER DEFAULT 1,
                active BOOLEAN DEFAULT TRUE,
                response_mode TEXT DEFAULT 'simulated_block'
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS incidents (
                id SERIAL PRIMARY KEY,
                incident_id TEXT UNIQUE NOT NULL,
                title TEXT,
                description TEXT,
                status TEXT DEFAULT 'NEW',
                severity TEXT DEFAULT 'LOW',
                max_score INTEGER DEFAULT 0,
                primary_source_ip TEXT,
                source_ips JSONB DEFAULT '[]'::jsonb,
                destination_ip TEXT,
                usernames JSONB DEFAULT '[]'::jsonb,
                services JSONB DEFAULT '[]'::jsonb,
                event_types JSONB DEFAULT '[]'::jsonb,
                mitre_techniques JSONB DEFAULT '[]'::jsonb,
                correlation_reasons JSONB DEFAULT '[]'::jsonb,
                replay_ids JSONB DEFAULT '[]'::jsonb,
                first_seen TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                event_count INTEGER DEFAULT 0,
                human_summary TEXT,
                analyst_notes TEXT DEFAULT '',
                assigned_to TEXT DEFAULT '',
                soc_action TEXT DEFAULT 'investigação simulada',
                created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        cur.execute("ALTER TABLE incidents ADD COLUMN IF NOT EXISTS description TEXT")
        cur.execute("ALTER TABLE incidents ADD COLUMN IF NOT EXISTS primary_source_ip TEXT")
        cur.execute("ALTER TABLE incidents ADD COLUMN IF NOT EXISTS source_ips JSONB DEFAULT '[]'::jsonb")
        cur.execute("ALTER TABLE incidents ADD COLUMN IF NOT EXISTS destination_ip TEXT")
        cur.execute("ALTER TABLE incidents ADD COLUMN IF NOT EXISTS usernames JSONB DEFAULT '[]'::jsonb")
        cur.execute("ALTER TABLE incidents ADD COLUMN IF NOT EXISTS services JSONB DEFAULT '[]'::jsonb")
        cur.execute("ALTER TABLE incidents ADD COLUMN IF NOT EXISTS event_types JSONB DEFAULT '[]'::jsonb")
        cur.execute("ALTER TABLE incidents ADD COLUMN IF NOT EXISTS mitre_techniques JSONB DEFAULT '[]'::jsonb")
        cur.execute("ALTER TABLE incidents ADD COLUMN IF NOT EXISTS correlation_reasons JSONB DEFAULT '[]'::jsonb")
        cur.execute("ALTER TABLE incidents ADD COLUMN IF NOT EXISTS replay_ids JSONB DEFAULT '[]'::jsonb")
        cur.execute("ALTER TABLE incidents ADD COLUMN IF NOT EXISTS analyst_notes TEXT DEFAULT ''")
        cur.execute("ALTER TABLE incidents ADD COLUMN IF NOT EXISTS assigned_to TEXT DEFAULT ''")
        cur.execute("ALTER TABLE incidents ADD COLUMN IF NOT EXISTS soc_action TEXT DEFAULT 'investigação simulada'")
        cur.execute("ALTER TABLE incidents ADD COLUMN IF NOT EXISTS lifecycle_stage TEXT DEFAULT 'Detected'")
        cur.execute("ALTER TABLE incidents ADD COLUMN IF NOT EXISTS affected_assets JSONB DEFAULT '[]'::jsonb")
        cur.execute("ALTER TABLE incidents ADD COLUMN IF NOT EXISTS evidence JSONB DEFAULT '[]'::jsonb")
        cur.execute("ALTER TABLE incidents ADD COLUMN IF NOT EXISTS score_explanation TEXT")
        cur.execute("ALTER TABLE incidents ADD COLUMN IF NOT EXISTS response_playbook TEXT")
        cur.execute("ALTER TABLE incidents ADD COLUMN IF NOT EXISTS recommended_action TEXT")
        cur.execute("ALTER TABLE incidents ADD COLUMN IF NOT EXISTS execution_mode TEXT DEFAULT 'simulation'")
        cur.execute("ALTER TABLE incidents ADD COLUMN IF NOT EXISTS execution_status TEXT DEFAULT 'not_executed'")
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS incident_alerts (
                id SERIAL PRIMARY KEY,
                incident_id TEXT NOT NULL,
                alert_id TEXT NOT NULL,
                created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                UNIQUE (incident_id, alert_id)
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS incident_audit_log (
                id SERIAL PRIMARY KEY,
                incident_id TEXT NOT NULL,
                field_changed TEXT NOT NULL,
                old_value TEXT,
                new_value TEXT,
                changed_by TEXT DEFAULT 'system',
                changed_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        cur.execute("CREATE INDEX IF NOT EXISTS idx_incidents_last_seen ON incidents (last_seen DESC)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_incident_alerts_alert_id ON incident_alerts (alert_id)")
    conn.commit()


def create_consumer():
    attempt = 0
    while True:
        try:
            consumer = KafkaConsumer(
                ALERTS_TOPIC,
                bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
                group_id=os.getenv("ALERT_SINK_GROUP_ID", "alert-sink-v1"),
                auto_offset_reset=os.getenv("KAFKA_AUTO_OFFSET_RESET", "earliest"),
                enable_auto_commit=False,
                value_deserializer=lambda message: json.loads(message.decode("utf-8")),
            )
            log_json("INFO", "Kafka conectado", topic=ALERTS_TOPIC)
            return consumer
        except Exception as exc:
            delay = backoff_delay(attempt)
            log_json("WARN", "Aguardando Kafka", error=str(exc), retry_in_seconds=delay)
            time.sleep(delay)
            attempt += 1


def ensure_event_id(alert):
    event_id = alert.get("event_id") or str(uuid.uuid4())
    alert["event_id"] = event_id
    return event_id


def severity_from_score(score):
    score = int(score or 0)
    if score >= 90:
        return "CRITICAL"
    if score >= 70:
        return "HIGH"
    if score >= 50:
        return "MEDIUM"
    return "LOW"


def normalize_event_type(value):
    return str(value or "").replace("-", "_").replace(" ", "_").upper()


def as_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, list) else [value]
        except ValueError:
            return [value] if value else []
    return [value]


def merge_unique(*values):
    merged = []
    for value in values:
        for item in as_list(value):
            if item in (None, ""):
                continue
            if item not in merged:
                merged.append(item)
    return merged


def service_label(alert):
    service = alert.get("service")
    port = alert.get("port")
    if port is not None and service:
        return f"{port}/{service}"
    return service or (str(port) if port is not None else None)


def alert_score(alert):
    breakdown = alert.get("score_breakdown")
    if isinstance(breakdown, dict) and breakdown.get("final_score") is not None:
        return int(breakdown.get("final_score") or 0)
    return int(alert.get("score_final") or alert.get("risco") or alert.get("threat_score") or 0)


def incident_id_for(alert):
    source_ip = alert.get("source_ip") or alert.get("ip") or "unknown"
    seed = f"{source_ip}|{alert.get('replay_id') or 'live'}"
    return "INC-" + str(uuid.uuid5(uuid.NAMESPACE_URL, seed)).split("-")[0].upper()


def fetch_incident_columns(cur):
    return [desc[0] for desc in getattr(cur, "description", None) or []]


def row_to_dict(row, columns):
    return {column: row[index] for index, column in enumerate(columns)}


def candidate_incident(conn, alert):
    source_ip = alert.get("source_ip") or alert.get("ip")
    replay_id = alert.get("replay_id")
    username = alert.get("username") or (alert.get("raw_event") or {}).get("username") if isinstance(alert.get("raw_event"), dict) else alert.get("username")
    service = service_label(alert)
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT * FROM incidents
            WHERE last_seen >= NOW() - INTERVAL '24 hours'
            ORDER BY last_seen DESC
            LIMIT 100
            """
        )
        rows = cur.fetchall() or []
        columns = fetch_incident_columns(cur)
    best = None
    best_score = 0
    for row in rows:
        incident = row_to_dict(row, columns)
        reasons = []
        if replay_id and replay_id in as_list(incident.get("replay_ids")):
            reasons.append("same_replay_id")
        if source_ip and source_ip in as_list(incident.get("source_ips")):
            reasons.append("same_source_ip")
        if username and username in as_list(incident.get("usernames")):
            reasons.append("same_target_user")
        if service and service in as_list(incident.get("services")):
            reasons.append("same_destination_service")
        score = 8 * ("same_replay_id" in reasons) + 5 * ("same_source_ip" in reasons) + 4 * ("same_target_user" in reasons) + 3 * ("same_destination_service" in reasons)
        if source_ip and source_ip not in as_list(incident.get("source_ips")) and score >= 4:
            reasons.append("multi_ip_same_target")
            score += 4
        if score > best_score:
            best = {**incident, "derived_reasons": reasons}
            best_score = score
    return best if best_score >= 5 else None


def mitre_payload(alert):
    mitre_id = alert.get("mitre_id")
    if not mitre_id or str(mitre_id).startswith("SENTINELA-"):
        return None
    return {
        "id": mitre_id,
        "name": alert.get("mitre_name") or "Correlated Security Activity",
        "tactic": alert.get("mitre_tactic") or "Detection",
    }


def persist_incident_for_alert(conn, alert):
    source_ip = alert.get("source_ip") or alert.get("ip")
    score = alert_score(alert)
    event_type = normalize_event_type(alert.get("event_type"))
    if event_type == "FALSE_POSITIVE":
        score = min(score, 20)
    existing = candidate_incident(conn, alert)
    incident_id = existing.get("incident_id") if existing else incident_id_for(alert)
    source_ips = merge_unique(existing.get("source_ips") if existing else [], [source_ip])
    usernames = merge_unique(existing.get("usernames") if existing else [], [alert.get("username")])
    services = merge_unique(existing.get("services") if existing else [], [service_label(alert)])
    event_types = merge_unique(existing.get("event_types") if existing else [], [event_type])
    mitres = merge_unique(existing.get("mitre_techniques") if existing else [], [mitre_payload(alert)])
    reasons = merge_unique(existing.get("correlation_reasons") if existing else [], existing.get("derived_reasons") if existing else [], alert.get("correlation_reasons"), ["same_replay_id" if alert.get("replay_id") else "same_source_ip"])
    replay_ids = merge_unique(existing.get("replay_ids") if existing else [], [alert.get("replay_id")])
    max_score = max(int(existing.get("max_score") or 0) if existing else 0, score)
    severity = severity_from_score(max_score)
    title = f"Incidente {severity} - {'campanha multi-IP' if len(source_ips) > 1 else source_ip}"
    summary = f"O incidente correlaciona {len(source_ips)} IP(s), eventos {', '.join(event_types) or 'N/D'} e score máximo {max_score} ({severity}). Todas as respostas são simuladas."
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO incidents (
                incident_id, title, description, status, severity, max_score,
                primary_source_ip, source_ips, destination_ip, usernames, services,
                event_types, mitre_techniques, correlation_reasons, replay_ids,
                first_seen, last_seen, event_count, human_summary, soc_action, created_at, updated_at
            )
            VALUES (
                %(incident_id)s, %(title)s, %(description)s, %(status)s, %(severity)s, %(max_score)s,
                %(primary_source_ip)s, %(source_ips)s::jsonb, %(destination_ip)s, %(usernames)s::jsonb,
                %(services)s::jsonb, %(event_types)s::jsonb, %(mitre_techniques)s::jsonb,
                %(correlation_reasons)s::jsonb, %(replay_ids)s::jsonb,
                COALESCE(%(first_seen)s::timestamptz, NOW()), COALESCE(%(last_seen)s::timestamptz, NOW()),
                %(event_count)s, %(human_summary)s, %(soc_action)s, NOW(), NOW()
            )
            ON CONFLICT (incident_id) DO UPDATE SET
                title = EXCLUDED.title,
                description = EXCLUDED.description,
                severity = EXCLUDED.severity,
                max_score = EXCLUDED.max_score,
                source_ips = EXCLUDED.source_ips,
                destination_ip = COALESCE(incidents.destination_ip, EXCLUDED.destination_ip),
                usernames = EXCLUDED.usernames,
                services = EXCLUDED.services,
                event_types = EXCLUDED.event_types,
                mitre_techniques = EXCLUDED.mitre_techniques,
                correlation_reasons = EXCLUDED.correlation_reasons,
                replay_ids = EXCLUDED.replay_ids,
                last_seen = EXCLUDED.last_seen,
                event_count = incidents.event_count + 1,
                human_summary = EXCLUDED.human_summary,
                updated_at = NOW()
            """,
            {
                "incident_id": incident_id,
                "title": title,
                "description": summary,
                "status": "DETECTED",
                "severity": severity,
                "max_score": max_score,
                "primary_source_ip": existing.get("primary_source_ip") if existing else source_ip,
                "source_ips": json.dumps(source_ips, ensure_ascii=False),
                "destination_ip": alert.get("destination_ip") or (alert.get("raw_event") or {}).get("destination_ip") if isinstance(alert.get("raw_event"), dict) else alert.get("destination_ip"),
                "usernames": json.dumps(usernames, ensure_ascii=False),
                "services": json.dumps(services, ensure_ascii=False),
                "event_types": json.dumps(event_types, ensure_ascii=False),
                "mitre_techniques": json.dumps(mitres, ensure_ascii=False),
                "correlation_reasons": json.dumps(reasons, ensure_ascii=False),
                "replay_ids": json.dumps(replay_ids, ensure_ascii=False),
                "first_seen": alert.get("first_seen") or alert.get("ts"),
                "last_seen": alert.get("last_seen") or alert.get("ts"),
                "event_count": 1,
                "human_summary": summary,
                "soc_action": "bloqueio simulado apenas" if alert.get("simulated_block") else "investigação simulada",
            },
        )
        cur.execute(
            """
            INSERT INTO incident_alerts (incident_id, alert_id, created_at)
            VALUES (%s, %s, NOW())
            ON CONFLICT (incident_id, alert_id) DO NOTHING
            """,
            (incident_id, str(alert.get("event_id"))),
        )
    return incident_id


def notification_message(alert):
    return "\n".join([
        f"{SENTINELA_VERSION} - ALERTA CRÍTICO",
        f"Incidente: {alert.get('replay_id') or alert.get('event_id')}",
        f"IP: {alert.get('source_ip') or alert.get('ip')}",
        f"Severidade: {alert.get('severity') or alert.get('status')}",
        f"Score: {alert_score(alert)}",
        f"MITRE: {alert.get('mitre_id') or 'N/D'} {alert.get('mitre_name') or ''}".strip(),
        f"Ação: {alert.get('auto_response') or alert.get('action_soc') or 'bloqueio simulado apenas'}",
        "Ambiente: local/demo",
        "Nenhum bloqueio real foi executado.",
    ])


def send_notifications(alert):
    severity = str(alert.get("severity") or alert.get("status") or "").upper()
    score = alert_score(alert)
    if severity != "CRITICAL" and score < 90:
        return
    if not ENABLE_NOTIFICATIONS:
        log_json("INFO", "Notificações desligadas por configuração", event_id=alert.get("event_id"))
        return

    message = notification_message(alert)
    if DISCORD_WEBHOOK_URL:
        try:
            payload = json.dumps({"content": message}, ensure_ascii=False).encode("utf-8")
            req = Request(DISCORD_WEBHOOK_URL, data=payload, headers={"Content-Type": "application/json"}, method="POST")
            urlopen(req, timeout=3).read()
            log_json("INFO", "Notificação Discord enviada", event_id=alert.get("event_id"))
        except Exception as exc:
            log_json("WARN", "Falha ao enviar Discord; pipeline preservado", error=str(exc))
    if TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID:
        try:
            data = urlencode({"chat_id": TELEGRAM_CHAT_ID, "text": message}).encode("utf-8")
            url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
            urlopen(Request(url, data=data, method="POST"), timeout=3).read()
            log_json("INFO", "Notificação Telegram enviada", event_id=alert.get("event_id"))
        except Exception as exc:
            log_json("WARN", "Falha ao enviar Telegram; pipeline preservado", error=str(exc))
    if not DISCORD_WEBHOOK_URL and not (TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID):
        log_json("WARN", "ENABLE_NOTIFICATIONS=true sem credenciais configuradas", event_id=alert.get("event_id"))


def persist_alert(conn, alert):
    event_id = ensure_event_id(alert)
    ip = alert.get("ip")
    if not ip:
        log_json("WARN", "Alerta descartado sem IP", event_id=event_id)
        return

    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO alertas (
                event_id, ip, status, risco, score_final, ts, "timestamp",
                source_ip, threat_score, severity, mitre_id, mitre_name, mitre_tactic,
                human_summary, explanation, reasons, correlation_reasons,
                event_count, replay_id, is_replay_event,
                service, port, event_type, ip_event_count, risk_reasons,
                threat_intel_match, threat_category, threat_description,
                threat_reputation_score, threat_source, correlation_window_seconds,
                correlation_key, correlation_reason,
                auto_response, action_soc,
                simulated_block, is_demo,
                occurrence_count, first_seen, last_seen, aggregated,
                ports, services, event_types,
                raw_event,
                mitre_techniques, internal_rule_id, internal_rule_name,
                correlation_rule, response_playbook, detection_source, alert_type,
                score_breakdown, score_explanation, target_host, target_ip,
                target_user, target_service, target_port, target_container,
                target_application, environment, asset_owner, asset_criticality,
                business_impact, recommended_action, action_reason, execution_mode,
                execution_status, execution_notes
            )
            VALUES (
                %(event_id)s, %(ip)s, %(status)s, %(risco)s, %(score_final)s,
                COALESCE(%(ts)s::timestamptz, NOW()),
                COALESCE(%(ts)s::timestamptz, NOW()),
                %(source_ip)s, %(threat_score)s, %(severity)s,
                %(mitre_id)s, %(mitre_name)s, %(mitre_tactic)s,
                %(human_summary)s, %(explanation)s,
                %(reasons)s::jsonb, %(correlation_reasons)s::jsonb,
                %(event_count)s, %(replay_id)s, %(is_replay_event)s,
                %(service)s, %(port)s, %(event_type)s, %(ip_event_count)s,
                %(risk_reasons)s::jsonb, %(threat_intel_match)s,
                %(threat_category)s, %(threat_description)s,
                %(threat_reputation_score)s, %(threat_source)s,
                %(correlation_window_seconds)s, %(correlation_key)s,
                %(correlation_reason)s, %(auto_response)s, %(action_soc)s,
                %(simulated_block)s, %(is_demo)s,
                %(occurrence_count)s, %(first_seen)s, %(last_seen)s, %(aggregated)s,
                %(ports)s::jsonb, %(services)s::jsonb, %(event_types)s::jsonb,
                %(raw_event)s::jsonb,
                %(mitre_techniques)s::jsonb, %(internal_rule_id)s, %(internal_rule_name)s,
                %(correlation_rule)s, %(response_playbook)s, %(detection_source)s, %(alert_type)s,
                %(score_breakdown)s::jsonb, %(score_explanation)s, %(target_host)s, %(target_ip)s,
                %(target_user)s, %(target_service)s, %(target_port)s, %(target_container)s,
                %(target_application)s, %(environment)s, %(asset_owner)s, %(asset_criticality)s,
                %(business_impact)s, %(recommended_action)s, %(action_reason)s, %(execution_mode)s,
                %(execution_status)s, %(execution_notes)s
            )
            ON CONFLICT (event_id) DO UPDATE SET
                ip = EXCLUDED.ip,
                status = EXCLUDED.status,
                risco = EXCLUDED.risco,
                score_final = EXCLUDED.score_final,
                ts = EXCLUDED.ts,
                "timestamp" = EXCLUDED."timestamp",
                source_ip = EXCLUDED.source_ip,
                threat_score = EXCLUDED.threat_score,
                severity = EXCLUDED.severity,
                mitre_id = EXCLUDED.mitre_id,
                mitre_name = EXCLUDED.mitre_name,
                mitre_tactic = EXCLUDED.mitre_tactic,
                human_summary = EXCLUDED.human_summary,
                explanation = EXCLUDED.explanation,
                reasons = EXCLUDED.reasons,
                correlation_reasons = EXCLUDED.correlation_reasons,
                event_count = EXCLUDED.event_count,
                replay_id = EXCLUDED.replay_id,
                is_replay_event = EXCLUDED.is_replay_event,
                service = EXCLUDED.service,
                port = EXCLUDED.port,
                event_type = EXCLUDED.event_type,
                ip_event_count = EXCLUDED.ip_event_count,
                risk_reasons = EXCLUDED.risk_reasons,
                threat_intel_match = EXCLUDED.threat_intel_match,
                threat_category = EXCLUDED.threat_category,
                threat_description = EXCLUDED.threat_description,
                threat_reputation_score = EXCLUDED.threat_reputation_score,
                threat_source = EXCLUDED.threat_source,
                correlation_window_seconds = EXCLUDED.correlation_window_seconds,
                correlation_key = EXCLUDED.correlation_key,
                correlation_reason = EXCLUDED.correlation_reason,
                auto_response = EXCLUDED.auto_response,
                action_soc = EXCLUDED.action_soc,
                simulated_block = EXCLUDED.simulated_block,
                is_demo = EXCLUDED.is_demo,
                occurrence_count = EXCLUDED.occurrence_count,
                first_seen = EXCLUDED.first_seen,
                last_seen = EXCLUDED.last_seen,
                aggregated = EXCLUDED.aggregated,
                ports = EXCLUDED.ports,
                services = EXCLUDED.services,
                event_types = EXCLUDED.event_types,
                raw_event = EXCLUDED.raw_event,
                mitre_techniques = EXCLUDED.mitre_techniques,
                internal_rule_id = EXCLUDED.internal_rule_id,
                internal_rule_name = EXCLUDED.internal_rule_name,
                correlation_rule = EXCLUDED.correlation_rule,
                response_playbook = EXCLUDED.response_playbook,
                detection_source = EXCLUDED.detection_source,
                alert_type = EXCLUDED.alert_type,
                score_breakdown = EXCLUDED.score_breakdown,
                score_explanation = EXCLUDED.score_explanation,
                target_host = EXCLUDED.target_host,
                target_ip = EXCLUDED.target_ip,
                target_user = EXCLUDED.target_user,
                target_service = EXCLUDED.target_service,
                target_port = EXCLUDED.target_port,
                target_container = EXCLUDED.target_container,
                target_application = EXCLUDED.target_application,
                environment = EXCLUDED.environment,
                asset_owner = EXCLUDED.asset_owner,
                asset_criticality = EXCLUDED.asset_criticality,
                business_impact = EXCLUDED.business_impact,
                recommended_action = EXCLUDED.recommended_action,
                action_reason = EXCLUDED.action_reason,
                execution_mode = EXCLUDED.execution_mode,
                execution_status = EXCLUDED.execution_status,
                execution_notes = EXCLUDED.execution_notes
            """,
            {
                "event_id": event_id,
                "ip": ip,
                "status": alert.get("status", "DESCONHECIDO"),
                "risco": alert.get("risco", 0),
                "score_final": alert.get("score_final", alert.get("risco", 0)),
                "ts": alert.get("ts"),
                "source_ip": alert.get("source_ip") or ip,
                "threat_score": alert_score(alert),
                "severity": alert.get("severity", "LOW"),
                "mitre_id": alert.get("mitre_id"),
                "mitre_name": alert.get("mitre_name"),
                "mitre_tactic": alert.get("mitre_tactic"),
                "human_summary": alert.get("human_summary") or alert.get("explanation"),
                "explanation": alert.get("explanation") or alert.get("human_summary"),
                "reasons": json.dumps(alert.get("reasons", []), ensure_ascii=False),
                "correlation_reasons": json.dumps(alert.get("correlation_reasons", []), ensure_ascii=False),
                "event_count": int(alert.get("event_count", alert.get("ip_event_count", 0)) or 0),
                "replay_id": alert.get("replay_id"),
                "is_replay_event": bool(alert.get("is_replay_event", False)),
                "service": alert.get("service"),
                "port": alert.get("port"),
                "event_type": alert.get("event_type"),
                "ip_event_count": alert.get("ip_event_count", 0),
                "risk_reasons": json.dumps(alert.get("risk_reasons", []), ensure_ascii=False),
                "threat_intel_match": bool(alert.get("threat_intel_match", False)),
                "threat_category": alert.get("threat_category"),
                "threat_description": alert.get("threat_description"),
                "threat_reputation_score": alert.get("threat_reputation_score"),
                "threat_source": alert.get("threat_source"),
                "correlation_window_seconds": alert.get("correlation_window_seconds"),
                "correlation_key": alert.get("correlation_key"),
                "correlation_reason": alert.get("correlation_reason"),
                "auto_response": alert.get("auto_response", "none"),
                "action_soc": alert.get("action_soc"),
                "simulated_block": bool(alert.get("simulated_block", False)),
                "is_demo": bool(alert.get("is_demo", False)),
                "occurrence_count": int(alert.get("occurrence_count", 1)),
                "first_seen": alert.get("first_seen") or alert.get("ts"),
                "last_seen": alert.get("last_seen") or alert.get("ts"),
                "aggregated": bool(alert.get("aggregated", False)),
                "ports": json.dumps(alert.get("ports", []), ensure_ascii=False),
                "services": json.dumps(alert.get("services", []), ensure_ascii=False),
                "event_types": json.dumps(alert.get("event_types", []), ensure_ascii=False),
                "raw_event": json.dumps(alert.get("raw_event", alert), ensure_ascii=False),
                "mitre_techniques": json.dumps(alert.get("mitre_techniques", []), ensure_ascii=False),
                "internal_rule_id": alert.get("internal_rule_id"),
                "internal_rule_name": alert.get("internal_rule_name"),
                "correlation_rule": alert.get("correlation_rule") or alert.get("correlation_key"),
                "response_playbook": alert.get("response_playbook"),
                "detection_source": alert.get("detection_source", "rule_engine"),
                "alert_type": alert.get("alert_type", "alert"),
                "score_breakdown": json.dumps(alert.get("score_breakdown", {}), ensure_ascii=False),
                "score_explanation": alert.get("score_explanation"),
                "target_host": alert.get("target_host"),
                "target_ip": alert.get("target_ip"),
                "target_user": alert.get("target_user"),
                "target_service": alert.get("target_service"),
                "target_port": alert.get("target_port"),
                "target_container": alert.get("target_container"),
                "target_application": alert.get("target_application"),
                "environment": alert.get("environment"),
                "asset_owner": alert.get("asset_owner"),
                "asset_criticality": alert.get("asset_criticality"),
                "business_impact": alert.get("business_impact"),
                "recommended_action": alert.get("recommended_action"),
                "action_reason": alert.get("action_reason"),
                "execution_mode": alert.get("execution_mode", "simulation"),
                "execution_status": alert.get("execution_status", "not_executed"),
                "execution_notes": alert.get("execution_notes"),
            },
        )

        if alert.get("should_blacklist"):
            cur.execute(
                """
                INSERT INTO blacklist (ip, reason, offense_count, response_mode)
                VALUES (%s, %s, 1, %s)
                ON CONFLICT (ip) DO UPDATE SET
                    reason = EXCLUDED.reason,
                    last_seen = CURRENT_TIMESTAMP,
                    offense_count = blacklist.offense_count + 1,
                    active = TRUE,
                    response_mode = EXCLUDED.response_mode
                """,
                (ip, alert.get("status", "ATIVIDADE SUSPEITA"), alert.get("auto_response", "simulated_block")),
            )

    incident_id = persist_incident_for_alert(conn, alert)
    conn.commit()
    log_json("INFO", "Alerta gravado", event_id=event_id, ip=ip, status=alert.get("status"), incident_id=incident_id)
    send_notifications(alert)


def run():
    consumer = create_consumer()
    conn = connect_postgres()
    ensure_schema(conn)

    while True:
        try:
            for message in consumer:
                persist_alert(conn, message.value)
                consumer.commit()
        except psycopg2.Error as exc:
            log_json("ERROR", "Erro no Postgres; reconectando", error=str(exc))
            try:
                conn.close()
            except Exception:
                pass
            conn = connect_postgres()
            ensure_schema(conn)
        except Exception as exc:
            log_json("ERROR", "Erro no Alert Sink; reconectando", error=str(exc))
            time.sleep(backoff_delay(0))
            consumer = create_consumer()


if __name__ == "__main__":
    try:
        run()
    except KeyboardInterrupt:
        log_json("INFO", "Alert Sink encerrado")
        sys.exit(0)
