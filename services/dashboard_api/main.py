import base64
import hashlib
import hmac
import json
import os
import time
import uuid
from datetime import datetime, timezone
from functools import wraps

import psycopg2
from flask import Flask, jsonify, request
from flask_cors import CORS
from prometheus_client import CONTENT_TYPE_LATEST, CollectorRegistry, Counter, generate_latest


app = Flask(__name__)
CORS(app)

DB_CONFIG = {
    "host": os.getenv("DB_HOST", "db"),
    "port": int(os.getenv("DB_PORT", "5432")),
    "dbname": os.getenv("DB_NAME", "postgres"),
    "user": os.getenv("DB_USER", "postgres"),
    "password": os.getenv("DB_PASSWORD", "root"),
}

API_TOKEN = os.getenv("SENTINELA_API_TOKEN", "sentinela-demo-token")
JWT_SECRET = os.getenv("SENTINELA_JWT_SECRET", "sentinela-demo-jwt-secret")
JWT_TTL_SECONDS = int(os.getenv("SENTINELA_JWT_TTL_SECONDS", "3600"))
MAX_BACKOFF_SECONDS = float(os.getenv("MAX_BACKOFF_SECONDS", "10"))

REGISTRY = CollectorRegistry()
REQUEST_COUNTER = Counter(
    "sentinela_dashboard_requests_total",
    "Total de requests por endpoint",
    ["endpoint"],
    registry=REGISTRY,
)
DEMO_COUNTER = Counter("sentinela_demo_incidents_total", "Total de incidentes demo executados", registry=REGISTRY)


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def log_json(level, message, **fields):
    payload = {
        "ts": now_iso(),
        "level": level,
        "component": "dashboard_api",
        "message": message,
        **fields,
    }
    print(json.dumps(payload, ensure_ascii=False), flush=True)


def backoff_delay(attempt):
    return min(MAX_BACKOFF_SECONDS, 1.5 * (2 ** min(attempt, 4)))


def get_connection():
    conn = psycopg2.connect(**DB_CONFIG)
    if hasattr(conn, "autocommit"):
        conn.autocommit = False
    return conn


def bootstrap_database():
    attempt = 0
    while True:
        try:
            conn = get_connection()
            ensure_schema(conn)
            conn.close()
            log_json("INFO", "Banco inicializado", host=DB_CONFIG["host"], port=DB_CONFIG["port"])
            return
        except Exception as exc:
            delay = backoff_delay(attempt)
            log_json("WARN", "Aguardando banco", error=str(exc), retry_in_seconds=delay)
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
    conn.commit()


def _b64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data):
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode((data + padding).encode("ascii"))


def create_jwt(subject="sentinela-demo", ttl_seconds=None):
    ttl = JWT_TTL_SECONDS if ttl_seconds is None else int(ttl_seconds)
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": subject,
        "iat": int(time.time()),
        "exp": int(time.time()) + ttl,
    }
    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    signature = hmac.new(JWT_SECRET.encode("utf-8"), signing_input, hashlib.sha256).digest()
    return f"{header_b64}.{payload_b64}.{_b64url_encode(signature)}"


def verify_jwt(token):
    try:
        header_b64, payload_b64, signature_b64 = token.split(".")
        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
        expected = hmac.new(JWT_SECRET.encode("utf-8"), signing_input, hashlib.sha256).digest()
        if not hmac.compare_digest(expected, _b64url_decode(signature_b64)):
            return False
        payload = json.loads(_b64url_decode(payload_b64))
        return int(payload.get("exp", 0)) >= int(time.time())
    except Exception:
        return False


def token_is_valid():
    bearer = request.headers.get("Authorization", "")
    if bearer.startswith("Bearer "):
        return verify_jwt(bearer.split(" ", 1)[1].strip())
    legacy = request.headers.get("X-SENTINELA-TOKEN")
    return bool(legacy and hmac.compare_digest(legacy, API_TOKEN))


def require_auth(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not token_is_valid():
            return jsonify({"error": "unauthorized"}), 401
        return view(*args, **kwargs)

    return wrapped


def ensure_connection():
    conn = get_connection()
    ensure_schema(conn)
    return conn


def demo_mode_enabled():
    mode = (request.args.get("mode") or "").strip().lower()
    demo_flag = (request.args.get("demo") or "").strip().lower()
    return mode == "demo" or demo_flag in {"1", "true", "yes", "on"}


def range_to_interval(range_value):
    value = (range_value or "5m").strip().lower()
    if value.endswith("m") and value[:-1].isdigit():
        return f"{int(value[:-1])} minutes"
    if value.endswith("h") and value[:-1].isdigit():
        hours = int(value[:-1])
        return f"{hours} hour" if hours == 1 else f"{hours} hours"
    if value.endswith("d") and value[:-1].isdigit():
        days = int(value[:-1])
        return f"{days} day" if days == 1 else f"{days} days"
    return "5 minutes"


def row_to_dict(row, columns):
    data = {}
    for index, column in enumerate(columns):
        value = row[index]
        if isinstance(value, uuid.UUID):
            value = str(value)
        data[column] = value
    return data


def fetch_alerts(conn):
    mode = (request.args.get("mode") or "").strip().lower()
    demo_only = mode == "demo"
    range_value = request.args.get("range", "5m")
    interval = range_to_interval(range_value)

    with conn.cursor() as cur:
        if demo_only:
            cur.execute(
                """
                SELECT * FROM alertas
                WHERE is_demo = TRUE
                ORDER BY ts DESC
                LIMIT 100
                """
            )
        else:
            cur.execute(
                """
                SELECT * FROM alertas
                WHERE ts >= NOW() - %s::interval
                ORDER BY ts DESC
                LIMIT 100
                """,
                (interval,),
            )

        rows = cur.fetchall() or []
        columns = [desc[0] for desc in getattr(cur, "description", None) or []]

    alerts = [row_to_dict(row, columns) for row in rows]
    return jsonify({
        "demo": demo_only,
        "mode": "demo" if demo_only else "normal",
        "range": range_value,
        "count": len(alerts),
        "data": alerts,
    })


def build_demo_alerts():
    attacker_ip = "45.67.89.12"
    stages = [
        {"stage": "Evento recebido", "type": "PORT_SCAN", "description": "Recebido do coletor com atividade suspeita inicial"},
        {"stage": "IP suspeito identificado", "type": "PORT_SCAN", "description": "Origem associada a varredura repetitiva"},
        {"stage": "Padrão de brute force detectado", "type": "BRUTE_FORCE", "description": "Falhas repetidas em porta sensível"},
        {"stage": "Regra YAML acionada", "type": "CORRELATION", "description": "Condições correlacionadas dentro da janela temporal"},
        {"stage": "Threat intelligence match encontrado", "type": "IOC_MATCH", "description": "IP localizado na base local de threat intel"},
        {"stage": "Risco elevado para CRITICAL", "type": "ESCALATION", "description": "Pontuação crítica confirmada pela correlação"},
        {"stage": "simulated_block registrado", "type": "RESPONSE", "description": "Resposta SOC simulada registrada sem bloqueio real"},
    ]
    risks = [25, 40, 60, 70, 85, 92, 98]

    alerts = []
    for index, stage in enumerate(stages):
        risk = risks[index]
        severity = "LOW" if risk < 50 else "MEDIUM" if risk < 80 else "CRITICAL"
        current_ts = now_iso()
        alert = {
            "id": str(uuid.uuid4()),
            "event_id": str(uuid.uuid4()),
            "ip": attacker_ip,
            "status": severity,
            "risco": risk,
            "score_final": risk,
            "ts": current_ts,
            "timestamp": current_ts,
            "service": "ssh" if index < 4 else "security",
            "port": 22 if index < 4 else 0,
            "event_type": stage["type"],
            "ip_event_count": index + 1,
            "risk_reasons": [stage["description"]],
            "threat_intel_match": index >= 4,
            "threat_category": "MALWARE_C2" if index >= 4 else None,
            "threat_description": "IP presente na base local de inteligência" if index >= 4 else None,
            "threat_reputation_score": 95 if index >= 4 else 0,
            "threat_source": "local",
            "correlation_window_seconds": 300,
            "correlation_key": f"{attacker_ip}:ssh",
            "correlation_reason": "Mesmo IP com múltiplas fases dentro da janela temporal",
            "auto_response": "simulated_block" if index >= 4 else "monitoring",
            "action_soc": "BLOQUEIO SIMULADO" if index >= 4 else "MONITORADO",
            "simulated_block": index >= 4,
            "is_demo": True,
            "occurrence_count": 1,
            "first_seen": current_ts,
            "last_seen": current_ts,
            "aggregated": False,
            "ports": [22 if index < 4 else 0],
            "services": ["ssh" if index < 4 else "security"],
            "event_types": [stage["type"]],
            "raw_event": {
                "event_id": str(uuid.uuid4()),
                "ip": attacker_ip,
                "event_type": stage["type"],
                "port": 22 if index < 4 else 0,
                "service": "ssh" if index < 4 else "security",
                "timestamp": current_ts,
                "is_demo": True,
            },
            "stage": stage["stage"],
            "description": stage["description"],
            "severity": severity,
        }
        alerts.append(alert)
    return alerts


def persist_demo_alerts(conn, alerts):
    with conn.cursor() as cur:
        cur.execute("DELETE FROM alertas WHERE is_demo = true;")
    conn.commit()

    with conn.cursor() as cur:
        for alert in alerts:
            cur.execute(
                """
                INSERT INTO alertas (
                    event_id, ip, status, risco, score_final, ts, "timestamp",
                    service, port, event_type, ip_event_count, risk_reasons,
                    threat_intel_match, threat_category, threat_description,
                    threat_reputation_score, threat_source, correlation_window_seconds,
                    correlation_key, correlation_reason, auto_response, action_soc,
                    simulated_block, is_demo, occurrence_count, first_seen, last_seen,
                    aggregated, ports, services, event_types, raw_event
                )
                VALUES (
                    %(event_id)s, %(ip)s, %(status)s, %(risco)s, %(score_final)s,
                    %(ts)s, %(timestamp)s, %(service)s, %(port)s, %(event_type)s,
                    %(ip_event_count)s, %(risk_reasons)s::jsonb, %(threat_intel_match)s,
                    %(threat_category)s, %(threat_description)s,
                    %(threat_reputation_score)s, %(threat_source)s,
                    %(correlation_window_seconds)s, %(correlation_key)s,
                    %(correlation_reason)s, %(auto_response)s, %(action_soc)s,
                    %(simulated_block)s, %(is_demo)s, %(occurrence_count)s,
                    %(first_seen)s, %(last_seen)s, %(aggregated)s,
                    %(ports)s::jsonb, %(services)s::jsonb, %(event_types)s::jsonb,
                    %(raw_event)s::jsonb
                )
                ON CONFLICT (event_id) DO UPDATE SET
                    status = EXCLUDED.status,
                    risco = EXCLUDED.risco,
                    score_final = EXCLUDED.score_final,
                    ts = EXCLUDED.ts,
                    "timestamp" = EXCLUDED."timestamp",
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
                    raw_event = EXCLUDED.raw_event
                """,
                {
                    **alert,
                    "risk_reasons": json.dumps(alert.get("risk_reasons", []), ensure_ascii=False),
                    "ports": json.dumps(alert.get("ports", []), ensure_ascii=False),
                    "services": json.dumps(alert.get("services", []), ensure_ascii=False),
                    "event_types": json.dumps(alert.get("event_types", []), ensure_ascii=False),
                    "raw_event": json.dumps(alert.get("raw_event", {}), ensure_ascii=False),
                },
            )
    conn.commit()


def summarize_incident(alerts):
    first = alerts[0] if alerts else {}
    attacker = first.get("ip", "--")
    return f"Controlled demo attack detected from {attacker}. Correlation rules elevated the incident to CRITICAL and registered simulated_block without real blocking."


@app.get("/health")
def health():
    try:
        conn = ensure_connection()
        with conn.cursor() as cur:
            cur.execute("SELECT 1")
            cur.fetchone()
        conn.close()
        return jsonify({"status": "ok"})
    except Exception as exc:
        return jsonify({"status": "error", "error": str(exc)}), 503


@app.get("/metrics")
@require_auth
def metrics():
    REQUEST_COUNTER.labels(endpoint="metrics").inc()
    return app.response_class(generate_latest(REGISTRY), mimetype=CONTENT_TYPE_LATEST)


@app.get("/alertas")
@require_auth
def alertas():
    REQUEST_COUNTER.labels(endpoint="alertas").inc()
    conn = ensure_connection()
    try:
        response = fetch_alerts(conn)
        return response
    finally:
        conn.close()


@app.post("/demo/simulate-attack")
@require_auth
def simulate_attack():
    REQUEST_COUNTER.labels(endpoint="demo_simulate_attack").inc()
    DEMO_COUNTER.inc()
    conn = ensure_connection()
    try:
        alerts = build_demo_alerts()
        persist_demo_alerts(conn, alerts)
        payload_alerts = []
        timeline = []
        primary = {
            "ip": alerts[0]["ip"],
            "initial_vector": alerts[0]["event_type"],
            "max_severity": "CRITICAL",
            "soc_action": "simulated_block only",
        }

        for index, alert in enumerate(alerts):
            item = {
                "id": alert["id"],
                "ip": alert["ip"],
                "event_type": alert["event_type"],
                "port": alert["port"],
                "service": alert["service"],
                "risk": alert["risco"],
                "risco": alert["risco"],
                "status": alert["status"],
                "severity": alert["severity"],
                "timestamp": alert["timestamp"],
                "ts": alert["ts"],
                "description": alert["description"],
                "stage": alert["stage"],
                "simulated_block": alert["simulated_block"],
                "threat_intel_match": alert["threat_intel_match"],
                "threat_category": alert["threat_category"],
                "threat_description": alert["threat_description"],
                "threat_source": alert["threat_source"],
                "occurrence_count": alert["occurrence_count"],
                "first_seen": alert["first_seen"],
                "last_seen": alert["last_seen"],
                "aggregated": alert["aggregated"],
                "ports": alert["ports"],
                "services": alert["services"],
                "event_types": alert["event_types"],
                "action_soc": alert["action_soc"],
                "is_demo": True,
            }
            payload_alerts.append(item)
            timeline.append(
                {
                    "timestamp": item["timestamp"],
                    "ip": item["ip"],
                    "event_type": item["event_type"],
                    "severity": item["severity"],
                    "description": item["description"],
                    "stage": item["stage"],
                    "simulated_block": item["simulated_block"],
                }
            )

        response = {
            "events_created": len(payload_alerts),
            "simulated_block": True,
            "real_blocking": False,
            "primary_attacker": primary,
            "incident_summary": summarize_incident(payload_alerts),
            "timeline": timeline,
            "alerts": payload_alerts,
        }
        return jsonify(response), 201
    finally:
        conn.close()


def main():
    bootstrap_database()
    app.run(host="0.0.0.0", port=5000)


if __name__ == "__main__":
    main()
