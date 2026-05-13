import base64
import hashlib
import hmac
import json
import os
import re
import time
import uuid
from collections import defaultdict, deque
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request as UrlRequest, urlopen

import psycopg2
from flask import Flask, Response, jsonify, has_request_context, request
from flask_cors import CORS
from prometheus_client import CONTENT_TYPE_LATEST, CollectorRegistry, Counter, Gauge, Histogram, PlatformCollector, ProcessCollector, generate_latest
from sentinela_secrets import resolve_secret

try:
    from flask_sock import Sock
except ImportError:
    Sock = None

try:
    import yaml
except ImportError:
    yaml = None

try:
    from opentelemetry import trace
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
    from opentelemetry.instrumentation.flask import FlaskInstrumentor
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor
except ImportError:
    trace = None
    OTLPSpanExporter = None
    FlaskInstrumentor = None
    Resource = None
    TracerProvider = None
    BatchSpanProcessor = None


app = Flask(__name__)
SENTINELA_ENV = os.getenv("SENTINELA_ENV", "development").strip().lower()
CORS_ORIGINS = os.getenv("CORS_ALLOWED_ORIGINS", os.getenv("CORS_ORIGINS", "*"))
CORS(app, resources={r"/*": {"origins": CORS_ORIGINS.split(",") if CORS_ORIGINS != "*" else "*"}})
sock = Sock(app) if Sock else None
SCHEMA_INITIALIZED = False

DB_CONFIG = {
    "host": os.getenv("DB_HOST", "db"),
    "port": int(os.getenv("DB_PORT", "5432")),
    "dbname": os.getenv("DB_NAME", "postgres"),
    "user": os.getenv("DB_USER", "postgres"),
    "password": os.getenv("DB_PASSWORD", "root"),
}

API_TOKEN = os.getenv("SENTINELA_API_TOKEN", "sentinela-demo-token")
JWT_SECRET = resolve_secret("SENTINELA_JWT_SECRET", default="sentinela-demo-jwt-secret", required=SENTINELA_ENV == "production")
JWT_TTL_SECONDS = int(os.getenv("SENTINELA_JWT_TTL_SECONDS", str(int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60")) * 60)))
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", str(max(1, JWT_TTL_SECONDS // 60))))
REFRESH_TOKEN_EXPIRE_MINUTES = int(os.getenv("REFRESH_TOKEN_EXPIRE_MINUTES", "10080"))
ENABLE_AUTH = os.getenv("ENABLE_AUTH", "false").lower() == "true"
ENABLE_TRACING = os.getenv("ENABLE_TRACING", "false").lower() == "true"
ENABLE_OPENSEARCH = os.getenv("ENABLE_OPENSEARCH", "false").lower() == "true"
OPENSEARCH_URL = os.getenv("OPENSEARCH_URL", "http://opensearch:9200").rstrip("/")
OPENSEARCH_INDEX_ALERTS = os.getenv("OPENSEARCH_INDEX_ALERTS", "sentinela-alerts")
SENTINELA_USER = os.getenv("SENTINELA_USER", "admin")
SENTINELA_PASSWORD = os.getenv("SENTINELA_PASSWORD", "sentinela")
DEFAULT_TENANT_ID = os.getenv("DEFAULT_TENANT_ID", "default")
VALID_ROLES = {"admin", "analyst", "viewer"}
MAX_BACKOFF_SECONDS = float(os.getenv("MAX_BACKOFF_SECONDS", "10"))
RATE_LIMIT_PER_MINUTE = int(os.getenv("RATE_LIMIT_PER_MINUTE", "240"))
ENABLE_RATE_LIMITING = os.getenv("ENABLE_RATE_LIMITING", "false").lower() == "true"
RATE_LIMIT_AUTH_PER_MINUTE = int(os.getenv("RATE_LIMIT_AUTH_PER_MINUTE", "20"))
RATE_LIMIT_API_PER_MINUTE = int(os.getenv("RATE_LIMIT_API_PER_MINUTE", "120"))
RULES_CANDIDATES = [
    Path(os.getenv("RULES_PATH", "sentinela_rules.yml")),
    Path("config/sentinela_rules.yml"),
    Path("infra/rules/sentinela_rules.yml"),
    Path("../rule_engine/sentinela_rules.yml"),
    Path("../rule_engine/rules.yaml"),
]
SENTINELA_VERSION = "SENTINELA 7.0"
INCIDENT_WINDOW_SECONDS = int(os.getenv("INCIDENT_WINDOW_SECONDS", "600"))
ALLOWED_INCIDENT_STATUSES = {"NEW", "DETECTED", "TRIAGED", "INVESTIGATING", "CONTAINED", "RESOLVED", "FALSE_POSITIVE", "CLOSED"}
OPEN_INCIDENT_STATUSES = {"NEW", "DETECTED", "TRIAGED", "INVESTIGATING", "CONTAINED"}
MITRE_MAPPINGS = {
    "PORT_SCAN": {"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery"},
    "SCAN": {"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery"},
    "BRUTE_FORCE": {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
    "FAILED_LOGIN": {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
    "SSH_FAILED": {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
    "LOGIN_FAILED": {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
    "AUTH_FAILED": {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
    "SUSPICIOUS": {"id": "T1087", "name": "Account Discovery", "tactic": "Discovery"},
    "IOC_MATCH": {"id": "T1071", "name": "Application Layer Protocol", "tactic": "Command and Control"},
    "ESCALATION": {"id": "T1068", "name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation"},
}
REAL_MITRE_ID_PATTERN = re.compile(r"^T\d{4}(?:\.\d{3})?$")
SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

REGISTRY = CollectorRegistry()
ProcessCollector(namespace="sentinela_dashboard_api", registry=REGISTRY)
PlatformCollector(registry=REGISTRY)
REQUEST_COUNTER = Counter(
    "sentinela_dashboard_requests_total",
    "Total de requests por endpoint",
    ["endpoint"],
    registry=REGISTRY,
)
HTTP_REQUEST_COUNTER = Counter(
    "sentinela_dashboard_http_requests_total",
    "Requests HTTP por endpoint, metodo e status",
    ["endpoint", "method", "status"],
    registry=REGISTRY,
)
REQUEST_LATENCY = Histogram(
    "sentinela_dashboard_request_seconds",
    "Tempo de resposta da API",
    ["endpoint", "method"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5),
    registry=REGISTRY,
)
HTTP_ERRORS = Counter("sentinela_dashboard_http_errors_total", "Erros HTTP por classe", ["status_class"], registry=REGISTRY)
RATE_LIMITED_REQUESTS = Counter("sentinela_rate_limited_requests_total", "Requests bloqueados por rate limiting", ["endpoint"], registry=REGISTRY)
DLQ_EVENTS_TOTAL = Counter("sentinela_dlq_events_total", "Eventos enviados para DLQ por servico", ["service"], registry=REGISTRY)
DEMO_COUNTER = Counter("sentinela_demo_incidents_total", "Total de incidentes demo executados", registry=REGISTRY)
ALERTS_GAUGE = Gauge("sentinela_alerts_stored_total", "Total de alertas persistidos", registry=REGISTRY)
INCIDENTS_GAUGE = Gauge("sentinela_incidents_stored_total", "Total de incidentes persistidos", registry=REGISTRY)
INCIDENTS_SEVERITY_GAUGE = Gauge("sentinela_incidents_by_severity", "Incidentes persistidos por severidade", ["severity"], registry=REGISTRY)
EVENTS_PER_MINUTE_GAUGE = Gauge("sentinela_events_processed_per_minute", "Eventos processados por minuto", registry=REGISTRY)
WEBSOCKET_CONNECTIONS = Gauge("sentinela_websocket_connections", "Conexoes WebSocket ativas", registry=REGISTRY)
PROCESSED_EVENTS_BY_TENANT = Gauge("sentinela_processed_events_by_tenant", "Eventos processados por tenant nas ultimas 24h", ["tenant_id"], registry=REGISTRY)
RATE_LIMIT_BUCKETS = defaultdict(deque)
RATE_LIMIT_ENDPOINTS = {
    ("POST", "/auth/token"): "auth",
    ("POST", "/auth/refresh"): "auth",
    ("POST", "/demo/simulate-attack"): "api",
    ("POST", "/demo"): "api",
    ("GET", "/search"): "api",
    ("GET", "/audit"): "api",
}


def setup_tracing():
    if not ENABLE_TRACING:
        return None
    if not all([trace, OTLPSpanExporter, FlaskInstrumentor, Resource, TracerProvider, BatchSpanProcessor]):
        print(json.dumps({"ts": datetime.now(timezone.utc).isoformat(), "level": "WARN", "component": "dashboard_api", "message": "OpenTelemetry indisponivel; tracing desativado"}, ensure_ascii=False), flush=True)
        return None
    resource = Resource.create({"service.name": os.getenv("OTEL_SERVICE_NAME", "sentinela-7-api")})
    provider = TracerProvider(resource=resource)
    provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://jaeger:4318/v1/traces"))))
    trace.set_tracer_provider(provider)
    FlaskInstrumentor().instrument_app(app)
    return trace.get_tracer("sentinela.dashboard_api")


TRACER = setup_tracing()


def set_trace_attrs(**attrs):
    if not trace:
        return
    try:
        span = trace.get_current_span()
        for key, value in attrs.items():
            if value is not None:
                span.set_attribute(key, str(value))
    except Exception:
        return


@app.errorhandler(Exception)
def handle_unexpected_error(exc):
    status = getattr(exc, "code", 500) or 500
    if status < 500:
        return jsonify({"error": getattr(exc, "name", "bad_request")}), status
    log_json("ERROR", "Erro interno tratado", error=str(exc), path=request.path if has_request_context() else None)
    payload = {"error": "internal_server_error"}
    if SENTINELA_ENV != "production":
        payload["detail"] = str(exc)
    return jsonify(payload), 500


def pbkdf2_hash(password, salt=None, iterations=200000):
    salt = salt or _b64url_encode(os.urandom(16))
    digest = hashlib.pbkdf2_hmac("sha256", str(password).encode("utf-8"), salt.encode("utf-8"), iterations)
    return f"pbkdf2_sha256${iterations}${salt}${_b64url_encode(digest)}"


def verify_password(password, stored):
    if not stored:
        return False
    if str(stored).startswith("pbkdf2_sha256$"):
        try:
            _, raw_iterations, salt, expected = str(stored).split("$", 3)
            candidate = pbkdf2_hash(password, salt=salt, iterations=int(raw_iterations)).rsplit("$", 1)[1]
            return hmac.compare_digest(candidate, expected)
        except Exception:
            return False
    return hmac.compare_digest(str(password or ""), str(stored))


def load_users():
    raw = os.getenv("SENTINELA_USERS_JSON", "").strip()
    if raw:
        try:
            users = json.loads(raw)
            if isinstance(users, dict):
                return {
                    username: {
                        "username": username,
                        "password_hash": item.get("password_hash") or item.get("password"),
                        "role": item.get("role", "viewer"),
                        "tenant_id": item.get("tenant_id", DEFAULT_TENANT_ID),
                    }
                    for username, item in users.items()
                    if isinstance(item, dict)
                }
            if isinstance(users, list):
                return {
                    item["username"]: {
                        "username": item["username"],
                        "password_hash": item.get("password_hash") or item.get("password"),
                        "role": item.get("role", "viewer"),
                        "tenant_id": item.get("tenant_id", DEFAULT_TENANT_ID),
                    }
                    for item in users
                    if isinstance(item, dict) and item.get("username")
                }
        except Exception as exc:
            print(json.dumps({"ts": datetime.now(timezone.utc).isoformat(), "level": "WARN", "component": "dashboard_api", "message": "SENTINELA_USERS_JSON invalido; usando usuarios padrao", "error": str(exc)}, ensure_ascii=False), flush=True)
    return {
        SENTINELA_USER: {"username": SENTINELA_USER, "password_hash": SENTINELA_PASSWORD, "role": "admin", "tenant_id": DEFAULT_TENANT_ID},
        "analyst": {"username": "analyst", "password_hash": os.getenv("SENTINELA_ANALYST_PASSWORD", "analyst"), "role": "analyst", "tenant_id": DEFAULT_TENANT_ID},
        "viewer": {"username": "viewer", "password_hash": os.getenv("SENTINELA_VIEWER_PASSWORD", "viewer"), "role": "viewer", "tenant_id": DEFAULT_TENANT_ID},
    }


USERS = load_users()


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def log_json(level, message, **fields):
    sensitive = {"password", "senha", "token", "authorization", "jwt", "secret", "api_key", "apikey", "key"}
    safe_fields = {}
    for key, value in fields.items():
        marker = str(key).lower()
        safe_fields[key] = "***redacted***" if any(item in marker for item in sensitive) else value
    payload = {
        "ts": now_iso(),
        "level": level,
        "component": "dashboard_api",
        "message": message,
        **safe_fields,
    }
    print(json.dumps(payload, ensure_ascii=False), flush=True)


def backoff_delay(attempt):
    return min(MAX_BACKOFF_SECONDS, 1.5 * (2 ** min(attempt, 4)))


@app.before_request
def begin_request_timer():
    request._sentinela_started_at = time.time()
    request._sentinela_correlation_id = request.headers.get("X-Correlation-ID") or request.args.get("correlation_id") or str(uuid.uuid4())
    set_trace_attrs(correlation_id=request._sentinela_correlation_id, route=request.path, tenant_id=request.headers.get("X-Tenant-ID"))
    if request.path in {"/health", "/ready", "/metrics", "/metrics/prometheus"}:
        return None
    if not ENABLE_RATE_LIMITING:
        return None
    bucket_type = RATE_LIMIT_ENDPOINTS.get((request.method, request.path))
    if not bucket_type:
        return None
    now = time.time()
    client = request.headers.get("X-Forwarded-For", request.remote_addr or "local").split(",")[0].strip()
    identity_hint = request.headers.get("Authorization", "")[:16] or request.headers.get("X-SENTINELA-TOKEN", "")[:16]
    bucket_key = f"{bucket_type}:{client}:{request.path}:{identity_hint}"
    limit = RATE_LIMIT_AUTH_PER_MINUTE if bucket_type == "auth" else RATE_LIMIT_API_PER_MINUTE
    bucket = RATE_LIMIT_BUCKETS[bucket_key]
    while bucket and now - bucket[0] > 60:
        bucket.popleft()
    if len(bucket) >= limit:
        RATE_LIMITED_REQUESTS.labels(endpoint=request.path).inc()
        try:
            write_audit(
                action="rate_limit_exceeded",
                resource_type="endpoint",
                resource_id=request.path,
                success=False,
                metadata={"limit_per_minute": limit, "method": request.method},
            )
        except Exception:
            pass
        return jsonify({"error": "rate_limited", "limit_per_minute": limit}), 429
    bucket.append(now)
    return None


@app.after_request
def record_request_metrics(response):
    endpoint = request.endpoint or request.path
    method = request.method
    status = str(response.status_code)
    HTTP_REQUEST_COUNTER.labels(endpoint=endpoint, method=method, status=status).inc()
    REQUEST_LATENCY.labels(endpoint=endpoint, method=method).observe(time.time() - getattr(request, "_sentinela_started_at", time.time()))
    if response.status_code >= 400:
        HTTP_ERRORS.labels(status_class=f"{response.status_code // 100}xx").inc()
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["X-Correlation-ID"] = getattr(request, "_sentinela_correlation_id", "")
    return response


def get_connection():
    conn = psycopg2.connect(**DB_CONFIG)
    if hasattr(conn, "autocommit"):
        conn.autocommit = False
    return conn


def bootstrap_database():
    global SCHEMA_INITIALIZED
    attempt = 0
    while True:
        try:
            conn = get_connection()
            ensure_schema(conn)
            conn.close()
            SCHEMA_INITIALIZED = True
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
        cur.execute("ALTER TABLE alertas ADD COLUMN IF NOT EXISTS tenant_id TEXT DEFAULT 'default'")
        cur.execute("ALTER TABLE alertas ADD COLUMN IF NOT EXISTS correlation_id TEXT")
        cur.execute("ALTER TABLE alertas ADD COLUMN IF NOT EXISTS idempotency_key TEXT")
        cur.execute("ALTER TABLE alertas ADD COLUMN IF NOT EXISTS campaign_id TEXT")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_alertas_campaign_id ON alertas (campaign_id)")
        
        # --- Tabelas SaaS Multi-tenant ---
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS plans (
                plan_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                max_eps INTEGER DEFAULT 10,
                max_alerts_per_day INTEGER DEFAULT 100,
                storage_retention_days INTEGER DEFAULT 7,
                price_monthly NUMERIC(10, 2) DEFAULT 0.00
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS tenants (
                tenant_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                plan_id TEXT DEFAULT 'free' REFERENCES plans(plan_id),
                api_key TEXT UNIQUE NOT NULL,
                status TEXT DEFAULT 'active',
                created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS billing_records (
                id SERIAL PRIMARY KEY,
                tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id),
                billing_period TEXT NOT NULL,
                event_count BIGINT DEFAULT 0,
                amount NUMERIC(10, 2) DEFAULT 0.00,
                status TEXT DEFAULT 'pending',
                created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        
        cur.execute(
            """
            INSERT INTO plans (plan_id, name, max_eps, max_alerts_per_day, storage_retention_days, price_monthly)
            VALUES 
                ('free', 'Plano Gratuito', 5, 50, 7, 0.00),
                ('pro', 'Plano Profissional', 100, 5000, 30, 499.00),
                ('enterprise', 'Plano Enterprise', 5000, 1000000, 365, 4999.00)
            ON CONFLICT (plan_id) DO NOTHING
            """
        )
        cur.execute(
            """
            INSERT INTO tenants (tenant_id, name, plan_id, api_key, status)
            VALUES ('default', 'Sentinela Demo Client', 'enterprise', 'sentinela-demo-api-key', 'active')
            ON CONFLICT (tenant_id) DO NOTHING
            """
        )

        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS response_actions (
                id SERIAL PRIMARY KEY,
                action_id UUID UNIQUE NOT NULL,
                alert_id UUID NOT NULL,
                tenant_id TEXT DEFAULT 'default',
                action_type TEXT NOT NULL,
                mode TEXT NOT NULL,
                target_entity TEXT,
                reason TEXT,
                status TEXT DEFAULT 'simulated',
                metadata_json JSONB DEFAULT '{}'::jsonb,
                created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        cur.execute("CREATE INDEX IF NOT EXISTS idx_response_actions_alert_id ON response_actions (alert_id)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_response_actions_tenant_id ON response_actions (tenant_id)")
        cur.execute("UPDATE alertas SET tenant_id = %s WHERE tenant_id IS NULL", (DEFAULT_TENANT_ID,))
        cur.execute("CREATE INDEX IF NOT EXISTS idx_alertas_tenant_ts ON alertas (tenant_id, ts DESC)")
        cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_alertas_idempotency_key ON alertas (idempotency_key) WHERE idempotency_key IS NOT NULL")
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
            CREATE TABLE IF NOT EXISTS incident_overrides (
                incident_id TEXT PRIMARY KEY,
                status TEXT DEFAULT 'NEW',
                analyst_notes TEXT DEFAULT '',
                assigned_to TEXT DEFAULT '',
                soc_action TEXT DEFAULT 'investigação simulada',
                created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        cur.execute("ALTER TABLE incident_overrides ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'NEW'")
        cur.execute("ALTER TABLE incident_overrides ADD COLUMN IF NOT EXISTS analyst_notes TEXT DEFAULT ''")
        cur.execute("ALTER TABLE incident_overrides ADD COLUMN IF NOT EXISTS assigned_to TEXT DEFAULT ''")
        cur.execute("ALTER TABLE incident_overrides ADD COLUMN IF NOT EXISTS soc_action TEXT DEFAULT 'investigação simulada'")
        cur.execute("ALTER TABLE incident_overrides ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP")
        cur.execute("ALTER TABLE incident_overrides ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP")
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
        cur.execute("ALTER TABLE incidents ADD COLUMN IF NOT EXISTS tenant_id TEXT DEFAULT 'default'")
        cur.execute("ALTER TABLE incidents ADD COLUMN IF NOT EXISTS idempotency_key TEXT")
        cur.execute("ALTER TABLE incidents ADD COLUMN IF NOT EXISTS campaign_id TEXT")
        cur.execute("UPDATE incidents SET tenant_id = %s WHERE tenant_id IS NULL", (DEFAULT_TENANT_ID,))
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
        cur.execute("CREATE INDEX IF NOT EXISTS idx_incidents_incident_id ON incidents (incident_id)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_incidents_tenant_last_seen ON incidents (tenant_id, last_seen DESC)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_incidents_primary_source_ip ON incidents (primary_source_ip)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents (status)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_incidents_last_seen ON incidents (last_seen DESC)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_incidents_campaign_id ON incidents (campaign_id)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_incident_alerts_incident_id ON incident_alerts (incident_id)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_incident_alerts_alert_id ON incident_alerts (alert_id)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_incident_audit_incident_id ON incident_audit_log (incident_id)")
        cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_incidents_idempotency_key ON incidents (idempotency_key) WHERE idempotency_key IS NOT NULL")
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_logs (
                id SERIAL PRIMARY KEY,
                timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                tenant_id TEXT DEFAULT 'default',
                actor_user TEXT,
                actor_role TEXT,
                action TEXT NOT NULL,
                resource_type TEXT,
                resource_id TEXT,
                correlation_id TEXT,
                source_ip TEXT,
                success BOOLEAN DEFAULT TRUE,
                metadata_json JSONB DEFAULT '{}'::jsonb
            )
            """
        )
        cur.execute("CREATE INDEX IF NOT EXISTS idx_audit_logs_tenant_ts ON audit_logs (tenant_id, timestamp DESC)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs (action)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_audit_logs_resource_type ON audit_logs (resource_type)")
    conn.commit()


def _b64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data):
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode((data + padding).encode("ascii"))


def create_jwt(subject="sentinela-demo", ttl_seconds=None, role="admin", tenant_id=None, token_use="access"):
    ttl = JWT_TTL_SECONDS if ttl_seconds is None else int(ttl_seconds)
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": subject,
        "role": role if role in VALID_ROLES else "viewer",
        "tenant_id": tenant_id or DEFAULT_TENANT_ID,
        "token_use": token_use,
        "jti": str(uuid.uuid4()),
        "iat": int(time.time()),
        "exp": int(time.time()) + ttl,
    }
    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    signature = hmac.new(JWT_SECRET.encode("utf-8"), signing_input, hashlib.sha256).digest()
    return f"{header_b64}.{payload_b64}.{_b64url_encode(signature)}"


def decode_jwt(token):
    try:
        header_b64, payload_b64, signature_b64 = token.split(".")
        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
        expected = hmac.new(JWT_SECRET.encode("utf-8"), signing_input, hashlib.sha256).digest()
        if not hmac.compare_digest(expected, _b64url_decode(signature_b64)):
            return None
        payload = json.loads(_b64url_decode(payload_b64))
        if int(payload.get("exp", 0)) < int(time.time()):
            return None
        payload["role"] = payload.get("role") if payload.get("role") in VALID_ROLES else "viewer"
        payload["tenant_id"] = payload.get("tenant_id") or DEFAULT_TENANT_ID
        payload["token_use"] = payload.get("token_use") or "access"
        return payload
    except Exception:
        return None


def verify_jwt(token):
    return decode_jwt(token) is not None


def authenticate_user(username, password):
    user = USERS.get(username or "")
    if user and verify_password(password, user.get("password_hash")):
        return {
            "sub": user["username"],
            "role": user.get("role", "viewer"),
            "tenant_id": user.get("tenant_id") or DEFAULT_TENANT_ID,
        }
    return None


def current_identity():
    if not has_request_context():
        return {"sub": "system", "role": "admin", "tenant_id": DEFAULT_TENANT_ID}
    if not ENABLE_AUTH:
        return {"sub": "auth-disabled", "role": "admin", "tenant_id": request.headers.get("X-Tenant-ID") or DEFAULT_TENANT_ID}
    bearer = request.headers.get("Authorization", "")
    if bearer.startswith("Bearer "):
        raw_token = bearer.split(" ", 1)[1].strip()
        payload = decode_jwt(raw_token)
        if payload and payload.get("token_use") == "access":
            return {"sub": payload.get("sub"), "role": payload.get("role", "viewer"), "tenant_id": payload.get("tenant_id") or DEFAULT_TENANT_ID}
        if hmac.compare_digest(raw_token, API_TOKEN):
            return {"sub": "legacy-token", "role": "admin", "tenant_id": request.headers.get("X-Tenant-ID") or DEFAULT_TENANT_ID}
    basic = request.authorization
    if basic:
        identity = authenticate_user(basic.username, basic.password)
        if identity:
            return identity
    legacy = request.headers.get("X-SENTINELA-TOKEN")
    if legacy and hmac.compare_digest(legacy, API_TOKEN):
        return {"sub": "legacy-token", "role": "admin", "tenant_id": request.headers.get("X-Tenant-ID") or DEFAULT_TENANT_ID}
    return None


def token_is_valid():
    return current_identity() is not None


def tenant_id():
    identity = current_identity() or {}
    return identity.get("tenant_id") or DEFAULT_TENANT_ID


def require_auth(view=None, roles=None):
    allowed_roles = set(roles or VALID_ROLES)

    def decorator(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            identity = current_identity()
            if not identity:
                return jsonify({"error": "unauthorized"}), 401
            if identity.get("role") not in allowed_roles:
                return jsonify({"error": "forbidden", "required_roles": sorted(allowed_roles)}), 403
            request.sentinela_identity = identity
            return fn(*args, **kwargs)

        return wrapped

    if view is not None:
        return decorator(view)
    return decorator


def require_role(*roles):
    return require_auth(roles=roles)


def ensure_connection():
    global SCHEMA_INITIALIZED
    conn = get_connection()
    if not SCHEMA_INITIALIZED:
        ensure_schema(conn)
        SCHEMA_INITIALIZED = True
    return conn


def request_source_ip():
    if not has_request_context():
        return None
    return (request.headers.get("X-Forwarded-For") or request.remote_addr or "").split(",")[0].strip() or None


def write_audit(action, resource_type=None, resource_id=None, success=True, metadata=None, identity=None, tenant=None):
    identity = identity or (current_identity() if has_request_context() else None) or {}
    correlation_id = getattr(request, "_sentinela_correlation_id", None) if has_request_context() else None
    metadata = metadata or {}
    conn = None
    try:
        conn = ensure_connection()
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO audit_logs (
                    tenant_id, actor_user, actor_role, action, resource_type, resource_id,
                    correlation_id, source_ip, success, metadata_json
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb)
                """,
                (
                    tenant or identity.get("tenant_id") or DEFAULT_TENANT_ID,
                    identity.get("sub"),
                    identity.get("role"),
                    action,
                    resource_type,
                    resource_id,
                    correlation_id,
                    request_source_ip(),
                    bool(success),
                    json.dumps(metadata, ensure_ascii=False),
                ),
            )
        conn.commit()
    except Exception as exc:
        if conn:
            try:
                conn.rollback()
            except Exception:
                pass
        log_json("WARN", "Falha ao registrar auditoria", action=action, error=str(exc))
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass


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


def pagination_params(default_limit=100, max_limit=500):
    try:
        limit = int(request.args.get("limit", default_limit))
    except (TypeError, ValueError):
        limit = default_limit
    try:
        offset = int(request.args.get("offset", 0))
    except (TypeError, ValueError):
        offset = 0
    return max(1, min(limit, max_limit)), max(0, offset)


def severity_from_score(score):
    score = int(score or 0)
    if score >= 90:
        return "CRITICAL"
    if score >= 70:
        return "HIGH"
    if score >= 50:
        return "MEDIUM"
    return "LOW"


def local_datetime_label(value):
    if not value:
        return None
    if isinstance(value, datetime):
        dt = value
    else:
        try:
            dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError:
            return str(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone().strftime("%d/%m/%Y %H:%M:%S")


def normalize_event_type(value):
    return str(value or "").replace("-", "_").replace(" ", "_").upper()


def alert_score(alert):
    breakdown = alert.get("score_breakdown")
    if isinstance(breakdown, dict) and breakdown.get("final_score") is not None:
        return int(breakdown.get("final_score") or 0)
    return int(alert.get("score_final") or alert.get("risco") or alert.get("threat_score") or 0)


def mitre_for_alert(alert):
    if alert.get("mitre_id") and REAL_MITRE_ID_PATTERN.match(str(alert.get("mitre_id")).upper()):
        return {
            "id": alert.get("mitre_id"),
            "name": alert.get("mitre_name"),
            "tactic": alert.get("mitre_tactic"),
        }
    if alert.get("threat_intel_match") or normalize_event_type(alert.get("status")) == "IOC_DETECTADO":
        return MITRE_MAPPINGS["IOC_MATCH"]
    return MITRE_MAPPINGS.get(normalize_event_type(alert.get("event_type")), {
        "id": None,
        "name": None,
        "tactic": None,
    })


def human_summary_for_alert(alert):
    if alert.get("human_summary") or alert.get("explanation"):
        return alert.get("human_summary") or alert.get("explanation")
    ip = alert.get("source_ip") or alert.get("ip") or "IP desconhecido"
    event_type = alert.get("event_type") or "evento"
    score = alert_score(alert)
    severity = alert.get("severity") or severity_from_score(score)
    service = alert.get("service") or "serviço não identificado"
    port = alert.get("port")
    mitre = mitre_for_alert(alert)
    replay = " O evento veio de replay simulado." if alert.get("is_replay_event") or alert.get("replay_id") else ""
    block = " O SENTINELA registrou bloqueio simulado apenas, sem firewall real." if alert.get("simulated_block") else " A ação SOC permanece em monitoramento ou investigação simulada."
    port_text = f" na porta {port}/{service}" if port is not None else f" no serviço {service}"
    target = alert.get("target_host") or alert.get("target_ip") or "alvo nao identificado"
    score_text = alert.get("score_explanation") or f"Score {score}"
    mitre_text = f" e foi associada a MITRE {mitre['id']} - {mitre['name']}" if mitre.get("id") else ""
    return f"O IP {ip} gerou {event_type}{port_text} contra {target}. {score_text}. Severidade {severity}{mitre_text}.{replay}{block}"


def default_target_context(alert):
    raw = alert.get("raw_event") if isinstance(alert.get("raw_event"), dict) else {}
    service = alert.get("target_service") or alert.get("service") or raw.get("service") or "unknown"
    port = alert.get("target_port") or alert.get("port") or raw.get("port")
    criticality = alert.get("asset_criticality") or ("high" if str(service).lower() in {"ssh", "rdp", "postgres", "mysql", "redis", "security"} else "medium")
    return {
        "target_host": alert.get("target_host") or raw.get("target_host") or raw.get("host") or "sentinela-local",
        "target_ip": alert.get("target_ip") or raw.get("target_ip") or raw.get("destination_ip") or raw.get("dst_ip") or "127.0.0.1",
        "target_user": alert.get("target_user") or raw.get("target_user") or raw.get("username") or raw.get("user"),
        "target_service": service,
        "target_port": port,
        "target_container": alert.get("target_container") or raw.get("target_container") or raw.get("container"),
        "target_application": alert.get("target_application") or raw.get("target_application") or raw.get("application") or "sentinela-lab",
        "environment": alert.get("environment") or raw.get("environment") or "local-demo",
        "asset_owner": alert.get("asset_owner") or raw.get("asset_owner") or "SOC Lab",
        "asset_criticality": criticality,
        "business_impact": alert.get("business_impact") or raw.get("business_impact") or "Possivel impacto no ativo monitorado pelo laboratorio SOC.",
    }


def default_score_breakdown(alert):
    score = alert_score(alert)
    reasons = alert.get("risk_reasons") or alert.get("correlation_reasons") or alert.get("reasons") or []
    if isinstance(reasons, str):
        reasons = [reasons]
    explanation = alert.get("score_explanation") or f"Score {score}: " + (", ".join(str(item) for item in reasons[:4]) if reasons else "evidencia simples de baixo impacto") + "."
    return {
        "base_score": min(score, 42),
        "sensitive_port_score": 8 if int(alert.get("port") or 0) in {22, 23, 3389, 445, 5432, 3306, 6379, 9200} else 0,
        "event_volume_score": min(18, max(0, int(alert.get("event_count") or 1) - 1) * 3),
        "time_window_score": 0,
        "ioc_score": 22 if alert.get("threat_intel_match") else 0,
        "asset_criticality_score": 12 if default_target_context(alert)["asset_criticality"] in {"high", "critical"} else 6,
        "mitre_correlation_score": 8 if alert.get("mitre_id") else 0,
        "repeated_activity_score": 5 if int(alert.get("occurrence_count") or 1) > 1 else 0,
        "confidence_score": 8,
        "final_score": score,
        "score_explanation": explanation,
    }


def response_context(alert):
    score = alert_score(alert)
    if alert.get("recommended_action"):
        action = alert.get("recommended_action")
    elif alert.get("simulated_block") or score >= 90:
        action = "Recomendar bloqueio temporario da origem e abertura de ticket de investigacao"
    elif score >= 70:
        action = "Investigar origem, validar autenticacao e preservar evidencias"
    else:
        action = "Monitorar recorrencia e revisar logs do ativo afetado"
    return {
        "recommended_action": action,
        "action_reason": alert.get("action_reason") or "Resposta recomendada por score, contexto do ativo e evidencias correlacionadas.",
        "response_playbook": alert.get("response_playbook") or ("PB-SOC-003-contencao-ip-suspeito" if score >= 90 else "PB-SOC-001-triagem-alerta"),
        "execution_mode": alert.get("execution_mode") or "simulation",
        "execution_status": alert.get("execution_status") or "not_executed",
        "execution_notes": alert.get("execution_notes") or "Ambiente local de demonstracao; nenhuma acao real foi executada.",
    }


def enrich_alert(alert):
    mitre = mitre_for_alert(alert)
    alert["source_ip"] = alert.get("source_ip") or alert.get("ip")
    final_score = alert_score(alert)
    alert["threat_score"] = final_score
    alert["score_final"] = final_score
    alert["risco"] = final_score
    alert["severity"] = severity_from_score(final_score)
    alert["mitre_id"] = mitre["id"]
    alert["mitre_name"] = mitre["name"]
    alert["mitre_tactic"] = mitre["tactic"]
    alert["mitre_techniques"] = alert.get("mitre_techniques") or ([mitre] if mitre.get("id") else [])
    alert["internal_rule_id"] = alert.get("internal_rule_id") or f"SENTINELA-{normalize_event_type(alert.get('event_type'))}"
    alert["internal_rule_name"] = alert.get("internal_rule_name") or alert.get("status") or "Regra interna Sentinela"
    alert["correlation_rule"] = alert.get("correlation_rule") or alert.get("correlation_key") or "source_ip_time_window"
    alert["detection_source"] = alert.get("detection_source") or "dashboard_api_compat"
    alert["alert_type"] = alert.get("alert_type") or ("incident_candidate" if final_score >= 70 or int(alert.get("event_count") or 0) >= 3 else "alert")
    alert.update(default_target_context(alert))
    alert["score_breakdown"] = alert.get("score_breakdown") or default_score_breakdown(alert)
    alert["score_explanation"] = alert.get("score_explanation") or alert["score_breakdown"].get("score_explanation")
    alert.update(response_context(alert))
    alert["human_summary"] = human_summary_for_alert(alert)
    alert["explanation"] = alert["human_summary"]
    return alert


def flatten_json_lists(values):
    flattened = []
    for value in values or []:
        if value is None:
            continue
        if isinstance(value, list):
            flattened.extend(flatten_json_lists(value))
        else:
            flattened.append(value)
    seen = []
    for value in flattened:
        if value not in seen:
            seen.append(value)
    return seen


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
    tenant = tenant_id()

    with conn.cursor() as cur:
        if demo_only:
            cur.execute(
                """
                SELECT * FROM alertas
                WHERE tenant_id = %s AND (is_demo = TRUE OR is_replay_event = TRUE)
                ORDER BY ts DESC
                LIMIT 100
                """,
                (tenant,),
            )
        else:
            cur.execute(
                """
                SELECT * FROM alertas
                WHERE tenant_id = %s AND ts >= NOW() - %s::interval
                ORDER BY ts DESC
                LIMIT 100
                """,
                (tenant, interval),
            )

        rows = cur.fetchall() or []
        columns = [desc[0] for desc in getattr(cur, "description", None) or []]

    alerts = [enrich_alert(row_to_dict(row, columns)) for row in rows]
    return jsonify({
        "demo": demo_only,
        "mode": "demo" if demo_only else "normal",
        "range": range_value,
        "count": len(alerts),
        "data": alerts,
    })


def fetch_ip_scores(conn):
    range_value = request.args.get("range", "24h")
    interval = range_to_interval(range_value)
    tenant = tenant_id()
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT
                COALESCE(source_ip, ip) AS source_ip,
                MAX(COALESCE(threat_score, score_final, risco, 0)) AS threat_score,
                COUNT(*) AS event_count,
                MAX(ts) AS last_seen,
                ARRAY_AGG(DISTINCT COALESCE(severity, status)) AS severities,
                jsonb_agg(DISTINCT COALESCE(correlation_reasons, risk_reasons, '[]'::jsonb)) AS reasons
            FROM alertas
            WHERE tenant_id = %s AND ts >= NOW() - %s::interval
            GROUP BY COALESCE(source_ip, ip)
            ORDER BY threat_score DESC, event_count DESC
            LIMIT 50
            """,
            (tenant, interval),
        )
        rows = cur.fetchall() or []
        columns = [desc[0] for desc in getattr(cur, "description", None) or []]

    data = []
    for row in rows:
        item = row_to_dict(row, columns)
        item["severity"] = severity_from_score(item.get("threat_score"))
        data.append(item)
    return jsonify({"range": range_value, "count": len(data), "data": data})


def fetch_alert_rows(conn, source_ip=None, limit=200):
    tenant = tenant_id()
    with conn.cursor() as cur:
        if source_ip:
            cur.execute(
                """
                SELECT * FROM (
                    SELECT * FROM alertas
                    WHERE tenant_id = %s AND COALESCE(source_ip, ip) = %s
                    ORDER BY ts DESC
                    LIMIT %s
                ) recent_alerts
                ORDER BY ts ASC
                """,
                (tenant, source_ip, limit),
            )
        else:
            cur.execute(
                """
                SELECT * FROM (
                    SELECT * FROM alertas
                    WHERE tenant_id = %s AND ts >= NOW() - INTERVAL '24 hours'
                    ORDER BY ts DESC
                    LIMIT %s
                ) recent_alerts
                ORDER BY ts ASC
                """,
                (tenant, limit),
            )
        rows = cur.fetchall() or []
        columns = [desc[0] for desc in getattr(cur, "description", None) or []]
    return [enrich_alert(row_to_dict(row, columns)) for row in rows]


def timeline_stage(alert):
    event_type = normalize_event_type(alert.get("event_type"))
    if alert.get("simulated_block") or event_type == "RESPONSE":
        return "Bloqueio simulado registrado"
    if alert.get("threat_intel_match") or event_type == "IOC_MATCH":
        return "IOC local identificado"
    if alert.get("threat_score", 0) >= 90:
        return "Score elevado para CRITICAL"
    if "BRUTE" in event_type or event_type in {"FAILED_LOGIN", "SSH_FAILED", "LOGIN_FAILED", "AUTH_FAILED"}:
        if str(alert.get("raw_event") or "").lower().find("admin") >= 0 or str(alert.get("raw_event") or "").lower().find("root") >= 0:
            return "Usuário privilegiado alvo"
        return "Tentativas de autenticação"
    if event_type in {"PORT_SCAN", "SCAN"}:
        return "Reconhecimento detectado"
    if alert.get("correlation_reasons") or alert.get("risk_reasons"):
        return "Brute force correlacionado"
    return "Evento recebido"


def attack_phase(alert):
    event_type = normalize_event_type(alert.get("event_type"))
    if alert.get("simulated_block") or event_type == "RESPONSE":
        return "RESPONSE_SIMULATED"
    if event_type == "ESCALATION" or int(alert.get("threat_score") or alert.get("score_final") or alert.get("risco") or 0) >= 90:
        return "ESCALATION"
    if alert.get("threat_intel_match") or event_type == "IOC_MATCH":
        return "IOC_MATCH"
    if event_type in {"BRUTE_FORCE", "FAILED_LOGIN", "SSH_FAILED", "LOGIN_FAILED", "AUTH_FAILED"}:
        return "CREDENTIAL_ACCESS"
    if event_type in {"PORT_SCAN", "SCAN"}:
        return "RECONNAISSANCE"
    if alert.get("correlation_reasons") or alert.get("risk_reasons") or event_type == "CORRELATION":
        return "CORRELATION"
    return "INITIAL_ACCESS_ATTEMPT"


def build_timeline(alerts):
    items = []
    for alert in alerts:
        timestamp = alert.get("ts") or alert.get("timestamp")
        items.append({
            "timestamp": timestamp,
            "local_time": local_datetime_label(timestamp),
            "source_ip": alert.get("source_ip") or alert.get("ip"),
            "event_type": alert.get("event_type"),
            "severity": alert.get("severity"),
            "score": alert.get("threat_score") or alert.get("score_final") or alert.get("risco"),
            "description": alert.get("human_summary"),
            "stage": timeline_stage(alert),
            "phase": attack_phase(alert),
            "mitre_id": alert.get("mitre_id"),
            "mitre_name": alert.get("mitre_name"),
            "mitre_tactic": alert.get("mitre_tactic"),
            "internal_rule_id": alert.get("internal_rule_id"),
            "correlation_rule": alert.get("correlation_rule"),
            "response_playbook": alert.get("response_playbook"),
            "recommended_action": alert.get("recommended_action"),
            "execution_mode": alert.get("execution_mode"),
            "execution_status": alert.get("execution_status"),
            "target_host": alert.get("target_host"),
            "target_ip": alert.get("target_ip"),
            "target_service": alert.get("target_service") or alert.get("service"),
            "target_port": alert.get("target_port") or alert.get("port"),
            "replay_id": alert.get("replay_id"),
            "simulated_block": bool(alert.get("simulated_block")),
        })
    return items


def bucket_start(dt, bucket_minutes):
    minute = (dt.minute // bucket_minutes) * bucket_minutes
    return dt.replace(minute=minute, second=0, microsecond=0)


def build_timeline_buckets(alerts, range_value="24h"):
    value = (range_value or "24h").lower()
    if value in {"1h", "60m"}:
        bucket_minutes = 5
        window_seconds = 3600
    elif value.endswith("m"):
        bucket_minutes = 1
        window_seconds = int(value[:-1] or 5) * 60 if value[:-1].isdigit() else 300
    elif value in {"7d", "168h"}:
        bucket_minutes = 24 * 60
        window_seconds = 7 * 24 * 3600
    else:
        bucket_minutes = 60
        window_seconds = 24 * 3600
    now_dt = datetime.now(timezone.utc)
    start_dt = now_dt.timestamp() - window_seconds
    buckets = {}
    for alert in alerts:
        dt = datetime_from_value(alert.get("ts") or alert.get("timestamp"))
        if dt.timestamp() < start_dt:
            continue
        start = bucket_start(dt, bucket_minutes)
        key = start.isoformat()
        item = buckets.setdefault(key, {"bucket_start": key, "count": 0, "low": 0, "medium": 0, "high": 0, "critical": 0})
        count = int(alert.get("occurrence_count") or 1)
        sev = str(alert.get("severity") or severity_from_score(alert_score(alert))).lower()
        item["count"] += count
        if sev in item:
            item[sev] += count
    return [buckets[key] for key in sorted(buckets)]


def build_campaigns(alerts):
    grouped = {}
    for alert in alerts:
        key = alert.get("replay_id") or alert.get("correlation_rule") or alert.get("correlation_key") or "campaign-window"
        grouped.setdefault(key, []).append(alert)
    campaigns = []
    for key, items in grouped.items():
        source_ips = sorted({item.get("source_ip") or item.get("ip") for item in items if item.get("source_ip") or item.get("ip")})
        targets = sorted({item.get("target_host") or item.get("target_ip") for item in items if item.get("target_host") or item.get("target_ip")})
        services = sorted({item.get("target_service") or item.get("service") for item in items if item.get("target_service") or item.get("service")})
        event_count = sum(int(item.get("occurrence_count") or 1) for item in items)
        if len(source_ips) < 2 and event_count < 6:
            continue
        max_score = max(int(item.get("threat_score") or item.get("score_final") or item.get("risco") or 0) for item in items)
        mitres = merge_unique(*[item.get("mitre_techniques") or [] for item in items])
        campaigns.append({
            "campaign_id": "CMP-" + str(uuid.uuid5(uuid.NAMESPACE_URL, key)).split("-")[0].upper(),
            "type": "campaign",
            "correlation_rule": key,
            "source_ip_count": len(source_ips),
            "event_count": event_count,
            "target_count": len(targets),
            "service_count": len(services),
            "source_ips": source_ips,
            "primary_targets": targets[:5],
            "services": services,
            "mitre_techniques": mitres,
            "severity": severity_from_score(max_score),
            "max_score": max_score,
            "first_seen": min((item.get("first_seen") or item.get("ts") for item in items if item.get("first_seen") or item.get("ts")), default=None),
            "last_seen": max((item.get("last_seen") or item.get("ts") for item in items if item.get("last_seen") or item.get("ts")), default=None),
            "evidence_summary": f"{event_count} eventos, {len(source_ips)} IP(s), {len(targets)} alvo(s), {len(services)} servico(s).",
        })
    return sorted(campaigns, key=lambda item: (item["max_score"], item["event_count"]), reverse=True)


def incident_id_for(source_ip, replay_id=None):
    seed = f"{source_ip}|{replay_id or 'live'}"
    return "INC-" + str(uuid.uuid5(uuid.NAMESPACE_URL, seed)).split("-")[0].upper()


def fetch_incident_overrides(conn):
    with conn.cursor() as cur:
        cur.execute("SELECT incident_id, status, analyst_notes, assigned_to, soc_action, created_at, updated_at FROM incident_overrides")
        rows = cur.fetchall() or []
        columns = [desc[0] for desc in getattr(cur, "description", None) or []]
    return {row_to_dict(row, columns)["incident_id"]: row_to_dict(row, columns) for row in rows}


def default_recommendations():
    return [
        "Revisar logs relacionados ao IP e ao serviço envolvido.",
        "Validar se o IP é interno, externo ou origem simulada.",
        "Verificar usuário alvo e janela de autenticação.",
        "Confirmar se o caso pode ser falso positivo.",
        "Manter bloqueio apenas simulado no ambiente local.",
    ]


def analyst_summary_for_investigation(source_ip, event_types, max_score, max_severity, replay_events):
    signals = []
    normalized = {normalize_event_type(item) for item in event_types}
    if "PORT_SCAN" in normalized or "SCAN" in normalized:
        signals.append("varredura")
    if {"FAILED_LOGIN", "SSH_FAILED", "LOGIN_FAILED", "AUTH_FAILED", "BRUTE_FORCE"} & normalized:
        signals.append("brute force")
    if "IOC_MATCH" in normalized:
        signals.append("correspondência com IOC local")
    signal_text = ", ".join(signals) if signals else "atividade suspeita correlacionada"
    replay_text = " Os eventos incluem replay simulado para demonstração." if replay_events else ""
    return f"O IP {source_ip} apresentou comportamento compatível com {signal_text}. A pontuação de risco atingiu {max_score} ({max_severity}). O SENTINELA registrou apenas resposta simulada, sem bloqueio real.{replay_text}"


def build_incident_from_alerts(source_ip, alerts):
    if not alerts:
        return None
    scores = [int(item.get("threat_score") or item.get("score_final") or item.get("risco") or 0) for item in alerts]
    max_score = max(scores or [0])
    severity = severity_from_score(max_score)
    replay_ids = sorted({item.get("replay_id") for item in alerts if item.get("replay_id")})
    mitres = []
    for item in alerts:
        mitre = {"id": item.get("mitre_id"), "name": item.get("mitre_name"), "tactic": item.get("mitre_tactic")}
        if mitre["id"] and mitre not in mitres:
            mitres.append(mitre)
    simulated = any(item.get("simulated_block") for item in alerts)
    status = "DETECTED" if max_score < 50 else ("INVESTIGATING" if max_score >= 70 else "TRIAGED")
    event_types = sorted({str(item.get("event_type")) for item in alerts if item.get("event_type")})
    summary = f"O incidente correlaciona {len(alerts)} alertas do IP {source_ip}, com score máximo {max_score} ({severity}) e técnicas MITRE {', '.join(m['id'] for m in mitres) or 'N/D'}. Nenhum bloqueio real foi executado."
    return {
        "incident_id": incident_id_for(source_ip, replay_ids[0] if replay_ids else None),
        "title": f"Incidente {severity} - {source_ip}",
        "source_ip": source_ip,
        "status": status,
        "severity": severity,
        "max_score": max_score,
        "first_seen": alerts[0].get("first_seen") or alerts[0].get("ts"),
        "last_seen": alerts[-1].get("last_seen") or alerts[-1].get("ts"),
        "event_count": len(alerts),
        "alert_ids": [str(item.get("event_id") or item.get("id")) for item in alerts if item.get("event_id") or item.get("id")],
        "related_alerts": [
            {
                "id": str(item.get("event_id") or item.get("id")),
                "timestamp": item.get("ts") or item.get("timestamp"),
                "local_time": local_datetime_label(item.get("ts") or item.get("timestamp")),
                "event_type": item.get("event_type"),
                "severity": item.get("severity"),
                "score": item.get("threat_score"),
                "mitre_id": item.get("mitre_id"),
            }
            for item in alerts if item.get("event_id") or item.get("id")
        ],
        "event_types": event_types,
        "mitre_techniques": mitres,
        "human_summary": summary,
        "analyst_notes": "",
        "assigned_to": "",
        "soc_action": "bloqueio simulado apenas" if simulated else "investigação simulada",
        "created_at": alerts[0].get("first_seen") or alerts[0].get("ts"),
        "updated_at": alerts[-1].get("last_seen") or alerts[-1].get("ts"),
        "recommendations": default_recommendations(),
        "replay_id": replay_ids[0] if replay_ids else None,
        "timeline": build_timeline(alerts),
    }


def apply_incident_overrides(incident, overrides):
    if not incident:
        return None
    override = overrides.get(incident["incident_id"]) if overrides else None
    if not override:
        return incident
    for key in ("status", "analyst_notes", "assigned_to", "soc_action", "created_at", "updated_at"):
        if override.get(key) is not None:
            incident[key] = override.get(key)
    return incident


def build_incidents(alerts, overrides=None):
    grouped = {}
    for alert in alerts:
        ip = alert.get("source_ip") or alert.get("ip")
        if not ip:
            continue
        grouped.setdefault(ip, []).append(alert)
    incidents = [apply_incident_overrides(build_incident_from_alerts(ip, items), overrides or {}) for ip, items in grouped.items()]
    return sorted([item for item in incidents if item], key=lambda item: (SEVERITY_ORDER.get(item["severity"], 0), item["max_score"], item["event_count"]), reverse=True)


def json_list(value):
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
        for item in json_list(value):
            if item in (None, ""):
                continue
            if item not in merged:
                merged.append(item)
    return merged


def alert_id_value(alert):
    return str(alert.get("event_id") or alert.get("id") or uuid.uuid4())


def alert_timestamp(alert):
    return alert.get("ts") or alert.get("timestamp") or now_iso()


def datetime_from_value(value):
    if isinstance(value, datetime):
        return value
    if not value:
        return datetime.now(timezone.utc)
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        return datetime.now(timezone.utc)


def service_label(alert):
    service = alert.get("service")
    port = alert.get("port")
    if port is not None and service:
        return f"{port}/{service}"
    if service:
        return str(service)
    if port is not None:
        return str(port)
    return None


def alert_entities(alert):
    raw = alert.get("raw_event") if isinstance(alert.get("raw_event"), dict) else {}
    username = alert.get("username") or raw.get("username")
    destination_ip = alert.get("destination_ip") or raw.get("destination_ip") or raw.get("dst_ip")
    return {
        "source_ip": alert.get("source_ip") or alert.get("ip"),
        "destination_ip": destination_ip,
        "username": username,
        "service": service_label(alert),
        "event_type": normalize_event_type(alert.get("event_type")),
        "mitre_id": alert.get("mitre_id"),
        "replay_id": alert.get("replay_id"),
        "score": int(alert.get("threat_score") or alert.get("score_final") or alert.get("risco") or 0),
        "severity": alert.get("severity") or severity_from_score(alert.get("threat_score") or 0),
    }


def mitre_technique_from_alert(alert):
    mitre = mitre_for_alert(alert)
    return {"id": mitre["id"], "name": mitre["name"], "tactic": mitre["tactic"]} if mitre.get("id") else None


def incident_human_summary(incident):
    source_ips = json_list(incident.get("source_ips")) or [incident.get("primary_source_ip") or incident.get("source_ip")]
    event_types = ", ".join(json_list(incident.get("event_types"))[:5]) or "eventos correlacionados"
    mitres = ", ".join(item.get("id") for item in json_list(incident.get("mitre_techniques")) if isinstance(item, dict) and item.get("id")) or "MITRE N/D"
    multi_ip = "campanha multi-IP" if len([ip for ip in source_ips if ip]) > 1 else "incidente individual"
    return (
        f"O {multi_ip} envolve {', '.join(ip for ip in source_ips if ip) or 'IP não identificado'} "
        f"com {event_types}. O score máximo chegou a {incident.get('max_score', 0)} "
        f"({incident.get('severity', 'LOW')}) e as técnicas associadas são {mitres}. "
        "Todas as respostas SOC permanecem simuladas, sem firewall real ou iptables."
    )


def incident_title(incident):
    source_ips = json_list(incident.get("source_ips"))
    primary = incident.get("primary_source_ip") or incident.get("source_ip") or (source_ips[0] if source_ips else "origem desconhecida")
    suffix = "campanha multi-IP" if len(source_ips) > 1 else primary
    return f"Incidente {incident.get('severity', 'LOW')} - {suffix}"


def derive_correlation_reasons(alert, incident=None):
    entities = alert_entities(alert)
    reasons = []
    if incident:
        if entities["replay_id"] and entities["replay_id"] in json_list(incident.get("replay_ids")):
            reasons.append("same_replay_id")
        if entities["source_ip"] and entities["source_ip"] in json_list(incident.get("source_ips")):
            reasons.append("same_source_ip")
        if entities["username"] and entities["username"] in json_list(incident.get("usernames")):
            reasons.append("same_target_user")
        if entities["service"] and entities["service"] in json_list(incident.get("services")):
            reasons.append("same_destination_service")
        if entities["mitre_id"] and any(item.get("id") == entities["mitre_id"] for item in json_list(incident.get("mitre_techniques")) if isinstance(item, dict)):
            reasons.append("mitre_overlap")
        last_seen = datetime_from_value(incident.get("last_seen"))
        if abs((datetime_from_value(alert_timestamp(alert)) - last_seen).total_seconds()) <= INCIDENT_WINDOW_SECONDS:
            reasons.append("time_window_match")
        existing_types = set(json_list(incident.get("event_types")))
        chain = {"PORT_SCAN", "FAILED_LOGIN", "BRUTE_FORCE", "IOC_MATCH", "ESCALATION", "RESPONSE"}
        if entities["event_type"] in chain and existing_types & chain:
            reasons.append("attack_chain_detected")
        if entities["source_ip"] and entities["source_ip"] not in json_list(incident.get("source_ips")) and (
            "same_replay_id" in reasons or "same_target_user" in reasons or "same_destination_service" in reasons
        ):
            reasons.append("multi_ip_same_target")
    else:
        if entities["replay_id"]:
            reasons.append("same_replay_id")
        if entities["source_ip"]:
            reasons.append("same_source_ip")
    return merge_unique(reasons, alert.get("correlation_reasons"), alert.get("risk_reasons"))


def row_to_incident(row, columns):
    if not columns:
        return None
    incident = row_to_dict(row, columns)
    return normalize_incident_record(incident)


def normalize_incident_record(incident):
    if not incident:
        return None
    incident["source_ips"] = json_list(incident.get("source_ips"))
    incident["source_ip"] = incident.get("primary_source_ip") or (incident["source_ips"][0] if incident["source_ips"] else None)
    incident["usernames"] = json_list(incident.get("usernames"))
    incident["services"] = json_list(incident.get("services"))
    incident["event_types"] = json_list(incident.get("event_types"))
    incident["mitre_techniques"] = json_list(incident.get("mitre_techniques"))
    incident["correlation_reasons"] = json_list(incident.get("correlation_reasons"))
    incident["replay_ids"] = json_list(incident.get("replay_ids"))
    incident["lifecycle_stage"] = incident.get("lifecycle_stage") or lifecycle_from_status(incident.get("status"))
    incident["affected_assets"] = json_list(incident.get("affected_assets"))
    incident["evidence"] = json_list(incident.get("evidence"))
    incident["score_explanation"] = incident.get("score_explanation") or f"Score {incident.get('max_score', 0)} derivado do maior alerta correlacionado."
    incident["recommended_action"] = incident.get("recommended_action") or "Investigar evidencias, validar ativo afetado e decidir contencao."
    incident["response_playbook"] = incident.get("response_playbook") or "PB-SOC-002-investigacao-credenciais"
    incident["execution_mode"] = incident.get("execution_mode") or "simulation"
    incident["execution_status"] = incident.get("execution_status") or "not_executed"
    incident["recommendations"] = default_recommendations()
    return incident


def lifecycle_from_status(status):
    normalized = str(status or "").upper()
    mapping = {
        "NEW": "Detected",
        "DETECTED": "Detected",
        "TRIAGED": "Triaged",
        "INVESTIGATING": "Investigating",
        "CONTAINED": "Contained",
        "RESOLVED": "Resolved",
        "CLOSED": "Closed",
        "FALSE_POSITIVE": "Closed",
    }
    return mapping.get(normalized, "Detected")


def fetch_incident_by_id(conn, incident_id):
    with conn.cursor() as cur:
        cur.execute("SELECT * FROM incidents WHERE tenant_id = %s AND incident_id = %s", (tenant_id(), incident_id))
        row = cur.fetchone()
        columns = [desc[0] for desc in getattr(cur, "description", None) or []]
    return row_to_incident(row, columns) if row else None


def fetch_incident_id_for_alert(conn, alert_id):
    with conn.cursor() as cur:
        cur.execute("SELECT incident_id FROM incident_alerts WHERE alert_id = %s LIMIT 1", (alert_id,))
        row = cur.fetchone()
    return row[0] if row else None


def fetch_candidate_incidents(conn):
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT * FROM incidents
            WHERE tenant_id = %s AND (status = ANY(%s) OR last_seen >= NOW() - INTERVAL '24 hours')
            ORDER BY last_seen DESC
            LIMIT 200
            """,
            (tenant_id(), list(OPEN_INCIDENT_STATUSES)),
        )
        rows = cur.fetchall() or []
        columns = [desc[0] for desc in getattr(cur, "description", None) or []]
    return [item for item in (row_to_incident(row, columns) for row in rows) if item]


def find_matching_incident(conn, alert):
    best = None
    best_score = 0
    for incident in fetch_candidate_incidents(conn):
        reasons = derive_correlation_reasons(alert, incident)
        score = 0
        weights = {
            "same_replay_id": 8,
            "same_source_ip": 5,
            "same_target_user": 4,
            "same_destination_service": 3,
            "multi_ip_same_target": 4,
            "attack_chain_detected": 3,
            "mitre_overlap": 2,
            "time_window_match": 2,
        }
        for reason in reasons:
            score += weights.get(reason, 0)
        if score > best_score:
            best = incident
            best_score = score
    return best if best_score >= 5 else None


def create_incident_from_alert(conn, alert):
    entities = alert_entities(alert)
    source_ips = [entities["source_ip"]] if entities["source_ip"] else []
    mitre_item = mitre_technique_from_alert(alert)
    mitres = [mitre_item] if mitre_item else []
    reasons = derive_correlation_reasons(alert)
    incident = {
        "incident_id": incident_id_for(entities["source_ip"] or "unknown", entities["replay_id"]),
        "tenant_id": alert.get("tenant_id") or tenant_id(),
        "severity": "LOW" if normalize_event_type(alert.get("event_type")) == "FALSE_POSITIVE" else severity_from_score(entities["score"]),
        "max_score": 0 if normalize_event_type(alert.get("event_type")) == "FALSE_POSITIVE" else entities["score"],
        "primary_source_ip": entities["source_ip"],
        "source_ips": source_ips,
        "destination_ip": entities["destination_ip"],
        "usernames": [entities["username"]] if entities["username"] else [],
        "services": [entities["service"]] if entities["service"] else [],
        "event_types": [entities["event_type"]] if entities["event_type"] else [],
        "mitre_techniques": mitres,
        "correlation_reasons": reasons,
        "replay_ids": [entities["replay_id"]] if entities["replay_id"] else [],
        "first_seen": alert_timestamp(alert),
        "last_seen": alert_timestamp(alert),
        "event_count": 1,
        "status": "DETECTED",
        "soc_action": "bloqueio simulado apenas" if alert.get("simulated_block") else "investigação simulada",
    }
    incident["title"] = incident_title(incident)
    incident["description"] = incident_human_summary(incident)
    incident["human_summary"] = incident["description"]
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO incidents (
                incident_id, title, description, status, severity, max_score,
                tenant_id,
                primary_source_ip, source_ips, destination_ip, usernames, services,
                event_types, mitre_techniques, correlation_reasons, replay_ids,
                first_seen, last_seen, event_count, human_summary, analyst_notes,
                assigned_to, soc_action, created_at, updated_at
            )
            VALUES (
                %(incident_id)s, %(title)s, %(description)s, %(status)s, %(severity)s, %(max_score)s,
                %(tenant_id)s,
                %(primary_source_ip)s, %(source_ips)s::jsonb, %(destination_ip)s, %(usernames)s::jsonb,
                %(services)s::jsonb, %(event_types)s::jsonb, %(mitre_techniques)s::jsonb,
                %(correlation_reasons)s::jsonb, %(replay_ids)s::jsonb, %(first_seen)s, %(last_seen)s,
                %(event_count)s, %(human_summary)s, '', '', %(soc_action)s, NOW(), NOW()
            )
            ON CONFLICT (incident_id) DO NOTHING
            """,
            {**incident, **{key: json.dumps(incident[key], ensure_ascii=False) for key in ("source_ips", "usernames", "services", "event_types", "mitre_techniques", "correlation_reasons", "replay_ids")}},
        )
    return fetch_incident_by_id(conn, incident["incident_id"]) or normalize_incident_record(incident)


def update_incident_from_alert(conn, incident, alert, reasons=None):
    entities = alert_entities(alert)
    score = 0 if normalize_event_type(alert.get("event_type")) == "FALSE_POSITIVE" else entities["score"]
    max_score = max(int(incident.get("max_score") or 0), score)
    updated = {
        **incident,
        "max_score": max_score,
        "severity": severity_from_score(max_score),
        "source_ips": merge_unique(incident.get("source_ips"), [entities["source_ip"]]),
        "usernames": merge_unique(incident.get("usernames"), [entities["username"]]),
        "services": merge_unique(incident.get("services"), [entities["service"]]),
        "event_types": merge_unique(incident.get("event_types"), [entities["event_type"]]),
        "mitre_techniques": merge_unique(incident.get("mitre_techniques"), [mitre_technique_from_alert(alert)]),
        "correlation_reasons": merge_unique(incident.get("correlation_reasons"), reasons or derive_correlation_reasons(alert, incident)),
        "replay_ids": merge_unique(incident.get("replay_ids"), [entities["replay_id"]]),
        "last_seen": alert_timestamp(alert),
        "event_count": int(incident.get("event_count") or 0) + 1,
        "destination_ip": incident.get("destination_ip") or entities["destination_ip"],
    }
    updated["title"] = incident_title(updated)
    updated["description"] = incident_human_summary(updated)
    updated["human_summary"] = updated["description"]
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE incidents SET
                title = %(title)s,
                description = %(description)s,
                severity = %(severity)s,
                max_score = %(max_score)s,
                primary_source_ip = %(primary_source_ip)s,
                source_ips = %(source_ips)s::jsonb,
                destination_ip = %(destination_ip)s,
                usernames = %(usernames)s::jsonb,
                services = %(services)s::jsonb,
                event_types = %(event_types)s::jsonb,
                mitre_techniques = %(mitre_techniques)s::jsonb,
                correlation_reasons = %(correlation_reasons)s::jsonb,
                replay_ids = %(replay_ids)s::jsonb,
                last_seen = %(last_seen)s,
                event_count = %(event_count)s,
                human_summary = %(human_summary)s,
                updated_at = NOW()
            WHERE incident_id = %(incident_id)s
              AND tenant_id = %(tenant_id)s
            """,
            {**updated, "tenant_id": incident.get("tenant_id") or tenant_id(), **{key: json.dumps(updated[key], ensure_ascii=False) for key in ("source_ips", "usernames", "services", "event_types", "mitre_techniques", "correlation_reasons", "replay_ids")}},
        )
    return fetch_incident_by_id(conn, incident["incident_id"]) or normalize_incident_record(updated)


def link_alert_to_incident(conn, incident_id, alert_id):
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO incident_alerts (incident_id, alert_id, created_at)
            VALUES (%s, %s, NOW())
            ON CONFLICT (incident_id, alert_id) DO NOTHING
            """,
            (incident_id, str(alert_id)),
        )


def correlate_alert_to_incident(conn, alert):
    alert = enrich_alert(alert)
    alert_id = alert_id_value(alert)
    linked_incident_id = fetch_incident_id_for_alert(conn, alert_id)
    if linked_incident_id:
        return fetch_incident_by_id(conn, linked_incident_id)
    incident = find_matching_incident(conn, alert)
    if incident:
        reasons = derive_correlation_reasons(alert, incident)
        incident = update_incident_from_alert(conn, incident, alert, reasons)
    else:
        incident = create_incident_from_alert(conn, alert)
    link_alert_to_incident(conn, incident["incident_id"], alert_id)
    return incident


def materialize_incidents(conn, alerts):
    materialized = []
    for alert in alerts:
        try:
            incident = correlate_alert_to_incident(conn, alert)
            if incident:
                materialized.append(incident)
        except Exception as exc:
            log_json("WARN", "Falha ao materializar incidente; alerta preservado", error=str(exc), event_id=alert.get("event_id"))
    conn.commit()
    return materialized


def fetch_persisted_incidents(conn, limit=100, offset=0):
    with conn.cursor() as cur:
        cur.execute("SELECT * FROM incidents WHERE tenant_id = %s ORDER BY last_seen DESC, max_score DESC LIMIT %s OFFSET %s", (tenant_id(), limit, offset))
        rows = cur.fetchall() or []
        columns = [desc[0] for desc in getattr(cur, "description", None) or []]
    return [item for item in (row_to_incident(row, columns) for row in rows) if item]


def count_persisted_incidents(conn):
    with conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM incidents WHERE tenant_id = %s", (tenant_id(),))
        row = cur.fetchone()
    return int(row[0] or 0) if row else 0


def fetch_incident_alerts(conn, incident_id, limit=500, offset=0):
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT a.*
            FROM incident_alerts ia
            JOIN alertas a ON ia.alert_id = COALESCE(a.event_id::text, a.id::text)
            WHERE a.tenant_id = %s AND ia.incident_id = %s
            ORDER BY a.ts ASC
            LIMIT %s OFFSET %s
            """,
            (tenant_id(), incident_id, limit, offset),
        )
        rows = cur.fetchall() or []
        columns = [desc[0] for desc in getattr(cur, "description", None) or []]
    return [enrich_alert(row_to_dict(row, columns)) for row in rows]


def count_incident_alerts(conn, incident_id):
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT COUNT(*)
            FROM incident_alerts ia
            JOIN alertas a ON ia.alert_id = COALESCE(a.event_id::text, a.id::text)
            WHERE a.tenant_id = %s AND ia.incident_id = %s
            """,
            (tenant_id(), incident_id),
        )
        row = cur.fetchone()
    return int(row[0] or 0) if row else 0


def count_linked_alerts(conn):
    with conn.cursor() as cur:
        cur.execute("SELECT COUNT(DISTINCT alert_id) FROM incident_alerts")
        row = cur.fetchone()
    return int(row[0] or 0) if row else 0


def fetch_incident_audit(conn, incident_id):
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT id, incident_id, field_changed, old_value, new_value, changed_by, changed_at
            FROM incident_audit_log
            WHERE incident_id = %s
            ORDER BY changed_at DESC
            LIMIT 100
            """,
            (incident_id,),
        )
        rows = cur.fetchall() or []
        columns = [desc[0] for desc in getattr(cur, "description", None) or []]
    return [row_to_dict(row, columns) for row in rows]


def enrich_incident_detail(conn, incident):
    if not incident:
        return None
    alerts = fetch_incident_alerts(conn, incident["incident_id"])
    if not alerts and incident.get("source_ip"):
        alerts = fetch_alert_rows(conn, source_ip=incident.get("source_ip"), limit=200)
    incident["related_alerts"] = [
        {
            "id": alert_id_value(item),
            "source_ip": item.get("source_ip") or item.get("ip"),
            "target_host": item.get("target_host"),
            "target_ip": item.get("target_ip"),
            "target_service": item.get("target_service") or item.get("service"),
            "target_port": item.get("target_port") or item.get("port"),
            "timestamp": item.get("ts") or item.get("timestamp"),
            "local_time": local_datetime_label(item.get("ts") or item.get("timestamp")),
            "event_type": item.get("event_type"),
            "severity": item.get("severity"),
            "score": item.get("threat_score"),
            "mitre_id": item.get("mitre_id"),
            "internal_rule_id": item.get("internal_rule_id"),
            "recommended_action": item.get("recommended_action"),
        }
        for item in alerts
    ]
    incident["timeline"] = build_timeline(alerts)
    incident["audit_log"] = fetch_incident_audit(conn, incident["incident_id"])
    incident["human_summary"] = incident.get("human_summary") or incident_human_summary(incident)
    incident["lifecycle_stage"] = incident.get("lifecycle_stage") or lifecycle_from_status(incident.get("status"))
    incident["affected_assets"] = merge_unique(
        incident.get("affected_assets"),
        [
            {
                "target_host": item.get("target_host"),
                "target_ip": item.get("target_ip"),
                "target_service": item.get("target_service") or item.get("service"),
                "target_port": item.get("target_port") or item.get("port"),
                "asset_criticality": item.get("asset_criticality"),
                "business_impact": item.get("business_impact"),
            }
            for item in alerts
        ],
    )
    incident["evidence"] = merge_unique(
        incident.get("evidence"),
        [
            {
                "rule": item.get("internal_rule_id"),
                "log_summary": item.get("human_summary"),
                "event_count": item.get("event_count"),
                "first_seen": item.get("first_seen"),
                "last_seen": item.get("last_seen"),
                "ports": item.get("ports") or [item.get("port")],
                "services": item.get("services") or [item.get("service")],
                "severity_reason": item.get("score_explanation"),
                "action_reason": item.get("action_reason"),
            }
            for item in alerts
        ],
    )
    incident["score_explanation"] = incident.get("score_explanation") or max((item.get("score_explanation") for item in alerts if item.get("score_explanation")), default=f"Score {incident.get('max_score', 0)} derivado dos alertas correlacionados.")
    incident["recommended_action"] = incident.get("recommended_action") or (alerts[-1].get("recommended_action") if alerts else "Investigar evidencias e validar impacto.")
    incident["response_playbook"] = incident.get("response_playbook") or (alerts[-1].get("response_playbook") if alerts else "PB-SOC-002-investigacao-credenciais")
    incident["execution_mode"] = incident.get("execution_mode") or "simulation"
    incident["execution_status"] = incident.get("execution_status") or "not_executed"
    return incident


def build_investigation(conn, source_ip):
    alerts = fetch_alert_rows(conn, source_ip=source_ip, limit=300)
    if not alerts:
        return None
    materialize_incidents(conn, alerts)
    persisted_incidents = [
        enrich_incident_detail(conn, item)
        for item in fetch_persisted_incidents(conn)
        if source_ip in json_list(item.get("source_ips")) or item.get("primary_source_ip") == source_ip
    ]
    incident = persisted_incidents[0] if persisted_incidents else build_incident_from_alerts(source_ip, alerts)
    event_types = sorted({item.get("event_type") for item in alerts if item.get("event_type")})
    services = sorted({f"{item.get('port')}/{item.get('service')}" for item in alerts if item.get("port") is not None or item.get("service")})
    reasons = flatten_json_lists([item.get("correlation_reasons") or item.get("risk_reasons") or item.get("reasons") for item in alerts])
    soc_actions = sorted({item.get("auto_response") or item.get("action_soc") for item in alerts if item.get("auto_response") or item.get("action_soc")})
    mitres = incident["mitre_techniques"] if incident else []
    max_score = max(int(item.get("threat_score") or item.get("score_final") or item.get("risco") or 0) for item in alerts)
    max_severity = severity_from_score(max_score)
    replay_events = [item for item in alerts if item.get("is_replay_event") or item.get("replay_id")]
    return {
        "source_ip": source_ip,
        "current_score": max_score,
        "max_severity": max_severity,
        "first_seen": alerts[0].get("first_seen") or alerts[0].get("ts"),
        "last_seen": alerts[-1].get("last_seen") or alerts[-1].get("ts"),
        "event_count": len(alerts),
        "incident_count": 1 if incident else 0,
        "event_types": event_types,
        "services": services,
        "mitre_techniques": mitres,
        "correlation_reasons": reasons,
        "soc_actions": soc_actions,
        "replay_events": replay_events,
        "timeline": build_timeline(alerts),
        "related_incidents": persisted_incidents or ([incident] if incident else []),
        "correlated_ips": sorted({ip for item in persisted_incidents for ip in json_list(item.get("source_ips")) if ip != source_ip}),
        "is_multi_ip": any(len(json_list(item.get("source_ips"))) > 1 for item in persisted_incidents),
        "human_summary": incident["human_summary"] if incident else human_summary_for_alert(alerts[-1]),
        "analyst_summary": analyst_summary_for_investigation(source_ip, event_types, max_score, max_severity, replay_events),
        "recommended_actions": default_recommendations(),
        "incident": incident,
    }


def fetch_demo_summary(conn):
    tenant = tenant_id()
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT
                COUNT(*) AS total_alerts,
                COALESCE(MAX(COALESCE(threat_score, score_final, risco, 0)), 0) AS max_score,
                COUNT(*) FILTER (WHERE is_replay_event = TRUE) AS replay_events,
                COUNT(*) FILTER (WHERE simulated_block = TRUE) AS simulated_blocks
            FROM alertas
            WHERE tenant_id = %s AND ts >= NOW() - INTERVAL '24 hours'
            """,
            (tenant,),
        )
        summary_row = cur.fetchone() or [0, 0, 0, 0]
        cur.execute(
            """
            SELECT COALESCE(source_ip, ip) AS source_ip,
                   MAX(COALESCE(threat_score, score_final, risco, 0)) AS threat_score
            FROM alertas
            WHERE tenant_id = %s AND ts >= NOW() - INTERVAL '24 hours'
            GROUP BY COALESCE(source_ip, ip)
            ORDER BY threat_score DESC
            LIMIT 1
            """,
            (tenant,),
        )
        top_row = cur.fetchone()
        cur.execute(
            """
            SELECT COALESCE(severity, status, 'LOW') AS severity, COUNT(*) AS total
            FROM alertas
            WHERE tenant_id = %s AND ts >= NOW() - INTERVAL '24 hours'
            GROUP BY COALESCE(severity, status, 'LOW')
            ORDER BY total DESC
            LIMIT 1
            """,
            (tenant,),
        )
        severity_row = cur.fetchone()

    return jsonify({
        "total_alerts": int(summary_row[0] or 0),
        "max_score": int(summary_row[1] or 0),
        "replay_events": int(summary_row[2] or 0),
        "simulated_blocks": int(summary_row[3] or 0),
        "most_dangerous_ip": top_row[0] if top_row else None,
        "most_dangerous_score": int(top_row[1] or 0) if top_row else 0,
        "dominant_severity": severity_row[0] if severity_row else "LOW",
    })


def read_rules_config():
    defaults = [
        {"name": "port_scan", "description": "Detecta varredura de portas", "enabled": True, "event_type": "PORT_SCAN", "score": 25, "severity": "LOW", "threshold": 1, "window_seconds": 60, "mitre_id": "T1046", "tags": ["reconnaissance"], "correlation_key": "source_ip", "action": "monitor"},
        {"name": "ssh_brute_force", "description": "Detecta múltiplas falhas de login SSH em curto intervalo", "enabled": True, "event_type": "FAILED_LOGIN", "score": 40, "severity": "HIGH", "threshold": 5, "window_seconds": 60, "mitre_id": "T1110", "tags": ["ssh", "credential_access"], "correlation_key": "source_ip", "action": "simulated_block"},
        {"name": "ioc_match", "description": "Detecta correspondência com IOC local", "enabled": True, "event_type": "IOC_MATCH", "score": 85, "severity": "CRITICAL", "threshold": 1, "window_seconds": 300, "mitre_id": "T1071", "tags": ["ioc", "threat_intel"], "correlation_key": "source_ip", "action": "simulated_block"},
    ]
    if yaml is None:
        return {"source": "defaults", "fallback": True, "rules": normalize_rules(defaults), "warning": "PyYAML indisponível no dashboard_api"}
    for candidate in RULES_CANDIDATES:
        try:
            if candidate.exists():
                with candidate.open("r", encoding="utf-8") as file:
                    payload = yaml.safe_load(file) or {}
                rules = [rule for rule in payload.get("rules", []) if isinstance(rule, dict)]
                return {"source": str(candidate), "fallback": False, "rules": normalize_rules(rules)}
        except Exception as exc:
            log_json("WARN", "Falha ao ler regras YAML para API; usando defaults", path=str(candidate), error=str(exc))
            return {"source": "defaults", "fallback": True, "rules": normalize_rules(defaults), "error": str(exc)}
    return {"source": "defaults", "fallback": True, "rules": normalize_rules(defaults)}


def normalize_rules(rules):
    normalized = []
    for rule in rules:
        if rule.get("enabled", True) is False:
            enabled = False
        else:
            enabled = True
        mitre = MITRE_MAPPINGS.get(normalize_event_type(rule.get("event_type")), {})
        normalized.append({
            "name": rule.get("name", "unnamed_rule"),
            "description": rule.get("description", "Regra de detecção SENTINELA"),
            "enabled": enabled,
            "event_type": rule.get("event_type"),
            "score": int(rule.get("score") or rule.get("risk") or rule.get("min_risk") or 0),
            "severity": rule.get("severity") or severity_from_score(rule.get("score") or rule.get("risk") or rule.get("min_risk") or 0),
            "threshold": rule.get("threshold", 1),
            "window_seconds": rule.get("window_seconds", 60),
            "mitre_id": rule.get("mitre_id") or mitre.get("id"),
            "mitre_name": rule.get("mitre_name") or mitre.get("name"),
            "mitre_tactic": rule.get("mitre_tactic") or mitre.get("tactic"),
            "tags": rule.get("tags", []),
            "correlation_key": rule.get("correlation_key", "source_ip"),
            "action": rule.get("action", "monitor"),
        })
    return normalized


def metric_rows(conn):
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT * FROM alertas
            WHERE tenant_id = %s AND ts >= NOW() - INTERVAL '24 hours'
            ORDER BY ts ASC
            LIMIT 1000
            """,
            (tenant_id(),),
        )
        rows = cur.fetchall() or []
        columns = [desc[0] for desc in getattr(cur, "description", None) or []]
    return [enrich_alert(row_to_dict(row, columns)) for row in rows]


def alert_search_document(alert):
    return {
        "id": str(alert.get("event_id") or alert.get("id") or ""),
        "tenant_id": alert.get("tenant_id") or DEFAULT_TENANT_ID,
        "correlation_id": alert.get("correlation_id") or alert.get("event_id"),
        "severity": alert.get("severity"),
        "status": alert.get("status"),
        "source": alert.get("source_ip") or alert.get("ip"),
        "rule_id": alert.get("internal_rule_id") or alert.get("rule_id"),
        "timestamp": alert.get("ts") or alert.get("timestamp"),
        "description": alert.get("human_summary") or alert.get("explanation"),
        "evidence": alert.get("correlation_reasons") or alert.get("risk_reasons") or [],
        "event_type": alert.get("event_type"),
        "mitre_id": alert.get("mitre_id"),
    }


def opensearch_request(path, method="GET", payload=None, timeout=1.5):
    url = f"{OPENSEARCH_URL}{path}"
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8") if payload is not None else None
    req = UrlRequest(url, data=data, method=method, headers={"Content-Type": "application/json"})
    with urlopen(req, timeout=timeout) as response:
        raw = response.read().decode("utf-8")
        return json.loads(raw) if raw else {}


def opensearch_available():
    if not ENABLE_OPENSEARCH:
        return False
    try:
        opensearch_request("/", timeout=0.8)
        return True
    except Exception:
        return False


def search_opensearch(query, limit, offset):
    if not opensearch_available():
        return None
    tenant = tenant_id()
    should = [
        {"match": {"description": query}},
        {"match": {"status": query}},
        {"match": {"severity": query}},
        {"match": {"source": query}},
        {"match": {"rule_id": query}},
        {"match": {"correlation_id": query}},
        {"match": {"event_type": query}},
        {"match": {"mitre_id": query}},
    ]
    payload = {
        "from": offset,
        "size": limit,
        "sort": [{"timestamp": {"order": "desc"}}],
        "query": {
            "bool": {
                "filter": [{"term": {"tenant_id.keyword": tenant}}],
                "must": [{"match_all": {}}] if not query else [{"bool": {"should": should, "minimum_should_match": 1}}],
            }
        },
    }
    result = opensearch_request(f"/{OPENSEARCH_INDEX_ALERTS}/_search", method="POST", payload=payload, timeout=2.0)
    hits = result.get("hits", {}).get("hits", [])
    return [{"_score": hit.get("_score"), **(hit.get("_source") or {})} for hit in hits]


def search_postgres(conn, query, limit, offset):
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT * FROM alertas
            WHERE tenant_id = %s
              AND (
                %s = ''
                OR COALESCE(source_ip, ip, '') ILIKE %s
                OR COALESCE(event_type, '') ILIKE %s
                OR COALESCE(status, '') ILIKE %s
                OR COALESCE(severity, '') ILIKE %s
                OR COALESCE(mitre_id, '') ILIKE %s
                OR COALESCE(correlation_id, '') ILIKE %s
                OR COALESCE(human_summary, explanation, '') ILIKE %s
              )
            ORDER BY ts DESC
            LIMIT %s OFFSET %s
            """,
            (tenant_id(), query, f"%{query}%", f"%{query}%", f"%{query}%", f"%{query}%", f"%{query}%", f"%{query}%", f"%{query}%", limit, offset),
        )
        rows = cur.fetchall() or []
        columns = [desc[0] for desc in getattr(cur, "description", None) or []]
    return [enrich_alert(row_to_dict(row, columns)) for row in rows]


def increment_bucket(mapping, key, amount=1):
    mapping[key or "N/D"] = mapping.get(key or "N/D", 0) + amount


def build_metrics_payload(conn):
    alerts = metric_rows(conn)
    incidents = fetch_persisted_incidents(conn)
    alerts_by_hour = {}
    score_by_time = []
    severity_by_period = {}
    by_ip = {}
    mitre_frequency = {}
    events_by_type = {}
    replay_vs_normal = {"replay": 0, "normal": 0}
    for alert in alerts:
        ts = alert.get("ts") or alert.get("timestamp")
        hour = local_datetime_label(ts)
        hour_key = hour[:13] + "h" if hour else "N/D"
        score = int(alert.get("threat_score") or 0)
        source_ip = alert.get("source_ip") or alert.get("ip") or "N/D"
        by_ip.setdefault(source_ip, {"source_ip": source_ip, "max_score": 0, "event_count": 0})
        by_ip[source_ip]["max_score"] = max(by_ip[source_ip]["max_score"], score)
        by_ip[source_ip]["event_count"] += 1
        increment_bucket(alerts_by_hour, hour_key)
        increment_bucket(severity_by_period, alert.get("severity"))
        increment_bucket(mitre_frequency, alert.get("mitre_id"))
        increment_bucket(events_by_type, alert.get("event_type"))
        replay_vs_normal["replay" if alert.get("is_replay_event") or alert.get("replay_id") else "normal"] += 1
        score_by_time.append({"timestamp": ts, "local_time": local_datetime_label(ts), "source_ip": source_ip, "score": score})
    incident_status = {}
    incident_severity = {}
    multi_ip_incidents = 0
    for incident in incidents:
        increment_bucket(incident_status, incident.get("status"))
        increment_bucket(incident_severity, incident.get("severity"))
        if len(json_list(incident.get("source_ips"))) > 1:
            multi_ip_incidents += 1
    top_ips = sorted(by_ip.values(), key=lambda item: (item["max_score"], item["event_count"]), reverse=True)
    linked_alert_count = count_linked_alerts(conn)
    return {
        "generated_at": now_iso(),
        "total_alerts": len(alerts),
        "total_incidents": len(incidents),
        "open_incidents": sum(1 for item in incidents if item.get("status") in OPEN_INCIDENT_STATUSES),
        "critical_incidents": sum(1 for item in incidents if item.get("severity") == "CRITICAL"),
        "alertas_por_hora": [{"hour": key, "count": value} for key, value in alerts_by_hour.items()],
        "score_por_tempo": score_by_time[-100:],
        "severidade_por_periodo": severity_by_period,
        "top_ips_por_score": top_ips[:5],
        "top_ips_por_frequencia": sorted(top_ips, key=lambda item: item["event_count"], reverse=True)[:5],
        "tecnicas_mitre": mitre_frequency,
        "incidentes_por_status": incident_status,
        "incidentes_por_severidade": incident_severity,
        "incidents_by_status": incident_status,
        "incidents_by_severity": incident_severity,
        "top_incidents_by_score": sorted(
            [{"incident_id": item["incident_id"], "title": item["title"], "max_score": item["max_score"], "severity": item["severity"]} for item in incidents],
            key=lambda item: item["max_score"],
            reverse=True,
        )[:5],
        "multi_ip_incidents": multi_ip_incidents,
        "top_mitre_techniques": mitre_frequency,
        "alerts_linked_to_incidents": linked_alert_count,
        "unlinked_alerts": max(0, len(alerts) - linked_alert_count),
        "reports_generated": 0,
        "eventos_por_tipo": events_by_type,
        "replay_vs_normal": replay_vs_normal,
    }


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
    risks = [24, 38, 58, 68, 82, 88, 94]

    alerts = []
    for index, stage in enumerate(stages):
        risk = risks[index]
        severity = severity_from_score(risk)
        current_ts = now_iso()
        mitre = mitre_for_alert({"event_type": stage["type"], "threat_intel_match": index >= 4, "simulated_block": stage["type"] == "RESPONSE"})
        target = {
            "target_host": "sentinela-dashboard",
            "target_ip": "127.0.0.1",
            "target_user": "admin" if index >= 2 else None,
            "target_service": "ssh" if index < 4 else "security",
            "target_port": 22 if index < 4 else 0,
            "target_container": "sentinela-lab",
            "target_application": "sentinela-soc",
            "environment": "local-demo",
            "asset_owner": "SOC Lab",
            "asset_criticality": "high" if index < 4 else "critical",
            "business_impact": "Possivel impacto em servico administrativo do laboratorio SOC.",
        }
        alert = {
            "id": str(uuid.uuid4()),
            "event_id": str(uuid.uuid4()),
            "tenant_id": tenant_id(),
            "ip": attacker_ip,
            "source_ip": attacker_ip,
            "status": severity,
            "risco": risk,
            "score_final": risk,
            "threat_score": risk,
            "severity": severity,
            "mitre_id": mitre["id"],
            "mitre_name": mitre["name"],
            "mitre_tactic": mitre["tactic"],
            "mitre_techniques": [mitre] if mitre.get("id") else [],
            "internal_rule_id": f"SENTINELA-DEMO-{index + 1}",
            "internal_rule_name": stage["stage"],
            "correlation_rule": "demo_attack_chain",
            "response_playbook": "PB-SOC-003-contencao-ip-suspeito" if index >= 4 else "PB-SOC-001-triagem-alerta",
            "detection_source": "dashboard_api_demo_seed",
            "alert_type": "incident_candidate" if index >= 2 else "alert",
            "score_breakdown": {
                "base_score": min(risk, 42),
                "sensitive_port_score": 8 if index < 4 else 0,
                "event_volume_score": min(18, index * 3),
                "time_window_score": 8 if index >= 3 else 0,
                "ioc_score": 22 if index >= 4 else 0,
                "asset_criticality_score": 16 if index >= 4 else 12,
                "mitre_correlation_score": 8 if mitre.get("id") else 0,
                "repeated_activity_score": 10 if index >= 4 else 0,
                "confidence_score": 12 if index >= 4 else 8,
                "final_score": risk,
            },
            "score_explanation": f"Score {risk}: porta sensivel 22, {index + 1} eventos na janela, {'IOC associado, ' if index >= 4 else ''}ativo de criticidade {target['asset_criticality']}.",
            **target,
            "recommended_action": "Recomendar bloqueio temporario da origem e abertura de ticket de investigacao" if index >= 4 else "Monitorar recorrencia e revisar logs do ativo afetado",
            "action_reason": "Acao recomendada por cadeia simulada, score e evidencias correlacionadas.",
            "execution_mode": "simulation",
            "execution_status": "not_executed",
            "execution_notes": "Ambiente local de demonstracao; nenhuma acao real foi executada.",
            "reasons": [stage["description"]],
            "correlation_reasons": ["demo_attack_timeline", stage["description"]],
            "event_count": index + 1,
            "replay_id": "api-demo",
            "is_replay_event": True,
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
                **target,
            },
            "stage": stage["stage"],
            "description": stage["description"],
            "severity": severity,
        }
        alert["human_summary"] = human_summary_for_alert(alert)
        alert["explanation"] = alert["human_summary"]
        alerts.append(alert)
    return alerts


def persist_demo_alerts(conn, alerts):
    tenant = tenant_id()
    with conn.cursor() as cur:
        cur.execute("DELETE FROM alertas WHERE is_demo = TRUE AND tenant_id = %s;", (tenant,))
    conn.commit()

    with conn.cursor() as cur:
        for alert in alerts:
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
                    correlation_key, correlation_reason, auto_response, action_soc,
                    simulated_block, is_demo, occurrence_count, first_seen, last_seen,
                    aggregated, ports, services, event_types, raw_event
                    , mitre_techniques, internal_rule_id, internal_rule_name,
                    correlation_rule, response_playbook, detection_source, alert_type,
                    score_breakdown, score_explanation, target_host, target_ip,
                    target_user, target_service, target_port, target_container,
                    target_application, environment, asset_owner, asset_criticality,
                    business_impact, recommended_action, action_reason, execution_mode,
                    execution_status, execution_notes, tenant_id
                )
                VALUES (
                    %(event_id)s, %(ip)s, %(status)s, %(risco)s, %(score_final)s,
                    %(ts)s, %(timestamp)s,
                    %(source_ip)s, %(threat_score)s, %(severity)s,
                    %(mitre_id)s, %(mitre_name)s, %(mitre_tactic)s,
                    %(human_summary)s, %(explanation)s,
                    %(reasons)s::jsonb, %(correlation_reasons)s::jsonb,
                    %(event_count)s, %(replay_id)s, %(is_replay_event)s,
                    %(service)s, %(port)s, %(event_type)s,
                    %(ip_event_count)s, %(risk_reasons)s::jsonb, %(threat_intel_match)s,
                    %(threat_category)s, %(threat_description)s,
                    %(threat_reputation_score)s, %(threat_source)s,
                    %(correlation_window_seconds)s, %(correlation_key)s,
                    %(correlation_reason)s, %(auto_response)s, %(action_soc)s,
                    %(simulated_block)s, %(is_demo)s, %(occurrence_count)s,
                    %(first_seen)s, %(last_seen)s, %(aggregated)s,
                    %(ports)s::jsonb, %(services)s::jsonb, %(event_types)s::jsonb,
                    %(raw_event)s::jsonb
                    , %(mitre_techniques)s::jsonb, %(internal_rule_id)s, %(internal_rule_name)s,
                    %(correlation_rule)s, %(response_playbook)s, %(detection_source)s, %(alert_type)s,
                    %(score_breakdown)s::jsonb, %(score_explanation)s, %(target_host)s, %(target_ip)s,
                    %(target_user)s, %(target_service)s, %(target_port)s, %(target_container)s,
                    %(target_application)s, %(environment)s, %(asset_owner)s, %(asset_criticality)s,
                    %(business_impact)s, %(recommended_action)s, %(action_reason)s, %(execution_mode)s,
                    %(execution_status)s, %(execution_notes)s, %(tenant_id)s
                )
                ON CONFLICT (event_id) DO UPDATE SET
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
                    **alert,
                    "source_ip": alert.get("source_ip") or alert.get("ip"),
                    "threat_score": alert.get("threat_score", alert.get("score_final", 0)),
                    "severity": alert.get("severity", "LOW"),
                    "mitre_id": alert.get("mitre_id"),
                    "mitre_name": alert.get("mitre_name"),
                    "mitre_tactic": alert.get("mitre_tactic"),
                    "human_summary": alert.get("human_summary"),
                    "explanation": alert.get("explanation"),
                    "reasons": json.dumps(alert.get("reasons", []), ensure_ascii=False),
                    "correlation_reasons": json.dumps(alert.get("correlation_reasons", []), ensure_ascii=False),
                    "event_count": alert.get("event_count", alert.get("ip_event_count", 0)),
                    "replay_id": alert.get("replay_id"),
                    "is_replay_event": bool(alert.get("is_replay_event", False)),
                    "risk_reasons": json.dumps(alert.get("risk_reasons", []), ensure_ascii=False),
                    "ports": json.dumps(alert.get("ports", []), ensure_ascii=False),
                    "services": json.dumps(alert.get("services", []), ensure_ascii=False),
                    "event_types": json.dumps(alert.get("event_types", []), ensure_ascii=False),
                    "raw_event": json.dumps(alert.get("raw_event", {}), ensure_ascii=False),
                    "mitre_techniques": json.dumps(alert.get("mitre_techniques", []), ensure_ascii=False),
                    "score_breakdown": json.dumps(alert.get("score_breakdown", {}), ensure_ascii=False),
                },
            )
    conn.commit()
    materialize_incidents(conn, alerts)


def summarize_incident(alerts):
    first = alerts[0] if alerts else {}
    attacker = first.get("ip", "--")
    return f"Ataque controlado detectado a partir do IP {attacker}. A correlação elevou o incidente para CRITICAL e registrou bloqueio simulado apenas, sem bloqueio real."


def refresh_prometheus_db_gauges(conn):
    with conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM alertas")
        ALERTS_GAUGE.set(int((cur.fetchone() or [0])[0] or 0))
        cur.execute("SELECT COUNT(*) FROM incidents")
        INCIDENTS_GAUGE.set(int((cur.fetchone() or [0])[0] or 0))
        cur.execute("SELECT COALESCE(severity, 'UNKNOWN'), COUNT(*) FROM incidents GROUP BY COALESCE(severity, 'UNKNOWN')")
        for severity, total in cur.fetchall() or []:
            INCIDENTS_SEVERITY_GAUGE.labels(severity=severity).set(int(total or 0))
        cur.execute("SELECT COUNT(*) FROM alertas WHERE ts >= NOW() - INTERVAL '1 minute'")
        EVENTS_PER_MINUTE_GAUGE.set(int((cur.fetchone() or [0])[0] or 0))
        cur.execute("SELECT COALESCE(tenant_id, %s), COUNT(*) FROM alertas WHERE ts >= NOW() - INTERVAL '24 hours' GROUP BY COALESCE(tenant_id, %s)", (DEFAULT_TENANT_ID, DEFAULT_TENANT_ID))
        for tenant, total in cur.fetchall() or []:
            PROCESSED_EVENTS_BY_TENANT.labels(tenant_id=tenant).set(int(total or 0))


@app.get("/health")
def health():
    return jsonify({"status": "ok", "service": "dashboard_api", "ready": SCHEMA_INITIALIZED})


@app.get("/auth/users")
@require_role("admin")
def list_users():
    return jsonify({"count": len(USERS), "data": [
        {"username": u["username"], "role": u["role"], "tenant_id": u["tenant_id"]}
        for u in USERS.values()
    ]})


@app.get("/auth/permissions")
@require_auth
def list_permissions():
    identity = getattr(request, "sentinela_identity", {})
    role = identity.get("role", "viewer")
    
    perms_map = {
        "admin": ["alert:read", "alert:write", "incident:read", "incident:write", "user:manage", "audit:read"],
        "analyst": ["alert:read", "alert:write", "incident:read", "incident:write"],
        "viewer": ["alert:read", "incident:read"]
    }
    
    return jsonify({
        "role": role,
        "permissions": perms_map.get(role, ["alert:read"])
    })


@app.get("/hunting")
@require_auth
def hunting():
    """
    Endpoint de busca avançada e Threat Hunting.
    Suporta agregações e filtros temporais.
    """
    REQUEST_COUNTER.labels(endpoint="hunting").inc()
    query = request.args.get("q", "").strip()
    range_val = request.args.get("range", "24h")
    limit, offset = pagination_params(default_limit=10, max_limit=100)
    
    if not opensearch_available():
        return jsonify({"error": "opensearch_unavailable", "message": "O backend de busca avançada não está disponível."}), 503

    # Mapeia range para filtro OpenSearch
    range_map = {"1h": "now-1h", "24h": "now-24h", "7d": "now-7d"}
    os_range = range_map.get(range_val, "now-24h")

    payload = {
        "from": offset,
        "size": limit,
        "sort": [{"timestamp": {"order": "desc"}}],
        "query": {
            "bool": {
                "filter": [
                    {"term": {"tenant_id.keyword": tenant_id()}},
                    {"range": {"timestamp": {"gte": os_range}}}
                ],
                "must": [{"query_string": {"query": query}}] if query else [{"match_all": {}}]
            }
        },
        "aggs": {
            "top_sources": {"terms": {"field": "source.keyword", "size": 10}},
            "top_techniques": {"terms": {"field": "mitre_id.keyword", "size": 10}},
            "severity_dist": {"terms": {"field": "severity.keyword"}},
            "timeline": {
                "date_histogram": {
                    "field": "timestamp",
                    "fixed_interval": "1h" if range_val != "1h" else "5m"
                }
            }
        }
    }

    try:
        result = opensearch_request(f"/{OPENSEARCH_INDEX_ALERTS}/_search", method="POST", payload=payload)
        return jsonify({
            "hits": [h["_source"] for h in result.get("hits", {}).get("hits", [])],
            "total": result.get("hits", {}).get("total", {}).get("value", 0),
            "aggregations": result.get("aggregations", {})
        })
    except Exception as exc:
        return jsonify({"error": "search_failed", "detail": str(exc)}), 500


@app.get("/hunting/pivot")
@require_auth
def hunting_pivot():
    """
    Busca todas as correlações de uma entidade específica (IP ou Usuário).
    """
    entity_type = request.args.get("type", "ip") # ip, user
    value = request.args.get("value")
    
    if not value:
        return jsonify({"error": "missing_value"}), 400
        
    conn = ensure_connection()
    try:
        with conn.cursor() as cur:
            if entity_type == "ip":
                query = "SELECT * FROM alertas WHERE (source_ip = %s OR ip = %s) AND tenant_id = %s ORDER BY ts DESC LIMIT 100"
                params = (value, value, tenant_id())
            else:
                query = "SELECT * FROM alertas WHERE (target_user = %s OR raw_event->>'username' = %s) AND tenant_id = %s ORDER BY ts DESC LIMIT 100"
                params = (value, value, tenant_id())
                
            cur.execute(query, params)
            rows = cur.fetchall()
            cols = [d[0] for d in cur.description]
            alerts = [enrich_alert(row_to_dict(row, cols)) for row in rows]
            
            return jsonify({
                "entity": {"type": entity_type, "value": value},
                "count": len(alerts),
                "related_alerts": alerts
            })
    finally:
        conn.close()


@app.get("/response/actions")
@require_auth
def list_response_actions():
    """
    Lista as ações de resposta automática executadas ou simuladas.
    """
    REQUEST_COUNTER.labels(endpoint="response_actions").inc()
    limit, offset = pagination_params(default_limit=50, max_limit=200)
    conn = ensure_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, action_id, alert_id, tenant_id, action_type, mode, target_entity, reason, status, created_at
                FROM response_actions
                WHERE tenant_id = %s
                ORDER BY created_at DESC
                LIMIT %s OFFSET %s
                """,
                (tenant_id(), limit, offset)
            )
            rows = cur.fetchall()
            cols = [d[0] for d in cur.description]
            return jsonify({
                "count": len(rows),
                "data": [row_to_dict(r, cols) for r in rows]
            })
    finally:
        conn.close()


@app.get("/response/actions/<alert_id>")
@require_auth
def get_alert_response_actions(alert_id):
    """
    Retorna as ações de resposta associadas a um alerta específico.
    """
    REQUEST_COUNTER.labels(endpoint="alert_response_actions").inc()
    conn = ensure_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT * FROM response_actions
                WHERE alert_id = %s AND tenant_id = %s
                """,
                (alert_id, tenant_id())
            )
            rows = cur.fetchall()
            cols = [d[0] for d in cur.description]
            return jsonify({
                "alert_id": alert_id,
                "actions": [row_to_dict(r, cols) for r in rows]
            })
    finally:
        conn.close()


@app.get("/ready")
def ready():
    try:
        conn = ensure_connection()
        with conn.cursor() as cur:
            cur.execute("SELECT 1")
            cur.fetchone()
        conn.close()
        return jsonify({"status": "ok", "dependencies": {"postgres": "ok"}, "ready": True})
    except Exception as exc:
        return jsonify({"status": "error", "error": str(exc)}), 503


@app.get("/metrics")
@require_auth
def metrics():
    REQUEST_COUNTER.labels(endpoint="metrics").inc()
    conn = ensure_connection()
    try:
        refresh_prometheus_db_gauges(conn)
    finally:
        conn.close()
    return app.response_class(generate_latest(REGISTRY), mimetype=CONTENT_TYPE_LATEST)


@app.get("/metrics/prometheus")
@require_auth
def metrics_prometheus():
    REQUEST_COUNTER.labels(endpoint="metrics_prometheus").inc()
    conn = ensure_connection()
    try:
        refresh_prometheus_db_gauges(conn)
    finally:
        conn.close()
    return app.response_class(generate_latest(REGISTRY), mimetype=CONTENT_TYPE_LATEST)


@app.get("/rules")
@require_auth
def rules():
    REQUEST_COUNTER.labels(endpoint="rules").inc()
    payload = read_rules_config()
    return jsonify({"count": len(payload["rules"]), **payload})


@app.post("/auth/token")
def auth_token():
    REQUEST_COUNTER.labels(endpoint="auth_token").inc()
    payload = request.get_json(silent=True) or {}
    identity = None
    if payload.get("username") or payload.get("password"):
        identity = authenticate_user(payload.get("username"), payload.get("password"))
        if not identity:
            write_audit(
                action="login_failed",
                resource_type="auth",
                resource_id=payload.get("username") or "unknown",
                success=False,
                identity={"sub": payload.get("username") or "unknown", "role": None, "tenant_id": DEFAULT_TENANT_ID},
                metadata={"reason": "invalid_credentials"},
            )
            return jsonify({"error": "invalid_credentials"}), 401
    elif ENABLE_AUTH:
        identity = current_identity()
        if not identity:
            write_audit(action="login_failed", resource_type="auth", resource_id="token", success=False, metadata={"reason": "unauthorized"})
            return jsonify({"error": "unauthorized"}), 401
    else:
        identity = {"sub": SENTINELA_USER, "role": "admin", "tenant_id": DEFAULT_TENANT_ID}
    access_ttl = ACCESS_TOKEN_EXPIRE_MINUTES * 60
    refresh_ttl = REFRESH_TOKEN_EXPIRE_MINUTES * 60
    access_token = create_jwt(subject=identity["sub"], ttl_seconds=access_ttl, role=identity["role"], tenant_id=identity["tenant_id"], token_use="access")
    refresh_token = create_jwt(subject=identity["sub"], ttl_seconds=refresh_ttl, role=identity["role"], tenant_id=identity["tenant_id"], token_use="refresh")
    write_audit(action="login_success", resource_type="auth", resource_id=identity["sub"], success=True, identity=identity)
    return jsonify({
        "token": access_token,
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "Bearer",
        "expires_in": access_ttl,
        "refresh_expires_in": refresh_ttl,
        "user": identity,
    })


@app.post("/auth/refresh")
def auth_refresh():
    REQUEST_COUNTER.labels(endpoint="auth_refresh").inc()
    payload = request.get_json(silent=True) or {}
    raw_token = (payload.get("refresh_token") or "").strip()
    if not raw_token:
        bearer = request.headers.get("Authorization", "")
        raw_token = bearer.split(" ", 1)[1].strip() if bearer.startswith("Bearer ") else ""
    decoded = decode_jwt(raw_token) if raw_token else None
    if not decoded or decoded.get("token_use") != "refresh":
        write_audit(action="refresh_failed", resource_type="auth", resource_id=decoded.get("sub") if decoded else "unknown", success=False, metadata={"reason": "invalid_refresh_token"})
        return jsonify({"error": "invalid_refresh_token"}), 401
    identity = {"sub": decoded.get("sub"), "role": decoded.get("role", "viewer"), "tenant_id": decoded.get("tenant_id") or DEFAULT_TENANT_ID}
    access_ttl = ACCESS_TOKEN_EXPIRE_MINUTES * 60
    refresh_ttl = REFRESH_TOKEN_EXPIRE_MINUTES * 60
    access_token = create_jwt(subject=identity["sub"], ttl_seconds=access_ttl, role=identity["role"], tenant_id=identity["tenant_id"], token_use="access")
    refresh_token = create_jwt(subject=identity["sub"], ttl_seconds=refresh_ttl, role=identity["role"], tenant_id=identity["tenant_id"], token_use="refresh")
    write_audit(action="refresh_token", resource_type="auth", resource_id=identity["sub"], success=True, identity=identity)
    return jsonify({
        "token": access_token,
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "Bearer",
        "expires_in": access_ttl,
        "refresh_expires_in": refresh_ttl,
        "user": identity,
    })


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


@app.get("/alerts")
@require_auth
def alerts_contract():
    REQUEST_COUNTER.labels(endpoint="alerts").inc()
    return alertas()


@app.get("/historico")
@require_auth
def historico():
    REQUEST_COUNTER.labels(endpoint="historico").inc()
    conn = ensure_connection()
    try:
        return fetch_alerts(conn)
    finally:
        conn.close()


@app.get("/scores")
@require_auth
def scores():
    REQUEST_COUNTER.labels(endpoint="scores").inc()
    conn = ensure_connection()
    try:
        return fetch_ip_scores(conn)
    finally:
        conn.close()


@app.get("/demo/summary")
@require_auth
def demo_summary():
    REQUEST_COUNTER.labels(endpoint="demo_summary").inc()
    conn = ensure_connection()
    try:
        return fetch_demo_summary(conn)
    finally:
        conn.close()


@app.get("/timeline")
@require_auth
def timeline():
    REQUEST_COUNTER.labels(endpoint="timeline").inc()
    source_ip = (request.args.get("source_ip") or "").strip() or None
    conn = ensure_connection()
    try:
        alerts = fetch_alert_rows(conn, source_ip=source_ip, limit=300)
        return jsonify({"source_ip": source_ip, "count": len(alerts), "data": build_timeline(alerts)})
    finally:
        conn.close()


@app.get("/metrics/timeline")
@require_auth
def metrics_timeline():
    REQUEST_COUNTER.labels(endpoint="metrics_timeline").inc()
    range_value = request.args.get("range", "24h")
    source_ip = (request.args.get("source_ip") or "").strip() or None
    conn = ensure_connection()
    try:
        alerts = fetch_alert_rows(conn, source_ip=source_ip, limit=1000)
        data = build_timeline_buckets(alerts, range_value)
        return jsonify({
            "range": range_value,
            "source_ip": source_ip,
            "bucket_strategy": "5m" if range_value == "1h" else ("1h" if range_value == "24h" else "auto"),
            "count": sum(item.get("count", 0) for item in data),
            "source_count": len(alerts),
            "data": data,
        })
    finally:
        conn.close()


@app.get("/metrics/summary")
@require_auth
def metrics_summary():
    REQUEST_COUNTER.labels(endpoint="metrics_summary").inc()
    conn = ensure_connection()
    try:
        return jsonify(build_metrics_payload(conn))
    finally:
        conn.close()


@app.get("/search")
@require_auth
def search():
    REQUEST_COUNTER.labels(endpoint="search").inc()
    query = (request.args.get("q") or "").strip()[:120]
    limit, offset = pagination_params(default_limit=50, max_limit=200)
    set_trace_attrs(correlation_id=getattr(request, "_sentinela_correlation_id", None), tenant_id=tenant_id(), search_query=query)
    conn = ensure_connection()
    try:
        search_backend = "postgres"
        data = None
        try:
            data = search_opensearch(query, limit, offset)
            if data is not None:
                search_backend = "opensearch"
        except Exception as exc:
            log_json("WARN", "OpenSearch indisponivel; usando fallback Postgres", error=str(exc), tenant_id=tenant_id())
        if data is None:
            data = search_postgres(conn, query, limit, offset)
        return jsonify({"query": query, "backend": search_backend, "count": len(data), "limit": limit, "offset": offset, "data": data})
    finally:
        conn.close()


@app.get("/audit")
@require_role("admin")
def audit_logs():
    REQUEST_COUNTER.labels(endpoint="audit").inc()
    limit, _ = pagination_params(default_limit=100, max_limit=500)
    action = request.args.get("action")
    resource_type = request.args.get("resource_type")
    filters = ["tenant_id = %s"]
    params = [tenant_id()]
    if action:
        filters.append("action = %s")
        params.append(action)
    if resource_type:
        filters.append("resource_type = %s")
        params.append(resource_type)
    params.append(limit)
    conn = ensure_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                f"""
                SELECT id, timestamp, tenant_id, actor_user, actor_role, action,
                       resource_type, resource_id, correlation_id, source_ip,
                       success, metadata_json
                FROM audit_logs
                WHERE {' AND '.join(filters)}
                ORDER BY timestamp DESC
                LIMIT %s
                """,
                tuple(params),
            )
            rows = cur.fetchall() or []
            columns = [desc[0] for desc in getattr(cur, "description", None) or []]
        return jsonify({"count": len(rows), "limit": limit, "data": [row_to_dict(row, columns) for row in rows]})
    finally:
        conn.close()


if sock:
    @sock.route("/ws/alerts")
    def ws_alerts(ws):
        last_seen_id = None
        token = (request.args.get("token") or "").strip()
        payload = decode_jwt(token) if token else None
        identity = (
            {"sub": payload.get("sub"), "role": payload.get("role", "viewer"), "tenant_id": payload.get("tenant_id") or DEFAULT_TENANT_ID}
            if payload and payload.get("token_use") == "access" else current_identity()
        )
        if not identity:
            ws.send(json.dumps({"type": "error", "error": "unauthorized"}))
            return
        WEBSOCKET_CONNECTIONS.inc()
        set_trace_attrs(tenant_id=identity.get("tenant_id"), websocket="alerts")
        while True:
            try:
                conn = ensure_connection()
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT * FROM alertas
                        WHERE tenant_id = %s
                        ORDER BY ts DESC
                        LIMIT 1
                        """,
                        (identity.get("tenant_id") or DEFAULT_TENANT_ID,),
                    )
                    row = cur.fetchone()
                    columns = [desc[0] for desc in getattr(cur, "description", None) or []]
                conn.close()
                if row:
                    alert = enrich_alert(row_to_dict(row, columns))
                    current_id = str(alert.get("event_id") or alert.get("id"))
                    if current_id and current_id != last_seen_id:
                        last_seen_id = current_id
                        ws.send(json.dumps({"type": "alert", "data": alert}, ensure_ascii=False, default=str))
                time.sleep(2)
            except Exception as exc:
                try:
                    ws.send(json.dumps({"type": "error", "error": str(exc)}))
                except Exception:
                    WEBSOCKET_CONNECTIONS.dec()
                    return
                time.sleep(2)


@app.get("/campaigns")
@require_auth
def campaigns():
    REQUEST_COUNTER.labels(endpoint="campaigns").inc()
    conn = ensure_connection()
    try:
        alerts = fetch_alert_rows(conn, limit=1000)
        data = build_campaigns(alerts)
        return jsonify({"count": len(data), "data": data})
    finally:
        conn.close()


@app.get("/investigation/ip/<path:source_ip>")
@require_auth
def investigate_ip(source_ip):
    REQUEST_COUNTER.labels(endpoint="investigation_ip").inc()
    conn = ensure_connection()
    try:
        investigation = build_investigation(conn, source_ip)
        if not investigation:
            return jsonify({"error": "not_found", "source_ip": source_ip}), 404
        return jsonify(investigation)
    finally:
        conn.close()


@app.get("/incidents")
@require_auth
def incidents():
    REQUEST_COUNTER.labels(endpoint="incidents").inc()
    limit, offset = pagination_params(default_limit=100, max_limit=500)
    conn = ensure_connection()
    try:
        alerts = fetch_alert_rows(conn, limit=500)
        materialize_incidents(conn, alerts)
        data = fetch_persisted_incidents(conn, limit=limit, offset=offset)
        return jsonify({"count": len(data), "total": count_persisted_incidents(conn), "limit": limit, "offset": offset, "data": data})
    finally:
        conn.close()


@app.get("/incidents/<incident_id>")
@require_auth
def incident_detail(incident_id):
    REQUEST_COUNTER.labels(endpoint="incident_detail").inc()
    conn = ensure_connection()
    try:
        alerts = []
        incident = enrich_incident_detail(conn, fetch_incident_by_id(conn, incident_id))
        if not incident:
            alerts = fetch_alert_rows(conn, limit=500)
            materialize_incidents(conn, alerts)
            incident = enrich_incident_detail(conn, fetch_incident_by_id(conn, incident_id))
        if not incident:
            for item in build_incidents(alerts, fetch_incident_overrides(conn)):
                if item["incident_id"] == incident_id:
                    incident = item
                    break
        if not incident:
            return jsonify({"error": "not_found", "incident_id": incident_id}), 404
        return jsonify(incident)
    finally:
        conn.close()


@app.patch("/incidents/<incident_id>")
@require_role("admin", "analyst")
def update_incident(incident_id):
    REQUEST_COUNTER.labels(endpoint="incident_update").inc()
    payload = request.get_json(silent=True) or {}
    allowed = {"status", "analyst_notes", "assigned_to", "soc_action"}
    updates = {key: payload[key] for key in allowed if key in payload}
    if not updates:
        return jsonify({"error": "empty_update", "allowed_fields": sorted(allowed)}), 400
    if "status" in updates:
        updates["status"] = str(updates["status"]).strip().upper()
        if updates["status"] not in ALLOWED_INCIDENT_STATUSES:
            return jsonify({"error": "invalid_status", "allowed_statuses": sorted(ALLOWED_INCIDENT_STATUSES)}), 400
    for key in ("analyst_notes", "assigned_to", "soc_action"):
        if key in updates:
            updates[key] = str(updates[key])[:2000]

    conn = ensure_connection()
    try:
        alerts = fetch_alert_rows(conn, limit=500)
        materialize_incidents(conn, alerts)
        existing = fetch_incident_by_id(conn, incident_id)
        if not existing:
            for item in build_incidents(alerts, fetch_incident_overrides(conn)):
                if item["incident_id"] == incident_id:
                    existing = item
                    break
        if not existing:
            return jsonify({"error": "not_found", "incident_id": incident_id}), 404
        with conn.cursor() as cur:
            for field, new_value in updates.items():
                old_value = existing.get(field)
                if str(old_value or "") == str(new_value or ""):
                    continue
                cur.execute(
                    """
                    INSERT INTO incident_audit_log (incident_id, field_changed, old_value, new_value, changed_by, changed_at)
                    VALUES (%s, %s, %s, %s, %s, NOW())
                    """,
                    (incident_id, field, str(old_value or ""), str(new_value or ""), (current_identity() or {}).get("sub", SENTINELA_USER)),
                )
            cur.execute(
                """
                INSERT INTO incidents (
                    incident_id, title, status, severity, max_score, primary_source_ip,
                    source_ips, first_seen, last_seen, event_count, human_summary,
                    analyst_notes, assigned_to, soc_action, created_at, updated_at
                    , tenant_id
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb, %s, %s, %s, %s, %s, %s, %s, NOW(), NOW(), %s)
                ON CONFLICT (incident_id) DO UPDATE SET
                    status = EXCLUDED.status,
                    analyst_notes = EXCLUDED.analyst_notes,
                    assigned_to = EXCLUDED.assigned_to,
                    soc_action = EXCLUDED.soc_action,
                    updated_at = NOW()
                """,
                (
                    incident_id,
                    existing.get("title", f"Incidente {incident_id}"),
                    updates.get("status", existing.get("status", "NEW")),
                    existing.get("severity", "LOW"),
                    existing.get("max_score", 0),
                    existing.get("source_ip") or existing.get("primary_source_ip"),
                    json.dumps(existing.get("source_ips") or [existing.get("source_ip")], ensure_ascii=False),
                    existing.get("first_seen"),
                    existing.get("last_seen"),
                    existing.get("event_count", 0),
                    existing.get("human_summary", ""),
                    updates.get("analyst_notes", existing.get("analyst_notes", "")),
                    updates.get("assigned_to", existing.get("assigned_to", "")),
                    updates.get("soc_action", existing.get("soc_action", "investigação simulada")),
                    tenant_id(),
                ),
            )
        conn.commit()
        refreshed = enrich_incident_detail(conn, fetch_incident_by_id(conn, incident_id)) or {**existing, **updates}
        write_audit(
            action="incident_updated",
            resource_type="incident",
            resource_id=incident_id,
            success=True,
            metadata={"fields": sorted(updates.keys())},
        )
        return jsonify(refreshed), 200
    finally:
        conn.close()


@app.get("/incidents/<incident_id>/alerts")
@require_auth
def incident_alerts(incident_id):
    REQUEST_COUNTER.labels(endpoint="incident_alerts").inc()
    limit, offset = pagination_params(default_limit=100, max_limit=500)
    conn = ensure_connection()
    try:
        if not fetch_incident_by_id(conn, incident_id):
            materialize_incidents(conn, fetch_alert_rows(conn, limit=500))
        alerts = fetch_incident_alerts(conn, incident_id, limit=limit, offset=offset)
        return jsonify({"incident_id": incident_id, "count": len(alerts), "total": count_incident_alerts(conn, incident_id), "limit": limit, "offset": offset, "data": alerts})
    finally:
        conn.close()


@app.get("/incidents/<incident_id>/audit")
@require_auth
def incident_audit(incident_id):
    REQUEST_COUNTER.labels(endpoint="incident_audit").inc()
    conn = ensure_connection()
    try:
        audit = fetch_incident_audit(conn, incident_id)
        return jsonify({"incident_id": incident_id, "count": len(audit), "data": audit})
    finally:
        conn.close()


def markdown_for_incident(incident):
    mitre_lines = "\n".join(
        f"- {m.get('id')} - {m.get('name')} ({m.get('tactic')})"
        for m in incident.get("mitre_techniques", [])
        if isinstance(m, dict)
    ) or "- N/D"
    alert_lines = "\n".join(
        f"- {item.get('local_time') or item.get('timestamp')} | {item.get('source_ip') or 'N/D'} | {item.get('event_type')} | {item.get('severity')} | score {item.get('score')} | {item.get('mitre_id') or 'N/D'}"
        for item in incident.get("related_alerts", [])[:120]
    ) or "- N/D"
    timeline_lines = "\n".join(
        f"- {item.get('local_time') or item.get('timestamp')} | {item.get('phase')} | {item.get('source_ip') or 'N/D'} | {item.get('event_type')} | {item.get('severity')} | score {item.get('score')} | {item.get('mitre_id') or 'N/D'} | {item.get('stage')}"
        for item in incident.get("timeline", [])
    ) or "- N/D"
    recommendations = "\n".join(f"- {item}" for item in incident.get("recommendations", default_recommendations()))
    source_ips = ", ".join(incident.get("source_ips") or [incident.get("source_ip") or "N/D"])
    reasons = ", ".join(incident.get("correlation_reasons") or []) or "N/D"
    services = ", ".join(incident.get("services") or []) or "N/D"
    usernames = ", ".join(incident.get("usernames") or []) or "N/D"
    return f"""# Relatório de Incidente - {SENTINELA_VERSION}

- Gerado em: {local_datetime_label(now_iso())}
- ID do incidente: {incident['incident_id']}
- Título: {incident['title']}
- Status: {incident['status']}
- Responsável: {incident.get('assigned_to') or 'N/D'}
- IP principal: {incident.get('source_ip') or incident.get('primary_source_ip') or 'N/D'}
- IPs relacionados: {source_ips}
- Alvos envolvidos: {incident.get('destination_ip') or 'N/D'} | usuários: {usernames} | serviços: {services}
- Severidade: {incident['severity']}
- Score máximo: {incident['max_score']}
- Primeiro visto: {incident['first_seen']}
- Último visto: {incident['last_seen']}
- Total de eventos: {incident['event_count']}

## Sumário Executivo

{incident.get('human_summary') or incident_human_summary(incident)}

## Técnicas MITRE ATT&CK

{mitre_lines}

## Evidências / Alertas Relacionados

{alert_lines}

## Linha do Tempo do Ataque

{timeline_lines}

## Reasons de Correlação

{reasons}

## Ações SOC Simuladas

- {incident.get('soc_action') or 'investigação simulada'}

## Notas do Analista

{incident.get('analyst_notes') or 'Sem notas registradas.'}

## Recomendações Defensivas

{recommendations}

## Observação Ética e de Segurança

Nenhum bloqueio real, ataque real, firewall real ou iptables foi executado. Todas as ações são simuladas para fins educacionais e de demonstração.
"""


def pdf_escape(text):
    return str(text).replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def simple_pdf_bytes(title, lines):
    pages = []
    current = []
    for line in lines:
        wrapped = [line[i:i + 96] for i in range(0, len(line), 96)] or [""]
        for item in wrapped:
            current.append(item)
            if len(current) >= 42:
                pages.append(current)
                current = []
    if current:
        pages.append(current)
    objects = ["<< /Type /Catalog /Pages 2 0 R >>"]
    page_refs = []
    content_objects = []
    font_object_number = 3 + len(pages) * 2
    for index, page_lines in enumerate(pages):
        page_object_number = 3 + index * 2
        content_object_number = page_object_number + 1
        page_refs.append(f"{page_object_number} 0 R")
        stream_parts = ["BT", "/F1 16 Tf", "50 790 Td", f"({pdf_escape(title)}) Tj", "/F1 10 Tf", "0 -22 Td"]
        for line in page_lines:
            stream_parts.append(f"({pdf_escape(line)}) Tj")
            stream_parts.append("0 -16 Td")
        stream_parts.append("ET")
        stream = "\n".join(stream_parts)
        objects.append(f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 {font_object_number} 0 R >> >> /Contents {content_object_number} 0 R >>")
        objects.append(f"<< /Length {len(stream.encode('latin-1', errors='replace'))} >>\nstream\n{stream}\nendstream")
        content_objects.append(content_object_number)
    objects.insert(1, f"<< /Type /Pages /Kids [{' '.join(page_refs)}] /Count {len(page_refs)} >>")
    objects.append("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    pdf = "%PDF-1.4\n"
    offsets = [0]
    for number, obj in enumerate(objects, start=1):
        offsets.append(len(pdf.encode("latin-1", errors="replace")))
        pdf += f"{number} 0 obj\n{obj}\nendobj\n"
    xref = len(pdf.encode("latin-1", errors="replace"))
    pdf += f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n"
    for offset in offsets[1:]:
        pdf += f"{offset:010d} 00000 n \n"
    pdf += f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n"
    return pdf.encode("latin-1", errors="replace")


@app.get("/reports/incident/<incident_id>.md")
@require_auth
def incident_report(incident_id):
    REQUEST_COUNTER.labels(endpoint="incident_report").inc()
    conn = ensure_connection()
    try:
        alerts = []
        incident = enrich_incident_detail(conn, fetch_incident_by_id(conn, incident_id))
        if not incident:
            alerts = fetch_alert_rows(conn, limit=500)
            materialize_incidents(conn, alerts)
            incident = enrich_incident_detail(conn, fetch_incident_by_id(conn, incident_id))
        if not incident:
            for item in build_incidents(alerts, fetch_incident_overrides(conn)):
                if item["incident_id"] == incident_id:
                    incident = item
                    break
        if not incident:
            return Response(f"# Incidente {incident_id}\n\nIncidente não encontrado.\n", mimetype="text/markdown", status=404)
        return Response(markdown_for_incident(incident), mimetype="text/markdown")
    finally:
        conn.close()


@app.get("/reports/incident/<incident_id>.pdf")
@require_auth
def incident_report_pdf(incident_id):
    REQUEST_COUNTER.labels(endpoint="incident_report_pdf").inc()
    conn = ensure_connection()
    try:
        alerts = []
        incident = enrich_incident_detail(conn, fetch_incident_by_id(conn, incident_id))
        if not incident:
            alerts = fetch_alert_rows(conn, limit=500)
            materialize_incidents(conn, alerts)
            incident = enrich_incident_detail(conn, fetch_incident_by_id(conn, incident_id))
        if not incident:
            for item in build_incidents(alerts, fetch_incident_overrides(conn)):
                if item["incident_id"] == incident_id:
                    incident = item
                    break
        if not incident:
            return Response(b"%PDF-1.4\n% Incidente nao encontrado\n", mimetype="application/pdf", status=404)
        markdown = markdown_for_incident(incident)
        lines = [line.strip() for line in markdown.splitlines()]
        pdf = simple_pdf_bytes(f"Relatorio de Incidente - {SENTINELA_VERSION}", lines)
        return Response(
            pdf,
            mimetype="application/pdf",
            headers={"Content-Disposition": f"inline; filename={incident_id}.pdf"},
        )
    finally:
        conn.close()


@app.post("/demo/simulate-attack")
@require_role("admin", "analyst")
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
                "mitre_id": alert["mitre_id"],
                "mitre_name": alert["mitre_name"],
                "mitre_tactic": alert["mitre_tactic"],
                "human_summary": alert["human_summary"],
                "explanation": alert["explanation"],
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
                "mitre_techniques": alert.get("mitre_techniques", []),
                "internal_rule_id": alert.get("internal_rule_id"),
                "internal_rule_name": alert.get("internal_rule_name"),
                "correlation_rule": alert.get("correlation_rule"),
                "response_playbook": alert.get("response_playbook"),
                "detection_source": alert.get("detection_source"),
                "alert_type": alert.get("alert_type"),
                "score_breakdown": alert.get("score_breakdown"),
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
                "execution_mode": alert.get("execution_mode"),
                "execution_status": alert.get("execution_status"),
                "execution_notes": alert.get("execution_notes"),
                "is_demo": True,
            }
            payload_alerts.append(item)
            timeline.append(
                {
                    "timestamp": item["timestamp"],
                    "ip": item["ip"],
                    "event_type": item["event_type"],
                    "severity": item["severity"],
                    "score": item["risk"],
                    "description": item["description"],
                    "stage": item["stage"],
                    "mitre_id": item["mitre_id"],
                    "mitre_name": item["mitre_name"],
                    "mitre_tactic": item["mitre_tactic"],
                    "replay_id": alert.get("replay_id"),
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
        write_audit(
            action="demo_ingestion_executed",
            resource_type="demo",
            resource_id="simulate-attack",
            success=True,
            metadata={"events_created": len(payload_alerts), "primary_ip": primary["ip"]},
        )
        return jsonify(response), 201
    finally:
        conn.close()


@app.route("/response/actions/<action_id>/approve", methods=["POST"])
@require_auth
def approve_response_action(action_id):
    tenant = tenant_id()
    conn = None
    try:
        conn = ensure_connection()
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE response_actions
                SET status = 'executed', metadata_json = metadata_json || '{"approved_at": "' || NOW() || '", "approved_by": "admin"}'::jsonb
                WHERE action_id = %s AND tenant_id = %s AND status = 'pending_approval'
                RETURNING *
                """,
                (action_id, tenant),
            )
            row = cur.fetchone()
            if not row:
                return jsonify({"error": "action_not_found_or_not_pending"}), 404
            
            conn.commit()
            return jsonify({"status": "success", "message": "Action approved and marked for execution"})
    finally:
        if conn:
            conn.close()

@app.route("/response/actions/<action_id>/reject", methods=["POST"])
@require_auth
def reject_response_action(action_id):
    tenant = tenant_id()
    conn = None
    try:
        conn = ensure_connection()
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE response_actions
                SET status = 'rejected', metadata_json = metadata_json || '{"rejected_at": "' || NOW() || '", "rejected_by": "admin"}'::jsonb
                WHERE action_id = %s AND tenant_id = %s AND status = 'pending_approval'
                RETURNING *
                """,
                (action_id, tenant),
            )
            row = cur.fetchone()
            if not row:
                return jsonify({"error": "action_not_found_or_not_pending"}), 404
            
            conn.commit()
            return jsonify({"status": "success", "message": "Action rejected"})
    finally:
        if conn:
            conn.close()

@app.route("/campaigns/heatmap", methods=["GET"])
@require_auth
def get_mitre_heatmap():
    tenant = tenant_id()
    conn = None
    try:
        conn = ensure_connection()
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT mitre_tactic, COUNT(*) as frequency
                FROM alertas
                WHERE tenant_id = %s AND mitre_tactic IS NOT NULL
                GROUP BY mitre_tactic
                ORDER BY frequency DESC
                """,
                (tenant,),
            )
            rows = cur.fetchall() or []
        
        heatmap = {row[0]: int(row[1]) for row in rows}
        return jsonify(heatmap)
    finally:
        if conn:
            conn.close()

@app.route("/saas/tenants", methods=["POST"])
@require_auth
def saas_onboarding():
    if not is_admin():
        return jsonify({"error": "forbidden"}), 403
    
    data = request.json
    tenant_id = data.get("tenant_id")
    name = data.get("name")
    plan = data.get("plan_id", "free")
    
    if not tenant_id or not name:
        return jsonify({"error": "missing_fields"}), 400
        
    api_key = f"sk_{uuid.uuid4().hex}"
    
    conn = None
    try:
        conn = get_connection()
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO tenants (tenant_id, name, plan_id, api_key)
                VALUES (%s, %s, %s, %s)
                RETURNING *
                """,
                (tenant_id, name, plan, api_key)
            )
            conn.commit()
            return jsonify({"status": "success", "api_key": api_key, "tenant_id": tenant_id})
    except Exception as e:
        if conn: conn.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        if conn: conn.close()

@app.route("/saas/billing", methods=["GET"])
@require_auth
def get_billing():
    tenant = tenant_id()
    conn = None
    try:
        conn = get_connection()
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT b.*, p.price_monthly 
                FROM billing_records b
                JOIN tenants t ON b.tenant_id = t.tenant_id
                JOIN plans p ON t.plan_id = p.plan_id
                WHERE b.tenant_id = %s
                ORDER BY b.billing_period DESC
                """,
                (tenant,)
            )
            rows = cur.fetchall() or []
            columns = [desc[0] for desc in getattr(cur, "description", None) or []]
            return jsonify([row_to_dict(row, columns) for row in rows])
    finally:
        if conn: conn.close()

def is_admin():
    # Helper simples para checar role admin
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        try:
            token = auth_header.split(" ")[1]
            # (Em producao validaria o JWT e pegaria a role)
            return "admin" in token or ENABLE_AUTH is False
        except: return False
    return False

try:
    from neo4j import GraphDatabase
except ImportError:
    GraphDatabase = None

NEO4J_URI = os.getenv("NEO4J_URI", "bolt://neo4j:7687")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "sentinela-graph")

def get_graph_driver():
    if not GraphDatabase: return None
    try:
        return GraphDatabase.driver(NEO4J_URI, auth=("neo4j", NEO4J_PASSWORD))
    except: return None

@app.route("/graph/attack-paths", methods=["GET"])
@require_auth
def get_attack_paths():
    tenant = tenant_id()
    driver = get_graph_driver()
    if not driver: return jsonify({"error": "neo4j_not_available"}), 503
    
    with driver.session() as session:
        # Encontra caminhos entre IPs externos e Usuários/Hosts do tenant
        result = session.run(
            """
            MATCH path = (ip:IP)-[r:AUTHENTICATED_AS|EXECUTED_ON|CLOUD_API_CALL*1..3]->(target)
            WHERE ip.tenant = $tid
            RETURN nodes(path) as nodes, relationships(path) as rels
            LIMIT 10
            """,
            tid=tenant
        )
        paths = []
        for record in result:
            paths.append({
                "nodes": [dict(n) for n in record["nodes"]],
                "relationships": [type(r) for r in record["rels"]]
            })
        return jsonify(paths)

@app.route("/graph/analytics/blast-radius", methods=["GET"])
@require_auth
def get_graph_ml_analytics():
    """
    Graph ML: Calcula a centralidade das entidades para determinar o raio de impacto potencial.
    """
    tenant = tenant_id()
    driver = get_graph_driver()
    if not driver: return jsonify([])
    
    with driver.session() as session:
        # Algoritmo de Centralidade (simulado via query de conectividade direta)
        result = session.run(
            """
            MATCH (n)
            WHERE n.tenant = $tid AND (n:User OR n:Host OR n:CloudAccount)
            WITH n, size((n)--()) as connections
            RETURN n.name as name, n.id as id, labels(n)[0] as type, connections as blast_radius_score
            ORDER BY connections DESC
            LIMIT 20
            """,
            tid=tenant
        )
        return jsonify([dict(r) for r in result])

@app.route("/graph/blast-radius/<entity_id>", methods=["GET"])
@require_auth
def get_blast_radius(entity_id):
    tenant = tenant_id()
    driver = get_graph_driver()
    if not driver: return jsonify({"error": "neo4j_not_available"}), 503
    
    with driver.session() as session:
        # Mostra tudo que esta conectado a uma entidade em ate 2 saltos
        result = session.run(
            """
            MATCH (e {id: $eid, tenant: $tid})-[r*1..2]-(connected)
            RETURN e, r, connected
            LIMIT 50
            """,
            eid=entity_id, tid=tenant
        )
        return jsonify([dict(r) for r in result])

@app.route("/copilot/incident/<incident_id>", methods=["GET"])
@require_auth
def get_copilot_insight(incident_id):
    """
    SOC Copilot: Gera um resumo inteligente e sugestão de resposta baseado no contexto total do incidente.
    """
    tenant = tenant_id()
    conn = None
    try:
        conn = get_connection()
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM incidents WHERE incident_id = %s AND tenant_id = %s", (incident_id, tenant))
            row = cur.fetchone()
            if not row: return jsonify({"error": "incident_not_found"}), 404
            
            columns = [desc[0] for desc in getattr(cur, "description", None) or []]
            incident = row_to_dict(row, columns)
            
            # Contexto p/ LLM (Simulado - em prod enviaria p/ OpenAI/Llama)
            summary = f"Análise assistida do incidente {incident_id}. "
            if incident["severity"] == "CRITICAL":
                summary += "Atenção: Este incidente apresenta múltiplas táticas do MITRE em progressão. "
            
            suggestion = "Sugerimos isolar o host envolvido e resetar as credenciais do usuário. "
            hunting_query = f"MATCH (ip:IP {{address: '{incident['primary_source_ip']}'}})-[*]->(target) RETURN target"
            
            return jsonify({
                "llm_insight": {
                    "summary": summary + "A atividade sugere uma tentativa de exfiltração após movimento lateral.",
                    "mitre_explanation": "As táticas detectadas (T1110, T1068) indicam uma cadeia de Credential Access seguida de Escalation.",
                    "response_suggestion": suggestion + "Verifique logs de API Cloud para chamadas incomuns de Role Assumption.",
                    "hunting_query": hunting_query,
                    "blast_radius_analysis": "O raio de impacto atinge 3 sistemas críticos e 2 contas administrativas."
                }
            })
    finally:
        if conn: conn.close()

@app.route("/graph/entities", methods=["GET"])
@require_auth
def list_graph_entities():
    tenant = tenant_id()
    driver = get_graph_driver()
    if not driver: return jsonify([])
    with driver.session() as session:
        result = session.run("MATCH (n) WHERE n.tenant_id = $tid RETURN n LIMIT 100", tid=tenant)
        return jsonify([dict(r["n"]) for r in result])

@app.route("/graph/entity/<entity_id>", methods=["GET"])
@require_auth
def get_graph_entity(entity_id):
    tenant = tenant_id()
    driver = get_graph_driver()
    if not driver: return jsonify({})
    with driver.session() as session:
        result = session.run("MATCH (n {id: $eid}) WHERE n.tenant_id = $tid RETURN n", eid=entity_id, tid=tenant)
        record = result.single()
        return jsonify(dict(record["n"]) if record else {})

@app.route("/attack-paths", methods=["GET"])
@require_auth
def list_attack_paths():
    tenant = tenant_id()
    driver = get_graph_driver()
    if not driver: return jsonify([])
    with driver.session() as session:
        # Busca caminhos de ataque baseados em alertas e táticas
        result = session.run(
            """
            MATCH path = (ip:IP)-[*1..4]->(target)
            WHERE ip.tenant_id = $tid AND (target:Host OR target:CloudAccount)
            RETURN nodes(path) as nodes, relationships(path) as rels
            ORDER BY size(nodes) DESC
            LIMIT 5
            """, tid=tenant
        )
        paths = []
        for i, record in enumerate(result):
            nodes = record["nodes"]
            paths.append({
                "path_id": f"PATH-{i+1}",
                "tenant_id": tenant,
                "entities": [dict(n) for n in nodes],
                "risk_score": 70 + (len(nodes) * 5),
                "confidence": "high",
                "mitre_tactics": ["Lateral Movement", "Privilege Escalation"],
                "recommended_actions": ["Reset password", "Isolate Host"]
            })
        return jsonify(paths)

@app.route("/soar/actions", methods=["GET"])
@require_auth
def list_soar_actions():
    limit, offset = pagination_params()
    tenant = tenant_id()
    conn = None
    try:
        conn = ensure_connection()
        with conn.cursor() as cur:
            cur.execute(
                "SELECT * FROM response_actions WHERE tenant_id = %s ORDER BY created_at DESC LIMIT %s OFFSET %s",
                (tenant, limit, offset),
            )
            rows = cur.fetchall() or []
            columns = [desc[0] for desc in getattr(cur, "description", None) or []]
        return jsonify({"data": [row_to_dict(row, columns) for row in rows]})
    finally:
        if conn: conn.close()

@app.route("/soar/playbooks", methods=["GET"])
@require_auth
def list_playbooks():
    return jsonify([
        {"id": "brute_force_response", "name": "Brute Force Mitigation", "auto_execute": True},
        {"id": "compromised_host_response", "name": "Compromised Host Isolation", "auto_execute": False},
        {"id": "cloud_abuse_response", "name": "Cloud API Abuse Containment", "auto_execute": False}
    ])

@app.route("/copilot/summarize-incident", methods=["POST"])
@require_auth
def copilot_summarize():
    data = request.json
    iid = data.get("incident_id")
    return jsonify({
        "summary": f"O incidente {iid} reflete uma progressão de ataque cross-domain.",
        "hypothesis": "Atacante obteve credenciais via phishing e está explorando a infraestrutura cloud.",
        "next_steps": "Investigar logs de S3 e IAM do usuário envolvido."
    })

def main():
    bootstrap_database()
    app.run(host="0.0.0.0", port=5000)


if __name__ == "__main__":
    main()
