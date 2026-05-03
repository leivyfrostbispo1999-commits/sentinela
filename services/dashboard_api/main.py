import json
import os
import time
from datetime import datetime, timezone

import psycopg2
from flask import Flask, Response, jsonify, request
from flask_cors import CORS
from prometheus_client import CONTENT_TYPE_LATEST, CollectorRegistry, Gauge, generate_latest


app = Flask(__name__)
CORS(app)

DB_CONFIG = {
    "host": os.getenv("DB_HOST", "db"),
    "port": int(os.getenv("DB_PORT", "5432")),
    "dbname": os.getenv("DB_NAME", "postgres"),
    "user": os.getenv("DB_USER", "postgres"),
    "password": os.getenv("DB_PASSWORD", "root"),
}
MAX_BACKOFF_SECONDS = float(os.getenv("MAX_BACKOFF_SECONDS", "10"))
SENTINELA_API_TOKEN = os.getenv("SENTINELA_API_TOKEN", "sentinela-demo-token")
ALLOWED_RANGES = {
    "5m": "5 minutes",
    "15m": "15 minutes",
    "1h": "1 hour",
    "24h": "24 hours",
}


def log(level, message, **extra):
    payload = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "level": level,
        "component": "dashboard_api",
        "message": message,
    }
    payload.update(extra)
    print(json.dumps(payload, ensure_ascii=False), flush=True)


def get_connection():
    attempt = 0
    while True:
        try:
            return psycopg2.connect(**DB_CONFIG)
        except Exception:
            if attempt >= 3:
                raise
            time.sleep(min(MAX_BACKOFF_SECONDS, 0.5 * (2 ** attempt)))
            attempt += 1


def ensure_schema(conn):
    with conn.cursor() as cur:
        cur.execute("ALTER TABLE alertas ADD COLUMN IF NOT EXISTS threat_source TEXT")
        cur.execute("ALTER TABLE alertas ADD COLUMN IF NOT EXISTS correlation_window_seconds INTEGER")
        cur.execute("ALTER TABLE alertas ADD COLUMN IF NOT EXISTS correlation_key TEXT")
        cur.execute("ALTER TABLE alertas ADD COLUMN IF NOT EXISTS correlation_reason TEXT")
    conn.commit()


def range_interval():
    selected = request.args.get("range", "1h").lower()
    return selected if selected in ALLOWED_RANGES else "1h"


def range_where():
    selected = range_interval()
    return selected, ALLOWED_RANGES[selected]


def token_is_valid():
    return request.headers.get("X-SENTINELA-TOKEN") == SENTINELA_API_TOKEN


def require_token():
    if token_is_valid():
        return None
    return jsonify({"error": "token inválido ou ausente", "header": "X-SENTINELA-TOKEN"}), 401


@app.route("/")
def home():
    return jsonify({
        "status": "online",
        "message": "API Sentinela SOC 5.5 rodando",
        "endpoints": ["/health", "/alertas?range=5m", "/alertas?range=1h", "/metrics"],
    })


@app.route("/health")
def health():
    try:
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT 1")
        cur.close()
        conn.close()
        return jsonify({"status": "ok", "service": "dashboard_api", "db": "ok"})
    except Exception as e:
        log("ERROR", "Healthcheck falhou", error=str(e))
        return jsonify({"status": "error", "service": "dashboard_api", "db": "error"}), 503


@app.route("/alertas")
def alertas():
    auth_error = require_token()
    if auth_error:
        return auth_error

    conn = None
    try:
        selected_range, interval = range_where()
        conn = get_connection()
        ensure_schema(conn)
        cur = conn.cursor()

        cur.execute(
            """
            SELECT
                id, event_id, ip, status, risco, ts, simulated_block,
                threat_intel_match, threat_category, threat_description,
                event_type, port, service, threat_source,
                correlation_window_seconds, correlation_key, correlation_reason
            FROM alertas
            WHERE ts >= NOW() - %s::interval
            ORDER BY ts DESC
            LIMIT 500
            """,
            (interval,),
        )

        rows = cur.fetchall()
        dados = []
        for row in rows:
            dados.append({
                "id": row[0],
                "event_id": row[1],
                "ip": row[2],
                "status": row[3],
                "risco": row[4],
                "ts": row[5].strftime("%d/%m/%Y %H:%M:%S") if row[5] else None,
                "simulated_block": bool(row[6]),
                "threat_intel_match": bool(row[7]),
                "threat_category": row[8],
                "threat_description": row[9],
                "event_type": row[10],
                "port": row[11],
                "service": row[12],
                "threat_source": row[13],
                "correlation_window_seconds": row[14],
                "correlation_key": row[15],
                "correlation_reason": row[16],
            })

        cur.close()
        return jsonify({"range": selected_range, "count": len(dados), "data": dados})

    except Exception as e:
        log("ERROR", "Erro na rota /alertas", error=str(e))
        return jsonify({"range": request.args.get("range", "1h"), "count": 0, "data": []})
    finally:
        if conn:
            conn.close()


@app.route("/metrics")
def metrics():
    auth_error = require_token()
    if auth_error:
        return auth_error

    conn = None
    registry = CollectorRegistry()
    total_events = Gauge("sentinela_events_total", "Total de eventos persistidos", registry=registry)
    critical_events = Gauge("sentinela_critical_events_total", "Total de eventos criticos", registry=registry)
    ioc_events = Gauge("sentinela_ioc_events_total", "Total de IOCs detectados", registry=registry)
    events_by_type = Gauge("sentinela_events_by_type_total", "Eventos por tipo", ["event_type"], registry=registry)

    try:
        conn = get_connection()
        ensure_schema(conn)
        cur = conn.cursor()

        cur.execute("SELECT COUNT(*) FROM alertas")
        total_events.set(cur.fetchone()[0])

        cur.execute("SELECT COUNT(*) FROM alertas WHERE risco >= 95 OR simulated_block = TRUE")
        critical_events.set(cur.fetchone()[0])

        cur.execute("SELECT COUNT(*) FROM alertas WHERE threat_intel_match = TRUE")
        ioc_events.set(cur.fetchone()[0])

        cur.execute(
            """
            SELECT COALESCE(event_type, 'unknown'), COUNT(*)
            FROM alertas
            GROUP BY COALESCE(event_type, 'unknown')
            """
        )
        for event_type, total in cur.fetchall():
            events_by_type.labels(event_type=str(event_type)).set(total)

        cur.close()
    except Exception as e:
        log("ERROR", "Erro ao gerar métricas", error=str(e))
    finally:
        if conn:
            conn.close()

    return Response(generate_latest(registry), mimetype=CONTENT_TYPE_LATEST)


if __name__ == "__main__":
    log("INFO", "Dashboard API rodando", url="http://localhost:5000")
    app.run(host="0.0.0.0", port=5000)
