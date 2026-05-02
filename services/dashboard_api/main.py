import json
from datetime import datetime, timezone

import psycopg2
from flask import Flask, jsonify
from flask_cors import CORS


app = Flask(__name__)
CORS(app)


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


def get_db_connection():
    try:
        return psycopg2.connect(
            host="localhost",
            dbname="sentinela",
            user="postgres",
            password="postgres",
        )
    except Exception:
        return psycopg2.connect(
            host="localhost",
            dbname="postgres",
            user="postgres",
            password="postgres",
        )


def ensure_schema(cur):
    cur.execute("""
        CREATE TABLE IF NOT EXISTS alertas (
            id SERIAL PRIMARY KEY,
            ip TEXT,
            status TEXT,
            risco INTEGER,
            ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cur.execute("ALTER TABLE alertas ADD COLUMN IF NOT EXISTS ip TEXT")
    cur.execute("ALTER TABLE alertas ADD COLUMN IF NOT EXISTS status TEXT")
    cur.execute("ALTER TABLE alertas ADD COLUMN IF NOT EXISTS risco INTEGER")
    cur.execute("ALTER TABLE alertas ADD COLUMN IF NOT EXISTS ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP")
    cur.execute("ALTER TABLE alertas ADD COLUMN IF NOT EXISTS service TEXT")
    cur.execute("ALTER TABLE alertas ADD COLUMN IF NOT EXISTS port INTEGER")
    cur.execute("ALTER TABLE alertas ADD COLUMN IF NOT EXISTS event_type TEXT")
    cur.execute("ALTER TABLE alertas ADD COLUMN IF NOT EXISTS ip_event_count INTEGER DEFAULT 0")
    cur.execute("ALTER TABLE alertas ADD COLUMN IF NOT EXISTS auto_response TEXT DEFAULT 'simulated'")
    cur.execute("ALTER TABLE alertas ADD COLUMN IF NOT EXISTS raw_event JSONB")
    cur.execute("ALTER TABLE alertas ADD COLUMN IF NOT EXISTS score_final INTEGER")
    cur.execute('ALTER TABLE alertas ADD COLUMN IF NOT EXISTS "timestamp" TIMESTAMP DEFAULT CURRENT_TIMESTAMP')
    cur.execute("UPDATE alertas SET risco = score_final WHERE risco IS NULL AND score_final IS NOT NULL")
    cur.execute('UPDATE alertas SET ts = "timestamp" WHERE ts IS NULL AND "timestamp" IS NOT NULL')

    cur.execute("""
        CREATE TABLE IF NOT EXISTS blacklist (
            ip TEXT PRIMARY KEY,
            reason TEXT NOT NULL,
            first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            offense_count INTEGER DEFAULT 1,
            active BOOLEAN DEFAULT TRUE,
            response_mode TEXT DEFAULT 'simulated'
        )
    """)


@app.route("/alertas")
def listar_alertas():
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        ensure_schema(cur)
        conn.commit()

        cur.execute("""
            SELECT
                ip, status, risco, ts, service, port,
                event_type, ip_event_count, auto_response
            FROM alertas
            ORDER BY ts DESC
            LIMIT 100
        """)

        alertas = []
        for row in cur.fetchall():
            ts = row[3]
            alertas.append({
                "ip": row[0],
                "status": row[1],
                "risco": row[2] if row[2] is not None else 0,
                "ts": ts.strftime("%d/%m/%Y %H:%M:%S") if hasattr(ts, "strftime") else str(ts),
                "service": row[4] or "UNKNOWN",
                "port": row[5],
                "event_type": row[6] or "unknown",
                "ip_event_count": row[7] or 0,
                "auto_response": row[8] or "none",
            })

        cur.close()
        conn.close()
        return jsonify(alertas)

    except Exception as exc:
        log_json("ERROR", "Erro na rota /alertas", error=str(exc))
        return jsonify([])


@app.route("/blacklist")
def listar_blacklist():
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        ensure_schema(cur)
        conn.commit()
        cur.execute("""
            SELECT ip, reason, first_seen, last_seen, offense_count, active, response_mode
            FROM blacklist
            ORDER BY last_seen DESC
            LIMIT 100
        """)

        rows = []
        for row in cur.fetchall():
            rows.append({
                "ip": row[0],
                "reason": row[1],
                "first_seen": row[2].strftime("%d/%m/%Y %H:%M:%S") if hasattr(row[2], "strftime") else str(row[2]),
                "last_seen": row[3].strftime("%d/%m/%Y %H:%M:%S") if hasattr(row[3], "strftime") else str(row[3]),
                "offense_count": row[4],
                "active": row[5],
                "response_mode": row[6],
            })

        cur.close()
        conn.close()
        return jsonify(rows)
    except Exception as exc:
        log_json("ERROR", "Erro na rota /blacklist", error=str(exc))
        return jsonify([])


if __name__ == "__main__":
    log_json("INFO", "Dashboard API rodando", url="http://localhost:5000")
    app.run(host="0.0.0.0", port=5000, debug=False)
