import json
import os
import sys
import time
import uuid
from datetime import datetime, timezone

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
                simulated_block BOOLEAN DEFAULT FALSE,
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
        cur.execute("ALTER TABLE alertas ADD COLUMN IF NOT EXISTS simulated_block BOOLEAN DEFAULT FALSE")
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
                service, port, event_type, ip_event_count, risk_reasons,
                threat_intel_match, threat_category, threat_description,
                threat_reputation_score, threat_source, correlation_window_seconds,
                correlation_key, correlation_reason,
                auto_response,
                simulated_block, raw_event
            )
            VALUES (
                %(event_id)s, %(ip)s, %(status)s, %(risco)s, %(score_final)s,
                COALESCE(%(ts)s::timestamptz, NOW()),
                COALESCE(%(ts)s::timestamptz, NOW()),
                %(service)s, %(port)s, %(event_type)s, %(ip_event_count)s,
                %(risk_reasons)s::jsonb, %(threat_intel_match)s,
                %(threat_category)s, %(threat_description)s,
                %(threat_reputation_score)s, %(threat_source)s,
                %(correlation_window_seconds)s, %(correlation_key)s,
                %(correlation_reason)s, %(auto_response)s,
                %(simulated_block)s, %(raw_event)s::jsonb
            )
            ON CONFLICT (event_id) DO NOTHING
            """,
            {
                "event_id": event_id,
                "ip": ip,
                "status": alert.get("status", "DESCONHECIDO"),
                "risco": alert.get("risco", 0),
                "score_final": alert.get("score_final", alert.get("risco", 0)),
                "ts": alert.get("ts"),
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
                "simulated_block": bool(alert.get("simulated_block", False)),
                "raw_event": json.dumps(alert.get("raw_event", alert), ensure_ascii=False),
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

    conn.commit()
    log_json("INFO", "Alerta gravado", event_id=event_id, ip=ip, status=alert.get("status"))


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
