import json
import os
import sys
import time
from collections import defaultdict, deque
from datetime import datetime, timezone

import psycopg2
from kafka import KafkaConsumer


KAFKA_BOOTSTRAP_SERVERS = ["kafka:9092"]
RAW_LOGS_TOPIC = "raw_logs"
AUTO_RESPONSE_MODE = os.getenv("SENTINELA_AUTO_RESPONSE_MODE", "simulated").lower()
STATE_WINDOW_SECONDS = 60
BLACKLIST_THRESHOLD = 5

ip_events = defaultdict(lambda: deque())


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


def get_db_connection():
    try:
        return psycopg2.connect(host="localhost", dbname="sentinela", user="postgres", password="postgres")
    except Exception:
        return psycopg2.connect(host="localhost", dbname="postgres", user="postgres", password="postgres")


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


def prune_state(ip, now):
    events = ip_events[ip]
    while events and now - events[0] > STATE_WINDOW_SECONDS:
        events.popleft()
    return events


def update_stateful_count(ip):
    now = time.time()
    events = prune_state(ip, now)
    events.append(now)
    return len(events)


def classify_event(log, ip_event_count):
    event_type = (log.get("event_type") or log.get("event") or "").lower()

    if "brute" in event_type or event_type == "ssh_failed":
        return "BRUTE FORCE", 85

    if event_type == "port_scan":
        return "PORT SCAN", 92

    if event_type in {"suspicious_login", "atividade_suspeita", "login_suspeito"}:
        return "ATIVIDADE SUSPEITA", 70

    if ip_event_count >= BLACKLIST_THRESHOLD:
        return "ATIVIDADE SUSPEITA", 65

    return "TRÁFEGO NORMAL", 25


def simulated_auto_response(ip, status, ip_event_count):
    should_blacklist = status in {"BRUTE FORCE", "PORT SCAN"} and ip_event_count >= BLACKLIST_THRESHOLD

    if not should_blacklist:
        return "none", False

    if AUTO_RESPONSE_MODE != "simulated":
        # Estrutura preparada para ativação futura de iptables. Não executa bloqueio real nesta sprint.
        log_json("WARN", "Modo de resposta real solicitado, mas bloqueio real está desativado nesta sprint", ip=ip)

    return "simulated_block", True


def upsert_blacklist(cur, ip, reason, response_mode):
    cur.execute("""
        INSERT INTO blacklist (ip, reason, offense_count, response_mode)
        VALUES (%s, %s, 1, %s)
        ON CONFLICT (ip) DO UPDATE SET
            reason = EXCLUDED.reason,
            last_seen = CURRENT_TIMESTAMP,
            offense_count = blacklist.offense_count + 1,
            active = TRUE,
            response_mode = EXCLUDED.response_mode
    """, (ip, reason, response_mode))


def persist_alert(log, status, risco, ip_event_count, auto_response, should_blacklist):
    ip = log["ip"]
    service = log.get("service") or "UNKNOWN"
    port = log.get("port")
    event_type = log.get("event_type") or log.get("event") or "unknown"

    conn = get_db_connection()
    try:
        cur = conn.cursor()
        ensure_schema(cur)

        if should_blacklist:
            upsert_blacklist(cur, ip, status, AUTO_RESPONSE_MODE)

        cur.execute("""
            INSERT INTO alertas (
                ip, status, risco, score_final, ts, "timestamp",
                service, port, event_type, ip_event_count, auto_response, raw_event
            )
            VALUES (%s, %s, %s, %s, NOW(), NOW(), %s, %s, %s, %s, %s, %s::jsonb)
        """, (
            ip,
            status,
            risco,
            risco,
            service,
            port,
            event_type,
            ip_event_count,
            auto_response,
            json.dumps(log, ensure_ascii=False),
        ))

        conn.commit()
        cur.close()
    finally:
        conn.close()


def create_consumer():
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
            log_json("WARN", "Aguardando Kafka", error=str(exc))
            time.sleep(3)


def process_log(log):
    ip = log.get("ip")
    if not ip:
        log_json("WARN", "Evento descartado sem IP", raw_event=log)
        return

    ip_event_count = update_stateful_count(ip)
    status, risco = classify_event(log, ip_event_count)
    auto_response, should_blacklist = simulated_auto_response(ip, status, ip_event_count)
    persist_alert(log, status, risco, ip_event_count, auto_response, should_blacklist)

    log_json(
        "INFO",
        "Alerta persistido",
        ip=ip,
        status=status,
        risco=risco,
        service=log.get("service"),
        port=log.get("port"),
        event_type=log.get("event_type") or log.get("event"),
        ip_event_count=ip_event_count,
        auto_response=auto_response,
        blacklisted=should_blacklist,
    )


def run():
    log_json("INFO", "Motor de regras Sentinela iniciado", auto_response_mode=AUTO_RESPONSE_MODE)

    while True:
        try:
            consumer = create_consumer()
            for message in consumer:
                process_log(message.value)
        except Exception as exc:
            log_json("ERROR", "Erro no loop do Rule Engine; reconectando", error=str(exc))
            time.sleep(3)


if __name__ == "__main__":
    try:
        run()
    except KeyboardInterrupt:
        log_json("INFO", "Rule Engine encerrado")
        sys.exit(0)
