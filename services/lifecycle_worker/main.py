import os
import json
import time
import psycopg2
import requests
from datetime import datetime, timezone

DB_CONFIG = {
    "host": os.getenv("DB_HOST", "db"),
    "port": int(os.getenv("DB_PORT", "5432")),
    "dbname": os.getenv("DB_NAME", "postgres"),
    "user": os.getenv("DB_USER", "postgres"),
    "password": os.getenv("DB_PASSWORD", "root"),
}

# Configurações do OpenSearch
ENABLE_OPENSEARCH = os.getenv("ENABLE_OPENSEARCH", "true").lower() == "true"
OPENSEARCH_URL = os.getenv("OPENSEARCH_URL", "http://opensearch:9200")

# Configurações de Retenção (em dias)
RETENTION_ALERTS_DAYS = int(os.getenv("RETENTION_ALERTS_DAYS", "30"))
RETENTION_INCIDENTS_DAYS = int(os.getenv("RETENTION_INCIDENTS_DAYS", "90"))
RETENTION_AUDIT_DAYS = int(os.getenv("RETENTION_AUDIT_DAYS", "180"))
CHECK_INTERVAL_SECONDS = int(os.getenv("LIFECYCLE_CHECK_INTERVAL", "3600"))

def now_iso():
    return datetime.now(timezone.utc).isoformat()

def log_json(level, message, **fields):
    payload = {
        "ts": now_iso(),
        "level": level,
        "component": "lifecycle_worker",
        "message": message,
        **fields,
    }
    print(json.dumps(payload, ensure_ascii=False), flush=True)

def connect_db():
    while True:
        try:
            conn = psycopg2.connect(**DB_CONFIG)
            return conn
        except Exception as exc:
            log_json("WARN", "Aguardando banco de dados", error=str(exc))
            time.sleep(10)

def migrate_to_opensearch(index_name, items):
    if not items or not ENABLE_OPENSEARCH:
        return True
    
    bulk_data = ""
    for item in items:
        # Extrai ID para o OpenSearch se disponível (ex: event_id ou incident_id)
        doc_id = item.get("event_id") or item.get("incident_id") or item.get("id")
        action = {"index": {"_index": index_name}}
        if doc_id:
            action["index"]["_id"] = str(doc_id)
        
        bulk_data += json.dumps(action) + "\n"
        # Garante que campos de data sejam serializáveis se vierem como objeto datetime
        clean_item = {}
        for k, v in item.items():
            if isinstance(v, datetime):
                clean_item[k] = v.isoformat()
            else:
                clean_item[k] = v
        bulk_data += json.dumps(clean_item) + "\n"

    try:
        response = requests.post(
            f"{OPENSEARCH_URL}/_bulk",
            data=bulk_data,
            headers={"Content-Type": "application/x-ndjson"},
            timeout=30
        )
        if response.status_code == 200:
            res_json = response.json()
            if res_json.get("errors"):
                log_json("ERROR", "Erro parcial no bulk OpenSearch", errors=res_json.get("items")[:5])
                return False
            return True
        else:
            log_json("ERROR", "Falha no bulk OpenSearch", status_code=response.status_code, text=response.text[:200])
            return False
    except Exception as exc:
        log_json("ERROR", "Erro de conexão com OpenSearch", error=str(exc))
        return False

def run_retention():
    conn = connect_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            # 1. Alertas
            cur.execute(
                "SELECT * FROM alertas WHERE ts < NOW() - %s * INTERVAL '1 day'",
                (RETENTION_ALERTS_DAYS,)
            )
            old_alerts = cur.fetchall()
            if old_alerts and migrate_to_opensearch("sentinela-alerts-cold", old_alerts):
                cur.execute(
                    "DELETE FROM alertas WHERE ts < NOW() - %s * INTERVAL '1 day'",
                    (RETENTION_ALERTS_DAYS,)
                )
                deleted_alerts = cur.rowcount
            else:
                deleted_alerts = 0
            
            # 2. Incidentes (apenas os fechados/resolvidos)
            cur.execute(
                "SELECT * FROM incidents WHERE status IN ('RESOLVED', 'CLOSED', 'FALSE_POSITIVE') AND last_seen < NOW() - %s * INTERVAL '1 day'",
                (RETENTION_INCIDENTS_DAYS,)
            )
            old_incidents = cur.fetchall()
            if old_incidents and migrate_to_opensearch("sentinela-incidents-cold", old_incidents):
                cur.execute(
                    "DELETE FROM incidents WHERE status IN ('RESOLVED', 'CLOSED', 'FALSE_POSITIVE') AND last_seen < NOW() - %s * INTERVAL '1 day'",
                    (RETENTION_INCIDENTS_DAYS,)
                )
                deleted_incidents = cur.rowcount
            else:
                deleted_incidents = 0

            # 3. Auditoria
            cur.execute(
                "SELECT * FROM audit_logs WHERE timestamp < NOW() - %s * INTERVAL '1 day'",
                (RETENTION_AUDIT_DAYS,)
            )
            old_audit = cur.fetchall()
            if old_audit and migrate_to_opensearch("sentinela-audit-cold", old_audit):
                cur.execute(
                    "DELETE FROM audit_logs WHERE timestamp < NOW() - %s * INTERVAL '1 day'",
                    (RETENTION_AUDIT_DAYS,)
                )
                deleted_audit = cur.rowcount
            else:
                deleted_audit = 0

            conn.commit()
            log_json("INFO", "Ciclo de limpeza e migração concluído", 
                     deleted_alerts=deleted_alerts, 
                     deleted_incidents=deleted_incidents,
                     deleted_audit=deleted_audit)
    except Exception as exc:
        log_json("ERROR", "Erro no ciclo de retenção", error=str(exc))
        conn.rollback()
    finally:
        conn.close()

if __name__ == "__main__":
    import psycopg2.extras
    log_json("INFO", "Lifecycle Worker iniciado")
    while True:
        run_retention()
        time.sleep(CHECK_INTERVAL_SECONDS)
