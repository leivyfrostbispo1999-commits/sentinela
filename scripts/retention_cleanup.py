import argparse
import json
import os
import sys
from datetime import datetime, timezone


RETENTION_TABLES = {
    "alertas": ("ts", "RETENTION_ALERTS_DAYS", 30),
    "incidents": ("last_seen", "RETENTION_INCIDENTS_DAYS", 90),
    "audit_logs": ("timestamp", "RETENTION_AUDIT_DAYS", 180),
}


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def retention_days(env_name, default):
    try:
        return max(1, int(os.getenv(env_name, str(default))))
    except ValueError:
        return default


def build_retention_plan():
    return [
        {"table": table, "column": column, "days": retention_days(env_name, default)}
        for table, (column, env_name, default) in RETENTION_TABLES.items()
    ]


def db_config():
    return {
        "host": os.getenv("DB_HOST", "localhost"),
        "port": int(os.getenv("DB_PORT", "5432")),
        "dbname": os.getenv("DB_NAME", "postgres"),
        "user": os.getenv("DB_USER", "postgres"),
        "password": os.getenv("DB_PASSWORD", "root"),
    }


def execute_plan(plan, execute=False):
    import psycopg2

    conn = psycopg2.connect(**db_config())
    results = []
    try:
        with conn.cursor() as cur:
            for item in plan:
                interval = f"{item['days']} days"
                cur.execute(f"SELECT COUNT(*) FROM {item['table']} WHERE {item['column']} < NOW() - %s::interval", (interval,))
                count = int((cur.fetchone() or [0])[0] or 0)
                if execute and count:
                    cur.execute(f"DELETE FROM {item['table']} WHERE {item['column']} < NOW() - %s::interval", (interval,))
                results.append({**item, "would_delete": count})
        if execute:
            conn.commit()
        else:
            conn.rollback()
    finally:
        conn.close()
    return results


def main(argv=None):
    parser = argparse.ArgumentParser(description="Retencao segura de dados do SENTINELA 7.0")
    parser.add_argument("--dry-run", action="store_true", default=True)
    parser.add_argument("--execute", action="store_true", help="Remove dados antigos; sem esta flag nada e apagado")
    parser.add_argument("--print-plan", action="store_true", help="Mostra plano sem conectar ao banco")
    args = parser.parse_args(argv)
    plan = build_retention_plan()
    if args.print_plan:
        print(json.dumps({"ts": now_iso(), "dry_run": True, "plan": plan}, ensure_ascii=False))
        return 0
    results = execute_plan(plan, execute=args.execute)
    print(json.dumps({"ts": now_iso(), "dry_run": not args.execute, "results": results}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
