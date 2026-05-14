import psycopg2
import uuid
import random
import time
from datetime import datetime, timezone

DB_CONFIG = {
    "host": "sentinela-db-lite",
    "port": 5432,
    "dbname": "postgres",
    "user": "postgres",
    "password": "root",
}

def inject_event(event_type, source_ip, severity, score, summary):
    conn = psycopg2.connect(**DB_CONFIG)
    cur = conn.cursor()
    event_id = str(uuid.uuid4())
    cur.execute("""
        INSERT INTO alertas (event_id, source_ip, event_type, severity, score_final, human_summary, ts, tenant_id)
        VALUES (%s, %s, %s, %s, %s, %s, NOW(), 'default')
    """, (event_id, source_ip, event_type, severity, score, summary))
    conn.commit()
    cur.close()
    conn.close()
    print(f"[+] Injetado: {event_type} de {source_ip} (Score: {score})")

ips_ataque = ["192.168.1.50", "45.33.22.11", "104.21.33.44", "185.12.33.99"]

print("--- Iniciando Simulação de Tráfego de Nuvem ---")

# 1. Simular Port Scan
for i in range(5):
    inject_event("PORT_SCAN", random.choice(ips_ataque), "MEDIUM", 50, "Varredura de portas detectada via Cloud Security List")
    time.sleep(1)

# 2. Simular SSH Brute Force
for i in range(10):
    inject_event("FAILED_LOGIN", "45.33.22.11", "HIGH", 75, "Falha de login SSH (tentativa de root)")
    time.sleep(0.5)

# 3. Simular Web Exploit
inject_event("WEB_ATTACK", "185.12.33.99", "CRITICAL", 95, "Tentativa de SQL Injection detectada no /api/auth")

print("--- Simulação Concluída. Cheque o Dashboard! ---")
