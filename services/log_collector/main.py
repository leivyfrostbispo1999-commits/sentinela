import time
import json
import random
from kafka import KafkaProducer

producer = KafkaProducer(
    bootstrap_servers=['localhost:9092'],
    value_serializer=lambda v: json.dumps(v).encode('utf-8')
)

print("📡 Gerador de Logs Reais de Ataques iniciado...")

ips = ["192.168.1.45", "10.0.0.87", "172.16.0.23", "45.67.89.12", "172.16.5.67"]

while True:
    ip = random.choice(ips)
    
    # Ataque Brute Force
    if random.random() < 0.5:
        event = {
            "timestamp": time.time(),
            "ip": ip,
            "event": "ssh_failed",
            "service": "SSH",
            "port": 22,
            "attempts": random.randint(5, 25)
        }
        producer.send('raw_logs', event)
        print(f"🔴 BRUTE FORCE → {ip} ({event['attempts']} tentativas)")

    # Port Scan
    else:
        event = {
            "timestamp": time.time(),
            "ip": ip,
            "event": "port_scan",
            "service": "Multiple",
            "ports_scanned": random.randint(12, 80)
        }
        producer.send('raw_logs', event)
        print(f"🔍 PORT SCAN → {ip} ({event['ports_scanned']} portas)")

    time.sleep(1.2)