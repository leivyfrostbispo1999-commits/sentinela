import time
import json
import random
from kafka import KafkaProducer

producer = KafkaProducer(
    bootstrap_servers=['localhost:9092'],
    value_serializer=lambda v: json.dumps(v).encode('utf-8')
)

print("🚀 Simulador de Ataques Sentinela iniciado...")

ips = ["192.168.1.45", "10.0.0.87", "172.16.0.23", "45.67.89.12"]

while True:
    ip = random.choice(ips)
    
    # Simula Brute Force (SSH)
    if random.random() < 0.6:
        event = {
            "ip": ip,
            "event": "ssh_failed",
            "service": "SSH",
            "port": 22,
            "timestamp": time.time()
        }
        producer.send('raw_logs', event)
        print(f"🔴 Brute Force simulado → {ip}")

    # Simula Port Scan
    else:
        event = {
            "ip": ip,
            "event": "port_scan",
            "service": "Multiple",
            "ports": [22, 80, 443, 3389],
            "timestamp": time.time()
        }
        producer.send('raw_logs', event)
        print(f"🔍 Port Scan simulado → {ip}")

    time.sleep(1.5)  # gera ataques a cada 1,5s