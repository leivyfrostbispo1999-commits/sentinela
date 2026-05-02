import time
import json
from collections import defaultdict, deque
from kafka import KafkaConsumer, KafkaProducer
from kafka.errors import NoBrokersAvailable
import subprocess

ip_attempts = defaultdict(lambda: deque(maxlen=30))
blocked_ips = set()

def load_blacklist():
    try:
        with open(r"D:\sentinela\scripts\blacklist.txt", "r") as f:
            for line in f:
                ip = line.strip()
                if ip:
                    blocked_ips.add(ip)
    except:
        pass

def save_to_blacklist(ip):
    with open(r"D:\sentinela\scripts\blacklist.txt", "a") as f:
        f.write(ip + "\n")

load_blacklist()

def start_engine():
    print("🚀 Motor de Regras Sentinela iniciado...")
    while True:
        try:
            consumer = KafkaConsumer(
                'raw_logs',
                bootstrap_servers=['localhost:9092'],
                value_deserializer=lambda m: json.loads(m.decode('utf-8')),
                group_id='sentinela-rule-engine'
            )
            producer = KafkaProducer(
                bootstrap_servers=['localhost:9092'],
                value_serializer=lambda v: json.dumps(v).encode('utf-8')
            )
            print("✅ Motor de Regras conectado ao Kafka!")

            for message in consumer:
                log = message.value
                ip = log.get('ip')
                event = log.get('event', '')

                if not ip or ip in blocked_ips:
                    continue

                current_time = time.time()
                ip_attempts[ip].append(current_time)

                alert = None

                recent_attempts = [t for t in ip_attempts[ip] if current_time - t <= 30]

                if len(recent_attempts) >= 2 and ip not in blocked_ips:
                    alert = {"ip": ip, "type": "BRUTE_FORCE", "status": "BLOCKED", "count": len(recent_attempts)}
                    blocked_ips.add(ip)
                    save_to_blacklist(ip)

                elif event == "port_scan" and len(recent_attempts) >= 8 and ip not in blocked_ips:
                    alert = {"ip": ip, "type": "PORT_SCAN", "status": "BLOCKED", "count": len(recent_attempts)}
                    blocked_ips.add(ip)
                    save_to_blacklist(ip)

                if alert:
                    producer.send('alerts', alert)
                    try:
                        subprocess.run(
                            ["powershell", "-ExecutionPolicy", "Bypass", "-File", r"D:\sentinela\scripts\block_ip.ps1", ip],
                            capture_output=True, text=True
                        )
                        print(f"🚫 {alert['type']} DETECTADO E BLOQUEADO → {ip}")
                    except:
                        print(f"⚠️ Erro ao bloquear IP {ip}")

        except Exception as e:
            print(f"⏳ Aguardando Kafka... {e}")
            time.sleep(15)

if __name__ == "__main__":
    start_engine()