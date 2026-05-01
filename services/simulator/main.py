<<<<<<< HEAD
﻿import time
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
=======
﻿import json
import time
import random
import os
import sys
from confluent_kafka import Producer

def print_flush(text):
    print(text)
    sys.stdout.flush()

# Kafka bootstrap (robusto e explícito)
host = os.getenv('KAFKA_BOOTSTRAP_SERVERS', 'kafka:9092')

p = Producer({
    'bootstrap.servers': host,
    'client.id': 'sentinela-simulator'
})

def delivery_report(err, msg):
    if err is not None:
        print_flush(f"❌ Falha no envio: {err}")
    else:
        print_flush(f"📨 Entregue em {msg.topic()} [{msg.partition()}]")

def run():
    ips = ['192.168.1.1', '10.0.0.1', '172.16.0.10']

    print_flush(f"🚀 Simulador em {host} iniciado...")

    while True:
        try:
            ip = random.choice(ips)

            payload = json.dumps({
                'ip': ip,
                'ts': time.time(),
                'type': 'LOG'
            })

            p.produce(
                topic='raw_logs',
                key=ip,
                value=payload,
                callback=delivery_report
            )

            # flush leve do buffer interno (evita acúmulo silencioso)
            p.poll(0)

            print_flush(f"✅ IP Enviado: {ip}")
            time.sleep(1)

        except BufferError:
            print_flush("⚠️ Buffer cheio, aguardando flush do Kafka...")
            p.flush(2)

        except Exception as e:
            print_flush(f"❌ Erro: {e}")
            time.sleep(2)

if __name__ == '__main__':
    run()
>>>>>>> f33ed383d8e88d290a27dd7885af588db7e1ce40
