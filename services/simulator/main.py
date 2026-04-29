import json
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