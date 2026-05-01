import time
import json
from kafka import KafkaConsumer
from kafka.errors import NoBrokersAvailable

def start_sink():
    print("🚀 Iniciando Sink de Alertas em D:\...")
    while True:
        try:
            consumer = KafkaConsumer(
                'alerts',
                bootstrap_servers=['localhost:9092'],
                value_deserializer=lambda m: json.loads(m.decode('utf-8')),
                auto_offset_reset='earliest',
                group_id='sentinela-alert-group'
            )
            print("✅ Alert Sink conectado ao Kafka!")
            for message in consumer:
                print(f"🔔 ALERTA RECEBIDO: {message.value}")
        except NoBrokersAvailable:
            print("⏳ Aguardando Kafka... Aguarde uns 15 segundo")
            time.sleep(15)

if __name__ == "__main__":
    start_sink()
