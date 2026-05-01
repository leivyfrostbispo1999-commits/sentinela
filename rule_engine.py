import time
import json
from kafka import KafkaConsumer, KafkaProducer
from kafka.errors import NoBrokersAvailable

def start_engine():
    print("🚀 Iniciando Motor de Regras Sentinela...")
    while True:
        try:
            # Consome dados brutos (ex: 'telemetry') e produz alertas ('alerts')
            consumer = KafkaConsumer(
                'telemetry',
                bootstrap_servers=['localhost:9092'],
                value_deserializer=lambda m: json.loads(m.decode('utf-8')),
                group_id='sentinela-engine-group'
            )
            producer = KafkaProducer(
                bootstrap_servers=['localhost:9092'],
                value_serializer=lambda v: json.dumps(v).encode('utf-8')
            )
            print("✅ Motor de Regras conectado ao Kafka!")

            for message in consumer:
                data = message.value
                # Exemplo de regra: se o valor for maior que 80, gera alerta
                if data.get('value', 0) > 80:
                    alert = {"status": "CRITICAL", "message": f"Valor alto detectado: {data['value']}"}
                    producer.send('alerts', alert)
                    print(f"⚠️ Regra disparada! Alerta enviado: {alert}")

        except NoBrokersAvailable:
            print("⏳ Aguardando Kafka (NoBrokersAvailable)... Aguarde uns 15 segundo")
            time.sleep(15)

if __name__ == "__main__":
    start_engine()
