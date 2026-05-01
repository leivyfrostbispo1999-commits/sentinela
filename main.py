import time
from kafka import KafkaProducer
from kafka.errors import NoBrokersAvailable

def connect_kafka():
    print("🚀 Iniciando sistema Sentinela em D:\...")
    while True:
        try:
            producer = KafkaProducer(bootstrap_servers=['localhost:9092'])
            print("✅ Conectado ao Kafka com sucesso!")
            return producer
        except NoBrokersAvailable:
            print("⏳ Aguardando Kafka (NoBrokersAvailable)... Aguarde uns 15 segundo")
            time.sleep(15)

if __name__ == "__main__":
    producer = connect_kafka()
