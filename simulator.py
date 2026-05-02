import time
import json
import random
from kafka import KafkaProducer
from kafka.errors import NoBrokersAvailable

def start_simulator():
    print("🚀 Iniciando Simulador de Dados...")
    producer = None
    
    while True:
        try:
            producer = KafkaProducer(bootstrap_servers=['localhost:9092'])
        except NoBrokersAvailable:
            print("⏳ Aguardando Kafka (NoBrokersAvailable)... Aguarde uns 15 segundo")
            time.sleep(15)

    while True:
        # Gera um valor aleatório entre 0 e 100
        valor = random.randint(0, 100)
        data = {"sensor": "termometro_01", "value": valor}
        
        producer.send('telemetry', data)
        print(f"📡 Dado enviado: {data}")
        
        # Se o valor for > 80, o motor de regras deve capturar
        time.sleep(2)

if __name__ == "__main__":
    start_simulator()
