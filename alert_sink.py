import time
<<<<<<< HEAD
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
=======

def safe_db_insert(cursor, query, data):
    """
    Tenta inserir no banco de dados até 3 vezes antes de desistir.
    """
    for i in range(3):
        try:
            cursor.execute(query, data)
            # Se chegar aqui, deu certo. O return encerra a função.
            print("✅ Inserção no banco realizada com sucesso!")
            return 
        except Exception as e:
            print(f"⚠️ Erro no Banco (Tentativa {i+1}/3):", e)
            if i < 2: # Se não for a última tentativa, espera 2 segundos
                time.sleep(2)
            else:
                print("❌ Falha crítica: Não foi possível salvar no banco após 3 tentativas.")
>>>>>>> f33ed383d8e88d290a27dd7885af588db7e1ce40
