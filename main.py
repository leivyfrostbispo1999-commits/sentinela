<<<<<<< HEAD
import json
import time
import psycopg2
from confluent_kafka import Consumer
from jsonschema import validate, ValidationError
=======
import json
import time
import psycopg2
from confluent_kafka import Consumer
from jsonschema import validate, ValidationError

# Carrega schema
with open("/app/schemas/processed_log.schema.json") as f:
    schema = json.load(f)

# Config Kafka
consumer_conf = {
    'bootstrap.servers': 'kafka:9092',
    'group.id': 'alert-sink-group',
    'auto.offset.reset': 'earliest'
}

consumer = Consumer(consumer_conf)
consumer.subscribe(['processed_logs'])

print("💾 Alert Sink iniciado...")

# Conexão com PostgreSQL (retry)
while True:
    try:
        conn = psycopg2.connect(
            host="sentinela-db",
            database="sentinela",
            user="postgres",
            password="password"
        )
        cursor = conn.cursor()
        print("✅ Conectado ao PostgreSQL!")
        break
    except Exception:
        print("⏳ Aguardando banco subir...")
        time.sleep(3)

# Criação da tabela
cursor.execute("""
CREATE TABLE IF NOT EXISTS alerts (
    id SERIAL PRIMARY KEY,
    ip VARCHAR(50),
    type VARCHAR(50),
    risk INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
""")
conn.commit()

while True:
    msg = consumer.poll(1.0)

    if msg is None:
        continue
    if msg.error():
        print(f"❌ Erro Kafka: {msg.error()}")
        continue

    try:
        data = json.loads(msg.value().decode('utf-8'))

        # 🔥 Validação de schema
        validate(instance=data, schema=schema)

        ip = data.get("ip", "0.0.0.0")
        event_type = data.get("type", "unknown")
        risk = data.get("risk", 0)

        cursor.execute(
            "INSERT INTO alerts (ip, type, risk) VALUES (%s, %s, %s)",
            (ip, event_type, risk)
        )
        conn.commit()

        print(f"💾 Salvo: {ip} | {event_type} | risco={risk}")

    except ValidationError as ve:
        print(f"⚠️ Evento inválido (schema): {ve.message}")

    except Exception as e:
        print(f"❌ Erro DB: {e}")
>>>>>>> f33ed383d8e88d290a27dd7885af588db7e1ce40
