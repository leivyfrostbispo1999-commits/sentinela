import json
from confluent_kafka import Consumer, Producer

KAFKA_BROKER = "sentinela-kafka:9092"
INPUT_TOPIC = "logs"
OUTPUT_TOPIC = "alerts"

def create_consumer():
    return Consumer({
        'bootstrap.servers': KAFKA_BROKER,
        'group.id': 'alert-sink-v1',
        'auto.offset.reset': 'earliest'
    })

def create_producer():
    return Producer({
        'bootstrap.servers': KAFKA_BROKER
    })

def run():
    consumer = create_consumer()
    producer = create_producer()

    consumer.subscribe([INPUT_TOPIC])

    print("🚀 Alert Sink rodando...")

    while True:
        msg = consumer.poll(1.0)

        if msg is None:
            continue

        if msg.error():
            print(f"Erro: {msg.error()}")
            continue

        data = json.loads(msg.value().decode("utf-8"))
        print(f"📩 Recebido: {data}")

        # repassa como alerta simples
        producer.produce(
            OUTPUT_TOPIC,
            json.dumps(data).encode("utf-8")
        )
        producer.flush()

if __name__ == "__main__":
    run()