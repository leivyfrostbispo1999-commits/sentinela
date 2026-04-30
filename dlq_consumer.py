from confluent_kafka import Consumer

c = Consumer({
    'bootstrap.servers': 'kafka:9092', # Se rodar fora do Docker, use 'localhost:9092'
    'group.id': 'dlq-group',
    'auto.offset.reset': 'earliest'
})

c.subscribe(['dlq'])

print("DLQ listening...")

while True:
    msg = c.poll(1.0)
    if msg is None:
        continue
    if msg.error():
        print(f"Erro: {msg.error()}")
        continue

    print("DLQ MESSAGE:", msg.value().decode('utf-8'))
