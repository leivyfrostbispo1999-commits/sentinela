import os
import json
from confluent_kafka import Consumer, Producer

BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")

consumer = Consumer({
    "bootstrap.servers": BOOTSTRAP,
    "group.id": "rule-engine",
    "auto.offset.reset": "earliest"
})

producer = Producer({
    "bootstrap.servers": BOOTSTRAP
})

consumer.subscribe(["raw_logs"])

print("Rule Engine iniciado...")

def score(ip):
    if ip.startswith("192.168"):
        return 20
    if ip.startswith("10."):
        return 50
    if ip.startswith("172.16"):
        return 80
    return 10

while True:
    msg = consumer.poll(1.0)

    if msg is None:
        continue

    if msg.error():
        print(msg.error())
        continue

    event = json.loads(msg.value().decode("utf-8"))

    alert = {
        "ip": event["ip"],
        "risk": score(event["ip"]),
        "ts": event["ts"]
    }

    producer.produce(
        "alerts",
        key=event["ip"],
        value=json.dumps(alert)
    )

    producer.poll(0)

    print("ALERTA:", alert)