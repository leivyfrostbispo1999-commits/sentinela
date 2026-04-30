import time, os, json
from confluent_kafka import Consumer, Producer

print("🚀 MODO TURBO ATIVADO: Rule Engine v4.1")

def conectar():
    while True:
        try:
            c = Consumer({'bootstrap.servers': 'kafka:9092', 'group.id': 're-fast-v5', 'auto.offset.reset': 'latest'})
            p = Producer({'bootstrap.servers': 'kafka:9092', 'linger.ms': 0})
            c.list_topics(timeout=5)
            print("✅ Conectado ao Kafka!")
            return c, p
        except:
            time.sleep(2)

def classificar(ip):
    if ip.startswith("172.16"): return "🔴 ATAQUE: Brute Force", 90
    if ip.startswith("10."): return "🟡 AVISO: Port Scan", 50
    return "🟢 NORMAL: Tráfego Comum", 10

consumer, producer = conectar()
consumer.subscribe(["raw_logs"])

while True:
    msg = consumer.poll(0.1)
    if msg is None or msg.error(): continue

    try:
        data = json.loads(msg.value().decode('utf-8'))
        ip = data.get("ip", "0.0.0.0")
        tipo, risco = classificar(ip)
        
        alerta = {"ip": ip, "status": tipo, "nivel_risco": risco, "ts": data.get("ts")}
        
        producer.produce("processed_logs", value=json.dumps(alerta).encode('utf-8'))
        producer.flush() # Envia imediatamente
        print(f"⚡ Processado: {ip} | {tipo}")
    except Exception as e:
        print(f"Erro: {e}")
