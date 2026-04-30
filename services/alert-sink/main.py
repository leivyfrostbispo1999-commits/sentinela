import time, os, json, psycopg2
from confluent_kafka import Consumer
def conectar():
    while True:
        try:
            c = Consumer({'bootstrap.servers': 'kafka:9092', 'group.id': 'as-final-v9', 'auto.offset.reset': 'earliest'})
            c.list_topics(timeout=5); print('Kafka OK')
            conn = psycopg2.connect('host=db dbname=postgres user=postgres password=root')
            cur = conn.cursor()
            cur.execute('CREATE TABLE IF NOT EXISTS alertas (id SERIAL, ip TEXT, status TEXT, risco INTEGER, ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP)'); conn.commit()
            print('Banco OK')
            return c, conn, cur
        except Exception as e:
            print(f'Erro: {e}'); time.sleep(5)
cons, conn, cur = conectar()
cons.subscribe(['processed_logs'])
while True:
    msg = cons.poll(1.0)
    if msg is None or msg.error(): continue
    d = json.loads(msg.value().decode('utf-8'))
    cur.execute('INSERT INTO alertas (ip, status, risco) VALUES (%s, %s, %s)', (d['ip'], d['status'], d['nivel_risco']))
    conn.commit(); print('?? GRAVADO: ' + d['ip'])
