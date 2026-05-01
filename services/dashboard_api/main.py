from flask import Flask, jsonify
from flask_cors import CORS
import psycopg2
<<<<<<< HEAD
from datetime import datetime

app = Flask(__name__)
CORS(app) 

def get_db_connection():
    # Ajustado para o nome do container e credenciais corretas
    return psycopg2.connect("host=sentinela-db dbname=sentinela user=postgres password=postgres")
=======
import time

app = Flask(__name__)
CORS(app) # Isso permite que o site acesse a API

def get_db_connection():
    return psycopg2.connect("host=db dbname=postgres user=postgres password=root")
>>>>>>> f33ed383d8e88d290a27dd7885af588db7e1ce40

@app.route('/alertas')
def listar_alertas():
    try:
        conn = get_db_connection()
        cur = conn.cursor()
<<<<<<< HEAD
        # Ajustado para as colunas reais: score_final e timestamp
        cur.execute("SELECT ip, status, score_final, timestamp FROM alertas ORDER BY timestamp DESC LIMIT 50")
=======
        # Busca os últimos 50 alertas
        cur.execute("SELECT ip, status, risco, ts FROM alertas ORDER BY ts DESC LIMIT 50")
>>>>>>> f33ed383d8e88d290a27dd7885af588db7e1ce40
        rows = cur.fetchall()
        alertas = []
        for r in rows:
            alertas.append({
                "ip": r[0],
                "status": r[1],
                "risco": r[2],
                "ts": r[3].strftime("%Y-%m-%d %H:%M:%S")
            })
        cur.close()
        conn.close()
        return jsonify(alertas)
    except Exception as e:
<<<<<<< HEAD
        print(f"Erro na API: {e}")
        return jsonify([])
=======
        return jsonify([]) # Retorna lista vazia se o banco estiver subindo
>>>>>>> f33ed383d8e88d290a27dd7885af588db7e1ce40

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
