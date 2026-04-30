from flask import Flask, jsonify
from flask_cors import CORS
import psycopg2
import time

app = Flask(__name__)
CORS(app) # Isso permite que o site acesse a API

def get_db_connection():
    return psycopg2.connect("host=db dbname=postgres user=postgres password=root")

@app.route('/alertas')
def listar_alertas():
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        # Busca os últimos 50 alertas
        cur.execute("SELECT ip, status, risco, ts FROM alertas ORDER BY ts DESC LIMIT 50")
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
        return jsonify([]) # Retorna lista vazia se o banco estiver subindo

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
