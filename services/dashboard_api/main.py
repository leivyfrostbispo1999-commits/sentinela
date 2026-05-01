from flask import Flask, jsonify
from flask_cors import CORS
import psycopg2
from datetime import datetime

app = Flask(__name__)
CORS(app) 

def get_db_connection():
    # Ajustado para o nome do container e credenciais corretas
    return psycopg2.connect("host=sentinela-db dbname=sentinela user=postgres password=postgres")

@app.route('/alertas')
def listar_alertas():
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        # Ajustado para as colunas reais: score_final e timestamp
        cur.execute("SELECT ip, status, score_final, timestamp FROM alertas ORDER BY timestamp DESC LIMIT 50")
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
        print(f"Erro na API: {e}")
        return jsonify([])

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
