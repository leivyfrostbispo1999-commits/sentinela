from flask import Flask, jsonify, request
import json
from threading import Lock

app = Flask(__name__)
alerts = []
lock = Lock()

@app.route('/alert', methods=['POST'])
def add_alert():
    try:
        alert = request.get_json()
        with lock:
            alerts.append(alert)
        print(f"📨 Alerta recebido na API: {alert.get('type')} - {alert.get('ip')}")
        return jsonify({"status": "received"})
    except Exception as e:
        print(f"Erro ao receber alerta: {e}")
        return jsonify({"status": "error"}), 400

@app.route('/alerts')
def get_alerts():
    with lock:
        return jsonify(alerts[-50:])  # últimos 50 alertas

if __name__ == '__main__':
    print("🚀 Dashboard API rodando na porta 5000...")
    app.run(host='0.0.0.0', port=5000, debug=False)