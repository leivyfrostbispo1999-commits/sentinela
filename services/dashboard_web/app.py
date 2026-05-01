from flask import Flask, render_template_string
import json

app = Flask(__name__)

HTML = """
<!DOCTYPE html>
<html>
<head><title>Sentinela Dashboard</title></head>
<body>
<h1>🚨 Sentinela IDS Dashboard</h1>
<p>Alertas em tempo real aparecerão aqui.</p>
<pre id="logs"></pre>

<script>
setInterval(() => {
  fetch('/alerts')
  .then(r => r.text())
  .then(data => document.getElementById('logs').textContent = data);
}, 2000);
</script>
</body>
</html>
"""

@app.route('/')
def home():
    return render_template_string(HTML)

@app.route('/alerts')
def alerts():
    # Aqui vai vir os alertas (por enquanto mock)
    return "Nenhum alerta ainda...\nTente rodar o simulator!"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)