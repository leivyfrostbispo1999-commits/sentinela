<!DOCTYPE html>
<html lang="pt">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SentinelaCore IDS</title>
    <style>
        body { font-family: 'Segoe UI', sans-serif; background: linear-gradient(#0f172a, #1e2937); color: #e2e8f0; margin: 0; padding: 20px; }
        h1 { text-align: center; color: #67e8f9; }
        .status { text-align: center; color: #4ade80; }
        .cards { display: flex; justify-content: center; gap: 20px; margin: 20px 0; flex-wrap: wrap; }
        .card { background: rgba(30, 41, 55, 0.9); padding: 20px; border-radius: 12px; text-align: center; width: 220px; box-shadow: 0 0 15px rgba(103, 232, 249, 0.3); }
        .card h2 { margin: 0; font-size: 3em; color: #67e8f9; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; background: rgba(30, 41, 55, 0.8); }
        th, td { padding: 14px; text-align: left; border-bottom: 1px solid #334155; }
        th { background: #1e40af; }
        .threat { color: #f87171; font-weight: bold; }
        .normal { color: #4ade80; }
    </style>
</head>
<body>
    <h1>🚨 SENTINELACORE_IDS</h1>
    <div class="status">● ONLINE - Sistema Ativo</div>
    
    <div class="cards">
        <div class="card"><h2>16</h2><p>THREAT NEUTRALIZED</p></div>
        <div class="card"><h2>21</h2><p>SUSPICIOUS ACTIVITY</p></div>
        <div class="card"><h2>13</h2><p>ENCRYPTED TRAFFIC</p></div>
    </div>

    <table id="alertTable">
        <tr><th>T-STAMP</th><th>SOURCE IP</th><th>STATUS</th><th>THREAT LEVEL</th></tr>
    </table>

    <script>
        setInterval(() => {
            fetch('http://localhost:5000/alerts')
            .then(r => r.json())
            .then(data => {
                const table = document.getElementById('alertTable');
                data.forEach(alert => {
                    const row = document.createElement('tr');
                    row.innerHTML = `
                        <td>${alert.timestamp || new Date().toLocaleString()}</td>
                        <td>${alert.ip || '10.0.0.x'}</td>
                        <td class="threat">${alert.type || 'ALERTA'}</td>
                        <td>50%</td>
                    `;
                    table.appendChild(row);
                });
            })
            .catch(() => {});
        }, 2000);
    </script>
</body>
</html>