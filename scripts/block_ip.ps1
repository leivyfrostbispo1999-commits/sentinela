param([string]$IP)

Write-Host "🔒 Bloqueando IP: $IP" -ForegroundColor Red

# Adiciona regra de bloqueio no Firewall do Windows
$ruleName = "Sentinela_Block_$IP"

netsh advfirewall firewall add rule name=$ruleName dir=in action=block remoteip=$IP enable=yes > $null

Write-Host "✅ IP $IP bloqueado com sucesso!" -ForegroundColor Green