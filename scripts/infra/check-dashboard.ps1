Write-Host "🔍 [SENTINELA DIAGNOSTIC] Verificando saúde do Dashboard..." -ForegroundColor Cyan

# 1. Verificar Docker Daemon
& docker version >$null 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Erro: Docker Daemon não está respondendo." -ForegroundColor Red
    Write-Host "👉 Execute: ./scripts/infra/recover-docker.ps1 -Profile core" -ForegroundColor Yellow
    return
}

# 2. Verificar Containers do Profile CORE
Write-Host "📦 Verificando containers do profile CORE..." -ForegroundColor Cyan
$containers = & docker compose --profile core ps --format json | ConvertFrom-Json
$web = $containers | Where-Object { $_.Name -like "*dashboard-web*" }
$api = $containers | Where-Object { $_.Name -like "*dashboard-api*" }

if ($null -eq $web) {
    Write-Host "❌ Container do Dashboard Web não encontrado no profile CORE." -ForegroundColor Red
} elseif ($web.State -ne "running") {
    Write-Host "⚠️ Dashboard Web está em estado: $($web.State)" -ForegroundColor Yellow
} else {
    Write-Host "✅ Dashboard Web está rodando." -ForegroundColor Green
}

if ($null -eq $api) {
    Write-Host "❌ Container da Dashboard API não encontrado no profile CORE." -ForegroundColor Red
} elseif ($api.State -ne "running") {
    Write-Host "⚠️ Dashboard API está em estado: $($api.State)" -ForegroundColor Yellow
} else {
    Write-Host "✅ Dashboard API está rodando." -ForegroundColor Green
}

# 3. Verificar Portas no Host
Write-Host "🌐 Verificando portas no host Windows..." -ForegroundColor Cyan
$p8080 = netstat -ano | findstr :8080
$p5000 = netstat -ano | findstr :5000

if ($p8080) { Write-Host "✅ Porta 8080 detectada no host." -ForegroundColor Green }
else { Write-Host "❌ Porta 8080 NÃO está respondendo no host." -ForegroundColor Red }

if ($p5000) { Write-Host "✅ Porta 5000 detectada no host." -ForegroundColor Green }
else { Write-Host "❌ Porta 5000 NÃO está respondendo no host." -ForegroundColor Red }

# 4. Testar Endpoints
Write-Host "📡 Testando conectividade HTTP..." -ForegroundColor Cyan
try {
    $apiRes = Invoke-RestMethod -Uri "http://localhost:5000/ready" -Method Get -TimeoutSec 2
    Write-Host "✅ API /ready: OK" -ForegroundColor Green
} catch {
    Write-Host "❌ API /ready: Falhou" -ForegroundColor Red
}

try {
    $webRes = Invoke-WebRequest -Uri "http://localhost:8080" -Method Get -TimeoutSec 2
    Write-Host "✅ Dashboard HTTP 200: OK" -ForegroundColor Green
} catch {
    Write-Host "❌ Dashboard Web: Falhou (Connection Refused)" -ForegroundColor Red
}

# 5. Sugestão de Correção
Write-Host "`n🛠️ RECOMENDAÇÃO:" -ForegroundColor Cyan
Write-Host "Se você vê ERR_CONNECTION_REFUSED mas os containers aparecem como Up:"
Write-Host "1. Tente: docker compose --profile core up -d --force-recreate"
Write-Host "2. Verifique se o antivírus/firewall não está bloqueando as portas 5000/8080."
Write-Host "3. Se o Docker estiver instável: ./scripts/infra/recover-docker.ps1 -Profile core"
