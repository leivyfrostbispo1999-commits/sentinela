param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("core", "analytics", "graph", "search", "full")]
    [string]$Profile = "core",

    [Parameter(Mandatory=$false)]
    [int]$TimeoutSeconds = 120,

    [Parameter(Mandatory=$false)]
    [switch]$Rebuild,

    [Parameter(Mandatory=$false)]
    [switch]$Prune,

    [Parameter(Mandatory=$false)]
    [switch]$SkipPrune
)

Write-Host "🛡️ [SENTINELA RECOVERY] Iniciando protocolo de restauração do Docker Desktop..." -ForegroundColor Cyan

# 1. Encerrar WSL
Write-Host "🛑 Encerrando subsistema WSL..." -ForegroundColor Yellow
wsl --shutdown

# 2. Matar processos travados do Docker
Write-Host "🔫 Finalizando processos do Docker Desktop no Windows..." -ForegroundColor Yellow
$dockerProcesses = @("Docker Desktop", "com.docker.backend", "com.docker.proxy", "com.docker.vpnkit", "DockerCli", "docker")
foreach ($proc in $dockerProcesses) {
    Stop-Process -Name $proc -ErrorAction SilentlyContinue -Force
}

# 3. Reiniciar Docker Desktop
$dockerPath = "C:\Program Files\Docker\Docker\Docker Desktop.exe"
if (Test-Path $dockerPath) {
    Write-Host "🚀 Iniciando Docker Desktop..." -ForegroundColor Green
    Start-Process $dockerPath
} else {
    Write-Error "❌ Executável do Docker Desktop não encontrado em: $dockerPath"
    return
}

# 4. Aguardar Daemon
Write-Host "⏳ Aguardando daemon responder (Timeout: $TimeoutSeconds s)..." -ForegroundColor Cyan
$start = Get-Date
$daemonReady = $false

while (((Get-Date) - $start).TotalSeconds -lt $TimeoutSeconds) {
    & docker version >$null 2>&1
    if ($LASTEXITCODE -eq 0) {
        $daemonReady = $true
        break
    }
    Write-Host "." -NoNewline
    Start-Sleep -Seconds 3
}

if (-not $daemonReady) {
    Write-Host "`n❌ TIMEOUT: O Docker não subiu a tempo." -ForegroundColor Red
    Write-Host "👉 AÇÕES MANUAIS NECESSÁRIAS:" -ForegroundColor Yellow
    Write-Host "1. Abra o Docker Desktop manualmente e aguarde o status 'Running'."
    Write-Host "2. Verifique: Settings > Resources (Mínimo: 12GB RAM, 6 CPUs)."
    Write-Host "3. Reinicie o computador se o problema persistir."
    return
}

Write-Host "`n✅ Docker Daemon operacional!" -ForegroundColor Green

# 5. Operações de Limpeza (se solicitado)
if ($Prune) {
    Write-Host "🧹 Executando 'docker system prune'..." -ForegroundColor Yellow
    & docker system prune -f
}

# 6. Orquestração de Containers
Write-Host "🏗️ Subindo Perfil [$($Profile.ToUpper())] do SENTINELA..." -ForegroundColor Cyan
Set-Location "D:\sentinela"

if ($Rebuild) {
    Write-Host "🔨 Reconstruindo imagens (--no-cache)..." -ForegroundColor Yellow
    & docker compose --profile $Profile build --no-cache
}

& docker compose --profile $Profile up -d

# 7. Validação Final
Write-Host "📊 Estado dos containers:" -ForegroundColor Cyan
& docker compose --profile $Profile ps

Write-Host "`n✨ SENTINELA Restaurado com sucesso!" -ForegroundColor Green
Write-Host "🔗 API: http://localhost:5000/ready" -ForegroundColor Gray
Write-Host "🔗 Dashboard: http://localhost:8080" -ForegroundColor Gray
