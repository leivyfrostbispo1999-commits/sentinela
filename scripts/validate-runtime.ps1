<#
.SYNOPSIS
Valida o ambiente runtime do Sentinela (Servicos, APIs, Bancos de Dados e Observabilidade).
#>

Write-Host "Validando ambiente runtime do Sentinela..." -ForegroundColor Cyan

# 1. Checar containers em execucao
Write-Host "Checando status dos containers no Docker Compose..." -ForegroundColor Yellow
$ps_output = docker compose ps --format json
if (-not $ps_output) {
    Write-Host "Nenhum container rodando." -ForegroundColor Red
} else {
    docker compose ps
}

# 2. Aguardar Healthchecks
Write-Host "Aguardando 20 segundos para os healthchecks iniciais..." -ForegroundColor Yellow
Start-Sleep -Seconds 20

# 3. Validar Endpoints HTTP
$endpoints = @{
    "API Dashboard (Health)" = "http://127.0.0.1:5000/health"
    "API Dashboard (Ready)" = "http://127.0.0.1:5000/ready"
    "Prometheus (Ready)" = "http://127.0.0.1:9090/-/ready"
    "Grafana (Health)" = "http://127.0.0.1:3000/api/health"
    "Rule Engine Metrics" = "http://127.0.0.1:8000/health"
}

foreach ($name in $endpoints.Keys) {
    $url = $endpoints[$name]
    Write-Host "Checando $name ($url)..." -NoNewline
    try {
        $response = Invoke-RestMethod -Uri $url -Method Get -TimeoutSec 5 -ErrorAction Stop
        Write-Host " OK" -ForegroundColor Green
    } catch {
        Write-Host " FALHOU" -ForegroundColor Red
        Write-Host "  Erro: $($_.Exception.Message)" -ForegroundColor DarkGray
    }
}

# 4. Validar PostgreSQL e Kafka via command no container
Write-Host "Validando Banco de Dados PostgreSQL..." -NoNewline
try {
    $db_check = docker compose exec db pg_isready -U postgres -d postgres
    if ($LASTEXITCODE -eq 0) { Write-Host " OK" -ForegroundColor Green }
    else { Write-Host " FALHOU" -ForegroundColor Red }
} catch { Write-Host " FALHOU" -ForegroundColor Red }

Write-Host "Validando Kafka Broker..." -NoNewline
try {
    $kafka_check = docker compose exec kafka kafka-topics --bootstrap-server 127.0.0.1:9092 --list
    if ($LASTEXITCODE -eq 0) { Write-Host " OK" -ForegroundColor Green }
    else { Write-Host " FALHOU" -ForegroundColor Red }
} catch { Write-Host " FALHOU" -ForegroundColor Red }

Write-Host "Validação finalizada." -ForegroundColor Cyan
