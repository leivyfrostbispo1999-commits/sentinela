<#
.SYNOPSIS
Script para realizar um rebuild limpo do Sentinela.

.DESCRIPTION
Este script executa a sequencia de comandos solicitada para garantir um ambiente 100% novo e reproduzivel,
limpando volumes, removendo imagens antigas (prune), buildando sem cache e subindo os conteineres.
#>

Write-Host "Iniciando Rebuild Limpo do Sentinela..." -ForegroundColor Cyan

Write-Host "1. Derrubando containers e volumes (docker compose down -v)..." -ForegroundColor Yellow
docker compose down -v

Write-Host "2. Limpando sistema Docker (docker system prune -af)..." -ForegroundColor Yellow
# Removendo forcadamente imagens não utilizadas e containers parados.
docker system prune -af

Write-Host "3. Buildando servicos sem cache (docker compose build --no-cache)..." -ForegroundColor Yellow
docker compose build --no-cache

Write-Host "4. Subindo ambiente (docker compose up -d)..." -ForegroundColor Yellow
docker compose up -d

Write-Host "Rebuild finalizado com sucesso! Aguarde os healthchecks estabilizarem." -ForegroundColor Green
Write-Host "Recomendamos rodar .\scripts\validate-runtime.ps1 em seguida." -ForegroundColor Cyan
