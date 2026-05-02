@echo off
title 🚀 SENTINELA IDS - Sistema Completo

echo.
echo ========================================================
echo     SENTINELA - INICIALIZAÇÃO AUTOMÁTICA
echo ========================================================
echo.

echo [1/4] Iniciando Log Collector...
start "1 - Log Collector" cmd /k "cd /d D:\sentinela && py services\log_collector\main.py"
timeout /t 3 >nul

echo [2/4] Iniciando Rule Engine...
start "2 - Rule Engine" cmd /k "cd /d D:\sentinela && py services\rule_engine\main.py"
timeout /t 3 >nul

echo [3/4] Iniciando Dashboard API...
start "3 - Dashboard API" cmd /k "cd /d D:\sentinela\services\dashboard_api && py main.py"
timeout /t 3 >nul

echo [4/4] Iniciando Dashboard Web...
start "4 - Dashboard Web" cmd /k "cd /d D:\sentinela\services\dashboard_web && py -m http.server 8080"

echo.
echo ✅ SENTINELA INICIADO COM SUCESSO!
echo.
echo 🌐 Acesse agora: http://localhost:8080
echo.
echo Deixe todas as janelas abertas.
echo.
pause