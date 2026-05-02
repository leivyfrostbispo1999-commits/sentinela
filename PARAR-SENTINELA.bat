@echo off
title PARANDO SENTINELA

echo.
echo ========================================================
echo     PARANDO TODOS OS SERVICOS DO SENTINELA
echo ========================================================
echo.

echo Parando Dashboard Web...
taskkill /FI "WINDOWTITLE eq 4 - Dashboard Web*" /F >nul 2>&1

echo Parando Dashboard API...
taskkill /FI "WINDOWTITLE eq 3 - Dashboard API*" /F >nul 2>&1

echo Parando Rule Engine...
taskkill /FI "WINDOWTITLE eq 2 - Rule Engine*" /F >nul 2>&1

echo Parando Log Collector...
taskkill /FI "WINDOWTITLE eq 1 - Log Collector*" /F >nul 2>&1

echo Limpando processos Python antigos do Sentinela...
powershell -NoProfile -ExecutionPolicy Bypass -Command "$all = Get-CimInstance Win32_Process; $roots = $all | Where-Object { $_.CommandLine -match 'services\\log_collector\\main.py|services\\rule_engine\\main.py|http.server 8080|D:\\sentinela\\services\\dashboard_api|services\\dashboard_api' }; function Stop-Tree($procId) { $all | Where-Object { $_.ParentProcessId -eq $procId } | ForEach-Object { Stop-Tree $_.ProcessId }; Stop-Process -Id $procId -Force -ErrorAction SilentlyContinue }; $roots | ForEach-Object { Stop-Tree $_.ProcessId }" >nul 2>&1

echo Liberando portas do dashboard...
powershell -NoProfile -ExecutionPolicy Bypass -Command "Get-NetTCPConnection -LocalPort 5000,8080 -State Listen -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess -Unique | ForEach-Object { Stop-Process -Id $_ -Force -ErrorAction SilentlyContinue }" >nul 2>&1

echo.
echo Todos os servicos do Sentinela foram parados.
echo.
pause
