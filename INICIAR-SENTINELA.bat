@echo off
cd /d D:\sentinela
echo Iniciando Sentinela SOC...
docker compose up -d --build
echo Sistema iniciado com sucesso!
pause