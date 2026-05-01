@echo off
cd /d C:\sentinela

echo ==========================
echo BACKUP SENTINELA INICIADO
echo ==========================

git add .
git commit -m "auto backup %date% %time%"
git push origin main

echo ==========================
echo BACKUP CONCLUIDO
echo ==========================
pause