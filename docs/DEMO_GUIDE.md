# Guia Rápido de Demonstração (Demo)

Este guia cobre como apresentar as principais funcionalidades do Sentinela de ponta a ponta.

## 1. Subir o Ambiente Completo
Rode: `docker compose up -d`
Aguarde alguns segundos e valide em: `.\scripts\validate-runtime.ps1`

## 2. Visitar o Dashboard (Interface do Analista)
Abra no navegador: `http://localhost:8080`
Você verá uma tela limpa, sem ameaças.

## 3. Gerar Um Ataque Simulado
Abra outro terminal e rode:
```powershell
python scripts/replay_attack.py --count 50
```
Isso disparará eventos de Bruteforce.

## 4. Ver as Defesas em Ação (Dashboard)
Retorne para `http://localhost:8080`.
Você verá novos incidentes sendo criados, agregando as tentativas de login. O SOC Dashboard exibirá a severidade subindo em tempo real.

## 5. Visualizar a Resiliência no Grafana
Abra o Grafana em `http://localhost:3000` (admin / sentinela).
Entre no dashboard *Operational Maturity*.
Observe as linhas de throughput do Kafka (Events In/Out) e latência da API subindo proporcionalmente à injeção de dados.

## 6. Mostrar Observabilidade Técnica
Mostre a resposta imediata da API:
```powershell
Invoke-RestMethod http://localhost:5000/health
```
Isso prova que a camada de frontend não degringolou junto com o grande fluxo em background (Kafka salvou o dia).
