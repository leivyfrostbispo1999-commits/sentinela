\# 🛡️ Sentinela SIEM



Sistema de detecção e resposta a intrusão (SIEM) inspirado em arquiteturas reais de SOC (Security Operations Center), construído com pipeline distribuído baseado em eventos.



O Sentinela simula tráfego malicioso, processa eventos em tempo real, detecta padrões de ataque e gera alertas persistidos com visualização operacional.



\---



\## 🚀 Arquitetura



```text

\[ Simulator ]

&#x20;     ↓

Kafka (raw\_logs)

&#x20;     ↓

\[ Rule Engine - Detecção em Tempo Real ]

&#x20;     ↓

Kafka (alerts)

&#x20;     ↓

\[ Alert Sink ]

&#x20;     ↓

PostgreSQL (persistência)

&#x20;     ↓

\[ Flask API ]

&#x20;     ↓

\[ SOC Dashboard (Web UI) ]

🔄 Fluxo de Dados

O Simulator gera eventos simulando tráfego de rede

Os eventos são publicados no Kafka (raw\_logs)

O Rule Engine analisa em tempo real usando Sliding Window

Ataques são detectados e convertidos em alertas

Alertas são publicados no tópico alerts

O Alert Sink persiste os eventos no PostgreSQL

A API expõe os dados via endpoints REST

O Dashboard apresenta métricas e ataques em tempo real

⚙️ Tecnologias

Python 3.11

Docker / Docker Compose

Apache Kafka

PostgreSQL

Flask (API + Dashboard)

Confluent Kafka Client

Chart.js

🧠 Módulos do Sistema


📡 Simulator

Geração de tráfego simulado

Publicação de logs no Kafka (raw\_logs)


🧮 Rule Engine

Sliding Window (10s)

Detecção de brute force

Risk scoring (0–100%)

Geração de alertas


💾 Alert Sink

Consome Kafka (alerts)

Persiste no PostgreSQL

Garantia de durabilidade dos eventos

🌐 API + Dashboard SOC

KPIs de segurança

Top atacantes

Alertas recentes

Gráficos de tendência

Detecção de anomalias

📊 Funcionalidades

Detecção de brute force em tempo real

Pipeline distribuído com Kafka

Processamento streaming

Persistência em PostgreSQL

Dashboard SOC interativo

Visualização de ataques

Risk scoring por comportamento

📈 Métricas

Volume de alertas por minuto

Top IPs atacantes

Taxa de crescimento de ataques

Detecção de anomalia

Risk Score (0–100%)


🐳 Como executar
docker compose up --build -d


🌍 Acesso

http://localhost:5000


🎯 Objetivo



Simular um ambiente real de:



SOC (Security Operations Center)

SIEM distribuído

Arquitetura orientada a eventos

Pipeline de segurança em tempo real


🚀 Evoluções futuras

SOAR (bloqueio automático de IPs)

Detecção de port scan

Machine Learning para anomalias

Integração com Slack/Telegram

Deploy em cloud (AWS/Azure)


👨‍💻 Autor



Projeto de estudo em:



DevSecOps

Engenharia de Segurança

Sistemas Distribuídos

Kafka Streaming

SIEM Architecture

⚠️ Nota



Projeto educacional para simulação de ambiente de segurança e detecção de ameaças.










