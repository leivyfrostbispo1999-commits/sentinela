<<<<<<< HEAD
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










=======
# 🛡️ Sentinela SIEM

Sistema de Detecção e Resposta a Intrusão (SIEM) distribuído, baseado em arquitetura orientada a eventos, inspirado em ambientes reais de SOC (Security Operations Center).

O Sentinela simula tráfego malicioso, processa eventos em tempo real, detecta padrões de ataque e gera alertas com persistência e visualização operacional.

---

## 🏗️ Arquitetura do Sistema

```
[ Simulator ]
      ↓
Kafka (raw_logs)
      ↓
[ Rule Engine - Stream Processing ]
      ↓
Kafka (alerts)
      ↓
[ Alert Sink ]
      ↓
PostgreSQL (persistência)
      ↓
[ Flask API ]
      ↓
[ SOC Dashboard ]
```

---

## 🔄 Pipeline de Dados

- Geração de logs simulados de rede
- Ingestão via Apache Kafka
- Processamento em tempo real (streaming)
- Detecção de ataques com Sliding Window
- Geração de alertas estruturados
- Persistência em banco relacional
- Exposição via API REST
- Visualização em dashboard SOC

---

## ⚙️ Stack Tecnológica

- Python 3.11
- Docker / Docker Compose
- Apache Kafka (KRaft mode)
- PostgreSQL
- Flask (API + Dashboard)
- Confluent Kafka Client
- Chart.js (visualização)

---

## 🧠 Módulos do Sistema

### 📡 Simulator
- Geração contínua de tráfego simulado
- Produção de eventos para Kafka (`raw_logs`)

---

### 🧮 Rule Engine
- Processamento streaming em tempo real
- Sliding Window (10 segundos)
- Detecção de brute force
- Risk scoring dinâmico (0–100%)
- Publicação de alertas no Kafka (`alerts`)

---

### 💾 Alert Sink
- Consumo do tópico `alerts`
- Persistência no PostgreSQL
- Garantia de durabilidade dos eventos
- Separação entre processamento e armazenamento

---

### 🌐 API + SOC Dashboard
- Exposição de dados via REST API
- KPIs de segurança em tempo real
- Top atacantes (Top N IPs)
- Gráficos de tendência de ataques
- Detecção de anomalias
- Interface SOC operacional

---

## 📊 Capacidades do Sistema

- Detecção de brute force em tempo real
- Arquitetura distribuída orientada a eventos
- Pipeline de streaming com Kafka
- Persistência transacional em PostgreSQL
- Dashboard SOC com atualização contínua
- Análise de comportamento de ataque
- Risk scoring baseado em volume e tempo

---

## 📈 Métricas de Segurança

- Volume de alertas por minuto
- Top IPs ofensores
- Taxa de crescimento de ataques
- Detecção de anomalias (baseline simples)
- Risk Score por comportamento

---

## 🐳 Execução

```bash
docker compose up --build -d
```

---

## 🌍 Acesso

Dashboard SOC:
```
http://localhost:5000
```

---

## 🎯 Objetivo

Simular um ambiente real de:

- SOC (Security Operations Center)
- SIEM distribuído
- Arquitetura orientada a eventos
- Pipeline de segurança em tempo real
- Detecção de ameaças baseada em comportamento

---

## 🚀 Evoluções Futuras

- SOAR (resposta automática e bloqueio de IPs)
- Detecção de port scan
- Machine Learning para anomalias
- Integração com Slack / Telegram
- Deploy em cloud (AWS / Azure)
- Multi-tenant SIEM architecture

---

## 👨‍💻 Autor

Projeto educacional voltado a:

- Engenharia de Segurança
- DevSecOps
- Sistemas Distribuídos
- Streaming com Kafka
- Arquitetura SIEM moderna

---

## ⚠️ Nota

Este projeto possui fins educacionais e de simulação de ambiente SOC/SIEM.
>>>>>>> 0b9d8956e58eb71fe1426fdc4e54d53c2a5428cc
