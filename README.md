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
