# SENTINELA CORE IDS

Sistema de Detecção e Resposta a Intrusões (IDS) moderno, event-driven, construído com Docker, Kafka KRaft e Python.

## Funcionalidades

- Detecção em tempo real de Brute Force e Port Scan
- Contagem stateful por IP
- Bloqueio automático de IP
- Blacklist persistente
- Dashboard web em tempo real
- Arquitetura escalável com Kafka

## Como rodar

```bash
cd D:\sentinela
# Inicie o Kafka
docker-compose up -d kafka

# Inicie os serviços
py services\log_collector\main.py
py services\rule_engine\main.py
# Dashboard API e Web...