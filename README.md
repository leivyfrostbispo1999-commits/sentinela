# 🛡️ Sentinela IDS | Tactical Command Center

![Status](https://shields.io)
![Architecture](https://shields.io)
![DB](https://shields.io)

O **Sentinela** é um sistema de detecção e resposta a intrusão (IDS) de alta performance, projetado para monitoramento de infraestrutura em tempo real. Utilizando uma arquitetura orientada a eventos, o sistema transforma logs brutos em inteligência de segurança acionável.

## 🚀 Diferenciais Tecnológicos

- **Kafka em modo KRaft:** Arquitetura moderna sem dependência de Zookeeper para baixa latência e alta disponibilidade.
- **Stateful Rule Engine:** Motor de regras com memória para detecção de padrões e bloqueio automático de IPs após recorrência de ofensas.
- **Persistence Layer:** Camada de persistência desacoplada gravando alertas críticos diretamente em um cluster PostgreSQL.
- **Elite Dashboard:** Interface visual "Military-Grade" com psicologia das cores aplicada para tomada de decisão em segundos.

## 🏗️ Arquitetura do Sistema

1.  **Simulator:** Ingestão de tráfego simulando cenários reais de ataques (Brute Force, Port Scan e Tráfego Normal).
2.  **Apache Kafka:** Barramento de mensagens gerenciando os tópicos `raw_logs` e `processed_logs`.
3.  **Rule Engine (IDS):** Cérebro do sistema que classifica ameaças e aplica políticas de firewall.
4.  **Alert Sink:** Serviço responsável pela persistência idempotente no banco de dados.
5.  **Dashboard API:** API REST (Flask) que serve os dados processados para a interface.
6.  **Web Command Center:** Interface "Glassmorphism" para monitoramento em tempo real.

## 🛠️ Tecnologias Utilizadas

- **Linguagem:** Python 3.11
- **Mensageria:** Apache Kafka (Confluent)
- **Banco de Dados:** PostgreSQL 15
- **Infraestrutura:** Docker & Docker Compose
- **Web:** Nginx, JavaScript (ES6), HTML5/CSS3

## 📊 Como Visualizar o Sistema

Após subir o ambiente com Docker, o painel de operações pode ser acessado via:
👉 `http://localhost`

Para auditoria técnica dos tópicos Kafka:
👉 `http://localhost:8080` (Kafka UI)

---
*Projeto desenvolvido com foco em padrões de engenharia de segurança e escalabilidade horizontal.*
