# Arquitetura do Sentinela

## Visão Geral
O Sentinela é uma plataforma de detecção de ameaças e SIEM (Security Information and Event Management) focada em observabilidade, resiliência e alta performance. Foi arquitetado com base em microsserviços, utilizando mensageria assíncrona (Kafka) para garantir tolerância a falhas e desacoplamento.

## Componentes Principais

### 1. Ingestão e Processamento
- **Log Collector:** Recebe os logs brutos e padroniza para o formato interno.
- **Kafka Pipeline:** Desacopla a ingestão do processamento, evitando gargalos.
- **Rule Engine:** Avalia eventos em tempo real com base em regras YAML dinâmicas. Suporta janelas de correlação e rate-limiting (com estado no Redis).

### 2. Armazenamento e Histórico
- **PostgreSQL:** Banco de dados relacional robusto armazenando estado dos alertas, metadados e incidentes agregados.
- **Alert Sink:** Consumer que persiste alertas do Kafka no PostgreSQL.

### 3. Dashboard e API
- **Dashboard API:** Backend Flask assíncrono para a interface. Suporta JWT, Rate Limiting, Filtros dinâmicos e exportação de relatórios.
- **Dashboard Web:** Interface front-end estática para os analistas do SOC visualizarem as métricas, investigações e topologia.

### 4. Observabilidade (SRE)
- **Prometheus:** Coleta as métricas de tempo de resposta, latência e vazão de todos os componentes.
- **Grafana:** Exibe dashboards táticos (alertas) e operacionais (saúde da API, JVM, Garbage Collection).

## Tolerância a Falhas
A plataforma implementa o padrão de **Dead Letter Queue (DLQ)**. Eventos inválidos ou com erro intermitente de banco de dados sofrem *retry exponencial* antes de serem movidos para a DLQ, assegurando *zero message loss*.
