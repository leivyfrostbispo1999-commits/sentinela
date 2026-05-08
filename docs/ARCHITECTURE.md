# SENTINELA Architecture: AI-Native Security Operations

O SENTINELA é uma plataforma modular projetada para XDR, Graph Analytics e SOC Autônomo.

## Camadas da Plataforma
1. **Telemetry Layer**: Ingestão cross-domain via Kafka (Endpoint eBPF, Network, CloudTrail, Identity).
2. **Enrichment Layer**: Contextualização geográfica e reputacional em tempo real.
3. **Analytics Layer (Flink)**: Processamento de stream stateful e Complex Event Processing (CEP) para detecção de Kill Chain.
4. **Graph Layer (Neo4j)**: Modelagem de entidades e relações em um Security Knowledge Graph.
5. **AI Layer**: Detecção de anomalias via Isolation Forest (scikit-learn) e triagem cerebral via Security Copilot.
6. **Response Layer (SOAR)**: Execução de playbooks governados e remediação automatizada semi-autônoma.

## Componentes Principais

### 1. Ingestão e Processamento (XDR)
- **Log Collector:** Recebe telemetria de domínios variados (Endpoint, Cloud, SaaS).
- **Kafka Pipeline:** Orquestra o fluxo de dados entre enriquecimento e motores analíticos.
- **Rule Engine:** Motor de correlação unitária e agregada com estado em Redis.

### 2. Stream & Graph Intelligence
- **Apache Flink:** Executa matemática temporal distribuída para identificar sequências de intrusão.
- **Neo4j Graph:** Mantém o grafo de relacionamentos entre usuários, hosts e recursos, permitindo Attack Path Inference.

### 3. AI & Automation
- **AI Engine:** Aplica modelos de Isolation Forest para detectar anomalias estatísticas sem regras fixas.
- **SOC Copilot:** Assistente LLM-based para suporte analítico N3.
- **SOAR Engine:** Executa respostas defensivas baseadas em risco e governança humana.

## Tolerância a Falhas
A plataforma implementa o padrão de **Dead Letter Queue (DLQ)**. Eventos inválidos ou com erro intermitente de banco de dados sofrem *retry exponencial* antes de serem movidos para a DLQ, assegurando *zero message loss*.
