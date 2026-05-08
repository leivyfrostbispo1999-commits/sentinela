# Próximos Passos Arquiteturais

Para o próximo ciclo evolutivo do Sentinela, visando maior escalabilidade e cenários de implantação em provedores cloud, os seguintes itens estão no roadmap:

## 1. High Availability e Escalonamento
- **Fanout HA (Alta Disponibilidade):** Adicionar instâncias concorrentes para Rule Engine e Alert Sink.
- **Kafka Fanout:** Dividir tópicos usando chaves de partição e escalar consumers.

## 2. Rate Limiting e Cache Avançado
- **Redis Rate Limiting Dinâmico:** Implementar algoritmo *Token Bucket* compartilhado via Redis Pub/Sub para rate limiting distribuído na API, não apenas em memória local.

## 3. Arquitetura Multi-Tenant
- **Multi-Tenancy Isolado:** Isolar dados de clientes (tenants) seja por schemas no banco de dados ou utilizando chaves de tenant no Kafka e OpenSearch.
- **Role-Based Access Control (RBAC):** Adicionar matrizes de permissão por tenant.

## 4. Evolução das Operações (SOC)
- **Alert Correlation OOTB:** Correlação automática multicanal.
- **Incident Timeline:** Exibição gráfica e cronológica de intrusão usando a API.
- **Políticas Avançadas de Retenção:** Jobs programados (CronJobs/Kubernetes) em vez de scripts manuais.
