# Defesa Técnica para Entrevista

## 1. Resumo do Projeto

O SENTINELA é um mini-SIEM educacional/profissional com arquitetura inspirada em ambientes reais de SOC. Ele coleta eventos, usa Kafka como barramento, processa regras em Python, aplica correlação temporal, enriquece alertas com Threat Intelligence, persiste dados no PostgreSQL e apresenta um dashboard SOC em tempo real.

## 2. Problema Que Ele Resolve

O projeto demonstra como transformar eventos brutos em alertas acionáveis. Ele cobre ingestão, desacoplamento, detecção, scoring de risco, enriquecimento, histórico, métricas e visualização.

## 3. Por Que Kafka Foi Usado

Kafka foi escolhido para desacoplar coleta, processamento e persistência. Ele permite retenção, replay, consumer groups e absorção de picos. Essa escolha aproxima o projeto de arquiteturas reais de detecção orientadas a eventos.

## 4. Como Funciona o Rule Engine

O `rule_engine` consome eventos de `raw_logs`, mantém uma janela temporal em memória, carrega regras de `rules.yaml`, avalia sequência e frequência de eventos, consulta Threat Intelligence, calcula risco e publica alertas enriquecidos em `security_alerts`.

## 5. Como Funciona a Correlação Temporal

Eventos são agrupados por IP e avaliados dentro de uma janela configurável. Eventos antigos expiram. A correlação considera IP, serviço, porta e tipo de evento, gerando `correlation_key` e `correlation_reason` para explicar por que o alerta foi classificado daquela forma.

## 6. Como Funciona a Threat Intelligence

O projeto usa uma base local de IOCs e uma fonte externa simulada com cache. Quando há correspondência, o alerta recebe `threat_intel_match=true`, categoria, descrição e `threat_source`.

## 7. Como Funciona o Simulated Block

O projeto não executa bloqueio real. `ENABLE_BLOCK=false` permanece como padrão obrigatório. Quando um evento tem alto risco, status crítico ou IOC detectado, o alerta recebe `simulated_block=true`. Isso demonstra resposta automatizada sem risco operacional.

## 8. Limitações Atuais

- Kafka está em nó único.
- Correlação é local e em memória.
- Threat Intelligence externa é simulada.
- Autenticação é token simples.
- Não há RBAC.
- Não há schema registry.
- Não há DLQ formal.
- Prometheus está documentado, mas não é serviço obrigatório no Compose.

## 9. Como Escalaria Para Produção

Eu escalaria Kafka com múltiplos brokers, replication factor adequado e partitions planejadas. Manteria afinidade por IP na chave de particionamento, adicionaria state store distribuído para correlação, schema registry, DLQ, migrações versionadas, Prometheus/Grafana e alertas para consumer lag, falhas de escrita e crescimento de incidentes críticos.

## 10. Perguntas Prováveis e Respostas

**Isso é um SIEM completo?**  
Não. É um mini-SIEM de portfólio com arquitetura inspirada em SOC real. Ele demonstra fundamentos importantes, mas não substitui ferramentas corporativas.

**Por que usar Kafka?**  
Para desacoplar componentes, permitir replay, lidar melhor com picos e escalar consumidores por consumer group.

**Como o projeto evita duplicidade?**  
O banco usa `event_id` único e o `alert_sink` grava com estratégia idempotente.

**Por que o bloqueio é simulado?**  
Porque bloqueio real exige governança, allowlist, rollback, aprovação e auditoria. Em um portfólio, `simulated_block` demonstra a lógica sem risco operacional.

**Qual é o próximo passo mais importante?**  
Adicionar estado distribuído para correlação, DLQ, validação formal de schema e observabilidade completa de Kafka.
