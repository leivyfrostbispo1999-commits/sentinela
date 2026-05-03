# Defesa Técnica para Entrevista

## 1. Resumo do projeto

O SENTINELA é um mini-SIEM educacional/profissional com arquitetura inspirada em ambientes reais de SOC. Ele coleta eventos, usa Kafka como barramento, processa regras em Python, enriquece alertas com threat intelligence, persiste no PostgreSQL e exibe um dashboard SOC em tempo real.

## 2. Problema que ele resolve

Ele demonstra como transformar logs brutos em alertas acionáveis, com scoring de risco, correlação temporal, threat intelligence e resposta simulada. O objetivo é mostrar fundamentos práticos de SOC, SIEM e arquitetura event-driven.

## 3. Por que Kafka foi usado

Kafka foi usado para desacoplar coleta, detecção e persistência. Isso permite absorver picos, reprocessar eventos, escalar consumidores e separar logs brutos de alertas enriquecidos.

## 4. Como funciona o rule_engine

O `rule_engine` consome `raw_logs`, mantém estado temporal em memória, carrega regras de `rules.yaml`, calcula risco, consulta threat intelligence local/externa simulada, gera campos de correlação e publica alertas em `security_alerts`.

## 5. Como funciona a correlação temporal

Eventos por IP são mantidos em uma janela temporal configurável. Eventos antigos expiram. As regras avaliam sequência, frequência, porta, serviço e tipo de evento dentro dessa janela.

## 6. Como funciona a threat intelligence

Existe uma base local em `threat_intel.py` e uma chamada externa simulada com cache. Quando há match, o alerta recebe `threat_intel_match=true`, categoria, descrição e `threat_source`.

## 7. Como funciona simulated_block

O projeto nunca executa bloqueio real por padrão. `ENABLE_BLOCK=false` permanece obrigatório. Quando o risco é alto, o status é crítico ou há IOC, o alerta recebe `simulated_block=true`, representando uma decisão SOC segura e auditável.

## 8. Limitações atuais

- Kafka está em nó único.
- Correlação é em memória.
- API usa token simples, não RBAC.
- Threat externa é simulada.
- Não há schema registry nem DLQ formal.
- Prometheus não está no compose por padrão.

## 9. Como escalaria para produção

Escalaria Kafka com múltiplos brokers e partitions, manteria afinidade por IP na chave de particionamento, usaria consumer groups, adicionaria state store para correlação distribuída, migrações versionadas, Prometheus/Grafana e alertas por consumer lag e taxa de incidentes.

## 10. Perguntas prováveis e respostas

**Isso é um SIEM completo?**  
Não. É um mini-SIEM demonstrativo com arquitetura inspirada em SOC real.

**Por que Kafka e não fila simples?**  
Kafka permite retenção, replay, consumer groups e desacoplamento com maior maturidade para pipelines de eventos.

**Como evita duplicidade?**  
Os alertas usam `event_id` único no PostgreSQL e `ON CONFLICT DO NOTHING`.

**Por que bloqueio simulado?**  
Para demonstrar resposta automatizada sem risco operacional. Bloqueio real exigiria governança, allowlist, aprovação e rollback.

**Qual seria o próximo passo técnico?**  
Adicionar state store distribuído, DLQ, schema registry, autenticação real, migrações versionadas e observabilidade completa de Kafka.
