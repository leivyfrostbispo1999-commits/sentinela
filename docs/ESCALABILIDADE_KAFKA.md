# Escalabilidade Kafka no SENTINELA

O SENTINELA foi estruturado como um mini-SIEM educacional/profissional com arquitetura inspirada em pipelines reais de SOC. Ele não afirma processar milhões de eventos por segundo. A proposta é demonstrar escolhas arquiteturais que permitem evolução controlada para cenários de maior volume.

## Pipeline Atual

```text
simulator/log_collector -> Kafka raw_logs -> rule_engine -> Kafka security_alerts -> alert_sink -> PostgreSQL -> dashboard_api -> dashboard_web
```

A separação entre logs brutos e alertas enriquecidos é intencional. O tópico `raw_logs` recebe eventos de maior volume. O tópico `security_alerts` recebe eventos já analisados, classificados e enriquecidos pelo `rule_engine`.

## Partitions

Em um ambiente de maior volume, os tópicos Kafka deveriam usar múltiplas partitions. Isso permitiria paralelismo real entre consumidores e melhor absorção de picos.

Estratégias possíveis de chave:

- IP de origem.
- Sensor de origem.
- Tenant.
- Hash de entidade investigada.

Quando a correlação depende de ordem por IP, eventos do mesmo IP devem cair na mesma partition. Isso reduz inconsistências na análise temporal.

## Consumer Groups

O `rule_engine` pode escalar horizontalmente usando consumer groups. Para isso, `raw_logs` precisa ter partitions suficientes para distribuir trabalho entre instâncias.

O `alert_sink` também pode escalar com consumer group. Como o banco usa `event_id` único e gravação idempotente, o risco de duplicidade é reduzido.

## Backpressure

Kafka ajuda a absorver picos quando algum componente posterior fica lento. Se o banco ou o `rule_engine` atrasarem, os eventos podem acumular no tópico em vez de derrubar diretamente os produtores.

Indicadores que deveriam ser monitorados:

- Consumer lag por grupo.
- Taxa de produção e consumo.
- Latência de processamento no `rule_engine`.
- Erros de escrita no PostgreSQL.
- Tempo fim a fim entre ingestão e visualização.

## Retenção

O tópico `raw_logs` deveria ter retenção suficiente para auditoria e reprocessamento. O tópico `security_alerts` poderia ter retenção menor, focada em replay dos alertas e recuperação do `alert_sink`.

A política real dependeria de custo, compliance, criticidade e necessidade de investigação.

## Escala Horizontal do Rule Engine

O `rule_engine` pode ser replicado se três condições forem atendidas:

- O tópico `raw_logs` tiver partitions suficientes.
- A chave de particionamento preservar afinidade por IP ou entidade correlacionada.
- O estado de correlação for compatível com execução distribuída.

Na versão atual, a correlação é local e em memória. Para produção, o estado deveria migrar para Redis, Kafka Streams, RocksDB ou outro state store.

## Limitações Atuais

- Kafka roda em nó único.
- Correlação é local ao container.
- Não há schema registry.
- Não há dead-letter queue formal.
- PostgreSQL é uma instância única.
- A autenticação é simples e baseada em token.

## Próximos Passos Para Produção

- Kafka com múltiplos brokers.
- Replication factor adequado.
- Partitions planejadas por tópico.
- DLQ para eventos inválidos.
- Schema registry ou validação formal de eventos.
- Métricas de consumer lag.
- State store distribuído para correlação.
- Testes de carga com metas realistas de throughput e latência.
