# Escalabilidade Kafka no SENTINELA

O SENTINELA foi desenhado como um mini-SIEM educacional/profissional com arquitetura inspirada em ambientes reais de SOC. Ele não afirma processar milhões de eventos por segundo, mas usa decisões arquiteturais que permitem evoluir para volumes maiores.

## Como escalaria para alto volume

O caminho natural de escala é aumentar a capacidade do Kafka, separar responsabilidades por tópicos e escalar consumidores horizontalmente. O pipeline atual já separa logs brutos de alertas enriquecidos:

```text
simulator/log_collector -> Kafka raw_logs -> rule_engine -> Kafka security_alerts -> alert_sink -> PostgreSQL -> API/dashboard
```

Em produção, `raw_logs` receberia alto volume e `security_alerts` teria menor volume, porque contém apenas eventos já classificados ou enriquecidos.

## Partitions no Kafka

Para alto volume, os tópicos deveriam ter múltiplas partitions. Uma estratégia comum seria particionar por IP de origem, tenant, sensor ou hash do evento. Isso permite paralelismo real no consumo.

Exemplo conceitual:

- `raw_logs`: várias partitions para ingestão paralela.
- `security_alerts`: partitions suficientes para acompanhar o throughput do `rule_engine`.

O cuidado técnico é manter eventos do mesmo IP na mesma partition quando a correlação depende de ordem temporal por IP.

## Consumer groups

O `rule_engine` usa consumer group. Em produção, múltiplas instâncias poderiam consumir o tópico `raw_logs` em paralelo, desde que o número de partitions suporte esse paralelismo.

O `alert_sink` também pode escalar por consumer group, mas precisa manter idempotência no banco. O projeto já usa `event_id UUID UNIQUE` e `ON CONFLICT DO NOTHING`, o que reduz risco de duplicidade.

## Backpressure

Kafka ajuda a absorver picos. Se o banco ou o `rule_engine` ficarem lentos, os eventos acumulam no tópico em vez de derrubar diretamente o produtor. Em produção, seriam monitorados:

- consumer lag por grupo
- taxa de produção e consumo
- tempo de processamento do `rule_engine`
- erros de escrita no PostgreSQL
- tamanho dos lotes e latência fim a fim

## Retenção de eventos

O tópico `raw_logs` deveria ter retenção maior para reprocessamento e auditoria. O tópico `security_alerts` poderia ter retenção diferente, focada em recuperação do sink e replay dos alertas.

Retenção em produção dependeria de custo, compliance e necessidade de investigação.

## Separação entre raw_logs e security_alerts

A separação é intencional:

- `raw_logs`: eventos originais, ruidosos, sem decisão final.
- `security_alerts`: eventos enriquecidos com risco, status, threat intel, correlação e resposta simulada.

Isso permite evoluir detecção sem acoplar coleta, persistência e dashboard.

## Escala horizontal do rule_engine

O `rule_engine` pode ser escalado horizontalmente se:

- `raw_logs` tiver partitions suficientes.
- a chave de particionamento preservar afinidade por IP ou entidade correlacionada.
- a correlação em memória for compatível com distribuição por partition.

Para uma versão mais robusta, estado de correlação poderia ir para Redis, RocksDB, Kafka Streams ou outro state store.

## Limitações atuais

- Kafka está em nó único, adequado para demo local.
- Correlação é em memória e local ao container.
- Não há schema registry.
- Não há DLQ formal por tipo de erro.
- PostgreSQL é único e recebe todos os alertas.
- Dashboard e API não têm RBAC, apenas token simples para demo.

## Próximos passos para produção

- Kafka com múltiplos brokers e replication factor adequado.
- Partitions configuradas por tópico e chave de particionamento estável.
- Observabilidade de consumer lag.
- DLQ para eventos inválidos.
- State store para correlação distribuída.
- Migrações versionadas de banco.
- Retenção por política operacional.
- Testes de carga com metas realistas de throughput.
