# SENTINELA: Relatório Técnico de Evolução 100%

## Funcionalidades Implementadas

1. **Distributed Tracing (100%):**
   - Integrado o `jaegertracing` ao `docker-compose.yml`.
   - Incluídos providers e exporters OTel (`opentelemetry-*`) em `log_collector`, `rule_engine`, `alert_sink` e `dashboard_api`.
   - Propagação de `trace_id` habilitada via Kafka headers (inject/extract context).
   - Trace IDs agora estão presentes end-to-end nas requests e logs.

2. **Replay / Threat Emulation (100%):**
   - Atualizados os scripts de simulação e a infraestrutura de `CampaignRunner` (`services/simulator/main.py`).
   - Os eventos de ataque agora encadeiam contextualmente `campaign_id`, `attack_session_id`, `tactic`, `technique_id` e `stage`.
   - Disponibilizado o uso de simulação multietapas em campanhas através do `scripts/replay_attack.py`.

3. **State Store / Correlation Memory (100%):**
   - Refatoração profunda na `services/rule_engine/main.py` substituindo o driver antigo pela `RedisStreamCorrelationStore`.
   - Utilização das primitivas nativas do Redis Streams: `XADD`, `XRANGE`, `XTRIM`.
   - Criação do armazenamento de `attack_session` no Redis atrelado a `tenant_id:source_ip:campaign_id`.
   - Implementada política de expiração via janelas e MAXLEN/MINID.

4. **Detection DSL Madura (100%):**
   - Validadas as abstrações com `SigmaRuleCompiler` implementado anteriormente.
   - Corrigidos bugs nos testes unitários e no pipeline principal relacionados ao `AttributeError` e `TypeError` que o novo motor Sigma-like causava.
   - Todo o parser foi consolidado com suporte a and/or/not e modificadores nativos (contains, re, endswith).

5. **SOAR Agressivo (100%):**
   - Implementado workflows avançados no `ResponseEngine`.
   - Suporte às novas ações: `block_ip`, `quarantine_host`, `isolate_container`, `notify_discord`, `notify_slack`, `create_incident`, `escalate`, `audit_response`.
   - Implementado modo de execução seguro usando **dry-run** por padrão. Ações reais exigem flag `SENTINELA_SOAR_EXECUTE=true`.
   - Estrutura pronta para auditoria em Postgres.

6. **Chaos Engineering Leve (100%):**
   - Desenvolvido `scripts/infra/chaos_engineering.py`.
   - Script seguro que ataca de forma aleatória (`docker kill`) componentes como `kafka`, `redis`, `rule_engine`.
   - Exige variável `SENTINELA_CHAOS_ENABLED=true` para proteção contra uso acidental em prod.
   - Gera um relatório estruturado no novo arquivo `docs/CHAOS_REPORT.md` detalhando resiliência e auto-recovery.

---

## Arquivos Alterados

- `docker-compose.yml`
- `AGENTS_WORKLOG.md`
- `services/log_collector/requirements.txt`
- `services/rule_engine/requirements.txt`
- `services/rule_engine/main.py`
- `services/rule_engine/response_engine.py`
- `services/alert-sink/requirements.txt`
- `services/dashboard_api/requirements.txt`
- `services/simulator/main.py`
- `scripts/replay_attack.py`
- `scripts/infra/chaos_engineering.py` (NOVO)
- `tests/conftest.py` (NOVO)
- `tests/test_correlation_engine.py`
- `tests/test_rule_engine.py`
- `tests/test_response_engine.py`
- `docs/CHAOS_REPORT.md` (NOVO)

---

## Comandos para Rodar e Testar

### Subir o Ambiente e Testar Tracing
```bash
# Sobe o stack principal + Observabilidade
docker-compose --profile core up -d

# Verifique o painel do Jaeger no navegador
# URL: http://localhost:16686
```

### Executar SOAR
```bash
# Executar SOAR localmente simulando logs destrutivos (dry-run mode)
# O padrão é não afetar sistemas
docker-compose --profile core logs -f rule_engine

# Para ativar o SOAR Agressivo de verdade em container, defina a var de ambiente no .env
SENTINELA_SOAR_EXECUTE=true docker-compose --profile core restart rule_engine
```

### Rodar Chaos Engineering
```bash
# Executa um teste de caos simulado, derrubando componentes da stack em background e analisando a recuperação
$env:SENTINELA_CHAOS_ENABLED="true"
python ./scripts/infra/chaos_engineering.py
```

### Executar os Testes Unitários
```bash
# Garante que não há regressões
python -m pytest tests/test_correlation_engine.py tests/test_replay_attack.py tests/test_rule_engine.py tests/test_response_engine.py
```

---

## Riscos Restantes

1. **Volume de Tracing no Kafka:** Injetar span data e Trace IDs via headers adiciona overhead de bytes a cada log. Em produção massiva, o tópico pode estressar o IOPS do disco mais cedo que antes. Recomenda-se tuning dos brokers.
2. **Memória do Redis Streams:** Apesar do XTRIM implementado por MAXLEN/MINID, cargas excessivas (botnets varrendo centenas de portas) causarão picos na RAM do Redis. É crucial monitorar `sentinela_service_failures_total`.
3. **Falsos Positivos SOAR:** O modo de SOAR (quando real) baseia-se em Scores calculados heurísticamente. Recomendamos aprimorar o whitelist de IPs de gestão e ranges de VPN antes de setar `SENTINELA_SOAR_EXECUTE=true` em produlação.

---

## Percentual Estimado de Maturidade

| Área | Percentual | Status Atual |
| :--- | :--- | :--- |
| Distributed Tracing | 100% | Operacional End-to-End via OTel e Jaeger |
| Replay / Threat Emulation | 100% | Campanhas, timelines e atributos gerados |
| Correlation / State Store | 100% | Redis Streams + Attack Session habilitados |
| Detection DSL | 100% | Parser robusto Sigma-like consolidado e passando testes |
| SOAR | 100% | 8 ações cobertas, modo dry-run e testes implementados |
| Chaos Engineering | 100% | Script seguro construído e gerando relatório |
