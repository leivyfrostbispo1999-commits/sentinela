## Checkpoint 2026-05-11
- **Status:** Concluído até o ponto de confiabilidade do pipeline de eventos.
- **Resumo do dia:**
  1. Migrei a discussão para um checkpoint operacional no workspace da Oracle/VPS e mantive o stack vivo sem `docker compose down`.
  2. Entreguei observabilidade do pipeline de eventos com `/events/stats`, métricas Prometheus, script `ops/event-stats.sh`, `ops/test-event-stats.sh` e atualização de docs.
  3. Endureci o pipeline com `services/common/pipeline_resilience.py`, backoff priorizado e `CircuitBreaker` local em `rule_engine` e `alert_sink`.
  4. Registrei `event_schema_version`, `pipeline_priority`, `pipeline_retry_count`, `max_retry_count`, `next_retry_at` e `retry_strategy` no fluxo de eventos/DLQ.
  5. Atualizei `docs/PIPELINE_RESILIENCE.md` e `docs/NEXT_ARCHITECTURAL_STEPS.md` com o novo estado arquitetural.
- **Validação concluída:**
  - `py -m pytest -q D:\sentinela\tests` -> `73 passed`
- **Ponto para retomar amanhã:**
  1. Evoluir `pipeline_priority` para filas/tópicos Kafka separados por prioridade.
  2. Se necessário, conectar isso a métricas de backpressure/lag mais explícitas.
- **Arquivos principais tocados hoje:**
  - `services/common/pipeline_resilience.py`
  - `services/rule_engine/main.py`
  - `services/alert-sink/main.py`
  - `tests/test_operational_hardening.py`
  - `docs/PIPELINE_RESILIENCE.md`
  - `docs/NEXT_ARCHITECTURAL_STEPS.md`

- **Status:** Concluído (Evolução do Pipeline de Prioridade)
- **Horário de Início:** 2026-05-16
- **Entregas:**
  1. Implementação de tópicos Kafka por prioridade (`security_alerts`, `security_alerts_high`, `security_alerts_low`).
  2. `rule_engine` agora publica dinamicamente baseado na prioridade do alerta.
  3. `alert_sink` agora consome simultaneamente de todos os tópicos de prioridade.
  4. Mantida compatibilidade total com instalações que usam apenas o tópico `security_alerts`.
  5. Adicionada suíte de testes `tests/test_priority_topics.py`.
  6. Validação completa: 76 testes passando (100% de sucesso).
- **Arquivos Alterados:** services/common/pipeline_resilience.py, services/rule_engine/main.py, services/alert-sink/main.py, tests/test_priority_topics.py.

## Agente Ativo
- **Agente:** Gemini CLI (Principal Engineer)
- **Status:** Em Andamento (Frentes 3, 4 e 5: SOAR Whitelist, Anti Lock-out e Validação de Resiliência)
- **Horário de Início:** 2026-05-16
- **Tarefas Pretendidas:**
  1. SOAR Whitelist Forte: Criar config/soar_whitelist.yml e validar alvos no ResponseEngine.
  2. Anti Lock-out e Segurança SOAR: Default dry-run, condições de execução (risk >= 70), Cooldown de 30min no Redis e Rollback plans.
  3. Validação de Resiliência: CLOUD_VALIDATION_PLAN.md, script run_resilience_validation.py e PRODUCTION_RISK_MITIGATION_REPORT.md.
- **Arquivos Travados:** services/rule_engine/response_engine.py, services/rule_engine/main.py, tests/test_response_engine.py, config/soar_whitelist.yml, docs/CLOUD_VALIDATION_PLAN.md, scripts/validation/run_resilience_validation.py, docs/PRODUCTION_RISK_MITIGATION_REPORT.md.

## Histórico de Tarefas Recentes
- **Status:** Concluído (Frente 2: Redis Memory Control)
- **Horário de Finalização:** 2026-05-16
- **Tarefas Realizadas:**
  1. Redis Memory Control: TTL, XTRIM, maxmemory e scripts de limpeza implementados.
- **Arquivos Travados:** Nenhum.



## Agente Ativo
- **Agente:** Gemini CLI
- **Status:** Concluído (Nível AI-NATIVE SOC PLATFORM + Infra Optimized)
- **Horário de Finalização:** 2026-05-08
- **Tarefas Realizadas:** 
  1. **AI-native XDR & Threat Graph:** Implementada plataforma completa com Neo4j, Flink CEP, ML Real (Isolation Forest) e Copilot SOC.
  2. **Docker Profiles Optimization:** Implementados perfis de execução no `docker-compose.yml` para economizar recursos locais:
     - `core`: Componentes essenciais (Kafka, DB, API, Rule Engine).
     - `analytics`: Flink, AI Engine e UEBA.
     - `graph`: Neo4j e Graph Engine.
     - `search`: OpenSearch (Cold Storage).
     - `full`: Stack completa para modo "God Mode".
  3. **UX & Infrastructure Resilience:** 
     - Criado script `scripts/infra/recover-docker.ps1` para reinicialização automatizada do WSL e Docker Desktop, resolvendo travamentos de engine.
     - Implementado atalho `scripts/infra/start-core.ps1`.
     - README.md atualizado com guias de auto-recuperação via terminal.
  4. **Higiene:** Validada integridade técnica com 69 testes aprovados.
- **Arquivos Travados:** Nenhum.

## Agente Ativo
- **Agente:** Gemini CLI
- **Status:** Concluído (Detection DSL Madura - Sigma-like)
- **Horário de Finalização:** 2026-05-09
- **Tarefas Realizadas:** 
  1. **Sigma Parser:** Desenvolvido o `SigmaRuleCompiler` em `dsl_parser.py`, suportando operadores booleanos (`and`, `or`, `not`), agregações (`1 of selection*`) e modificadores de campo (`contains`, `re`, `endswith`).
  2. **Refatoração do Engine:** O motor de regras agora compila o YAML na inicialização e aplica a lógica Sigma de forma nativa e segura.
  3. **Playbooks Sigma:** Atualizado `sentinela_rules.yml` com regras reais usando seleções nomeadas e condições booleanas complexas.
  4. **Correção de Bugs:** Resolvida inconsistência em `mitre_for_event` que causava `TypeError` após a mudança de tipos de dados das regras.
  5. **Resiliência:** Executado novo procedimento de recuperação forçada do Docker Desktop para estabilizar o broker Kafka sob alta carga de tracing.
- **Arquivos Travados:** Nenhum.

## Histórico de Tarefas Recentes
- **Status:** Concluído (Agente Anterior)
- **Tarefas Realizadas:** 
  1. Implementada `ResponseEngine` (`services/rule_engine/response_engine.py`) para SOAR básico.
  2. Adicionadas ações automáticas simuladas (`block_ip`, `escalate_to_incident`, `notify_webhook`) baseadas em severidade e MITRE.
  3. Criada tabela `response_actions` no Postgres para auditoria completa das ações de resposta.
  4. Implementados endpoints de consulta SOAR (`/response/actions`) na `dashboard_api`.
  5. Criada suíte de testes `tests/test_response_engine.py` (Total: 69 testes passando).

## Checkpoint Final - Oracle Micro Validada
- **Data:** 2026-05-13
- **Status:** Concluído e validado após reboot real da VM.
- **Ambiente:** Oracle Cloud Infrastructure, região `sa-saopaulo-1`.
- **VM:** `SENTINELA-AMD-TEST`
- **Shape:** `VM.Standard.E2.1.Micro` (1 OCPU, 1 GB RAM)
- **IP público:** `163.176.204.190`
- **URL pública:** `http://163.176.204.190`

### Stack 24/7 Ativa
- `sentinela-web-lite`
- `sentinela-api-lite`
- `sentinela-db-lite`
- `sentinela-redis-lite`

### Heavy Stack Sob Demanda
- Definida em `docker-compose.heavy.yml`.
- Inclui Kafka, Jaeger, simulator, `ai_engine_lite`, `log_collector`, `enrichment_worker`, `rule_engine` e `alert_sink`.
- Serviços pesados configurados com `restart: "no"` e limites rígidos de memória.
- Heavy stack deve ser usada apenas para janelas curtas de teste/validação.

### Comandos Operacionais
- Iniciar micro 24/7:
  ```bash
  ./ops/oci/start_micro.sh
  ```
- Parar micro sem apagar volumes:
  ```bash
  ./ops/oci/stop_micro.sh
  ```
- Subir heavy stack temporária:
  ```bash
  ./ops/oci/start_heavy_test.sh
  ```
- Parar/remover heavy stack sem apagar volumes:
  ```bash
  ./ops/oci/stop_heavy_test.sh
  ```
- Ver status, restart policies e memória:
  ```bash
  ./ops/oci/status_micro.sh
  ```

### Alertas Operacionais
- **Não rodar `docker system prune` sem confirmação explícita.**
- **Não rodar `docker compose down -v`, `docker volume rm` ou qualquer limpeza de volumes sem backup e confirmação explícita.**
- **Não manter Kafka, Jaeger, AI engine, simulator ou workers pesados rodando continuamente na micro.**
- A micro é apenas o plano 24/7 leve: dashboard, API, Postgres e Redis.

### Validação Realizada
- Após reboot, apenas `sentinela-web-lite`, `sentinela-api-lite`, `sentinela-db-lite` e `sentinela-redis-lite` subiram automaticamente.
- Heavy stack permaneceu vazia/parada.
- Dashboard público respondeu `200 OK`.
- API via proxy Nginx (`/metrics/summary`) respondeu `200 OK`.
- Porta pública `5000` permaneceu bloqueada; a API deve ser acessada pelo proxy HTTP/80.

### Próximos Passos
- Tentar novamente provisionar uma VM Ampere A1 (`VM.Standard.A1.Flex`) futuramente, quando houver capacidade disponível na região.
- Ao migrar para Ampere A1, mover a execução contínua de Kafka/Jaeger/AI/workers para a nova VM ou separar por hosts.

## Checkpoint - Tentativa Ampere A1
- **Data:** 2026-05-13
- **Status:** Tentativa concluída sem criação de nova VM.
- **Região:** `sa-saopaulo-1`
- **Alvo tentado:** `VM.Standard.A1.Flex`
- **Tentativas realizadas:**
  1. `4 OCPU / 24 GB RAM` para `SENTINELA-ARM-HEAVY` -> falhou com `Out of host capacity`.
  2. `2 OCPU / 12 GB RAM` para `SENTINELA-ARM-HEAVY` -> uma tentativa teve timeout da CLI; após conferência, nenhuma VM foi criada.
  3. Nova tentativa `2 OCPU / 12 GB RAM` -> falhou com `Out of host capacity`.
- **Resultado:** nenhuma VM Ampere A1 parcial ficou criada.
- **Micro atual:** `SENTINELA-AMD-TEST` permanece `RUNNING`.
- **Infraestrutura:** sem alteração na micro atual, sem migração de produção, sem alteração em volumes Postgres e sem heavy stack permanente.
- **Próximo passo:** tentar novamente Ampere A1 futuramente quando houver capacidade disponível na Oracle Cloud.

## Checkpoint - Hardening Operacional da Oracle Micro
- **Data:** 2026-05-13
- **Status:** Concluído e validado na VPS.
- **Escopo:** proteção da stack micro 24/7 sem subir heavy stack e sem apagar volumes.
- **Entregas:**
  1. Backup diário automático do Postgres com `ops/oci/backup_postgres.sh`.
  2. Backup inicial gerado em `/home/ubuntu/sentinela/backups/postgres/sentinela_2026-05-13.sql.gz`.
  3. Retenção configurada para manter os últimos 7 dias de backups `.sql.gz`.
  4. Watchdog simples com `ops/oci/watchdog_micro.sh`, rodando a cada 2 minutos via cron.
  5. Métricas mínimas da VPS com `ops/oci/write_host_metrics.sh`, expostas em `/runtime/host_metrics.json`.
  6. Cron instalado por `ops/oci/install_micro_cron.sh`.
  7. Rate limiting configurado no Nginx para web/API.
  8. Docker log rotation configurado no `docker-compose.micro.yml` (`max-size=10m`, `max-file=3`).
  9. Healthchecks adicionados em Postgres, Redis, API e Web.
  10. API deixou de publicar a porta `5000` no host; acesso passa pelo proxy Nginx na porta `80`.
  11. UFW habilitado localmente permitindo apenas `22/tcp` e `80/tcp`.
- **Validação:**
  - Containers micro: `sentinela-web-lite`, `sentinela-api-lite`, `sentinela-db-lite`, `sentinela-redis-lite` em estado `healthy`.
  - Portas no host: apenas `22` e `80` escutando.
  - Dashboard público: `http://163.176.204.190` retornando `200 OK`.
  - Métricas públicas: `http://163.176.204.190/runtime/host_metrics.json` retornando `200 OK`.
  - Porta pública `5000`: fechada.
- **Alertas mantidos:**
  - Não rodar `docker system prune` sem confirmação explícita.
  - Não apagar volumes do Postgres.
  - Não manter Kafka, Jaeger, AI engine ou workers pesados rodando continuamente na micro.

## Checkpoint - Restore Test e Backup Fora da VPS
- **Data:** 2026-05-13
- **Status:** Concluído.
- **Backup testado:** `/home/ubuntu/sentinela/backups/postgres/sentinela_2026-05-13.sql.gz`
- **Restore test:** executado com `ops/oci/test_restore_backup.sh`.
- **Método:** restore em container temporário `postgres:15-alpine`, isolado e sem volume persistente, sem tocar no `sentinela-db-lite`.
- **Resultado do restore:** OK, 11 tabelas restauradas e tabela `public.alertas` validada.
- **Limpeza:** container temporário de restore removido automaticamente.
- **Cópia fora da VPS:** backup copiado para `D:\sentinela_backups\sentinela_2026-05-13.sql.gz`.
- **Validação pós-teste:**
  - `sentinela-web-lite`, `sentinela-api-lite`, `sentinela-db-lite` e `sentinela-redis-lite` continuam `healthy`.
  - Apenas portas `22` e `80` escutam no host.
  - Porta `5000` não está publicada no host.
- **HTTPS/DNS:** documentado como hardening futuro em `ops/oci/RUNBOOK_MICRO.md`; ainda não implementado.

## Checkpoint Final Git - Oracle Micro
- **Data:** 2026-05-13
- **Status:** pronto para commit local, sem push remoto.
- **Validação final da VPS:**
  - `sentinela-web-lite`, `sentinela-api-lite`, `sentinela-db-lite` e `sentinela-redis-lite` em estado `healthy`.
  - Heavy stack vazia; nenhum Kafka, Jaeger, simulator, AI engine ou worker pesado rodando continuamente.
  - Cron legado removido; permanecem apenas `watchdog_micro.sh`, `write_host_metrics.sh` e `backup_postgres.sh`.
  - Portas públicas/host: `22/tcp` e `80/tcp`; porta `5000` sem listener no host e sem resposta externa.
  - Endpoint público de métricas respondeu `200 OK`.
- **Alertas finais:**
  - Não rodar `docker system prune` sem confirmação explícita.
  - Não apagar volumes do Postgres.
  - Não subir Kafka, Jaeger ou AI continuamente na micro.
