# Histórico de Decisões Técnicas

## SENTINELA SOC 4.0

- Dashboard SOC visual em HTML, CSS e JavaScript puro.
- Mapa global simulado sem dependência de APIs externas.
- Threat Intelligence local para demonstrar enriquecimento de alertas.
- `simulated_block` como mecanismo seguro de resposta sem bloqueio real.

## SENTINELA SOC 5.0

- Regras YAML para separar lógica de detecção da implementação Python.
- Filtros temporais na API para análise de histórico recente.
- Métricas Prometheus para demonstrar observabilidade operacional.
- Threat Intelligence externa simulada com cache para evitar dependência de chave real.

## SENTINELA SOC 5.5

- Repositório organizado para portfólio.
- Documentação de escalabilidade Kafka, observabilidade e defesa técnica.
- Autenticação simples por token no dashboard e na API.
- Drill-down no dashboard para investigação de alertas.

## Fundação Técnica Pré-6.0

- Redis adotado como state store do `rule_engine`.
- Fallback em memória mantido para resiliência da demo local.
- JWT HMAC-SHA256 adicionado mantendo compatibilidade com o token legado.
- Testes com `pytest` adicionados para scoring, detecção, autenticação e `simulated_block`.
- GitHub Actions criado para rodar compilação Python e testes.
- Profile educacional `kafka-lab` adicionado ao Docker Compose sem alterar o modo single broker padrão.
- Modo demonstração de incidente adicionado ao dashboard para apresentações guiadas.
- Endpoint `POST /demo/simulate-attack` protegido por autenticação e limitado a alertas simulados.
- Timeline investigativa vertical adicionada para demonstrar progressão de detecção, correlação e resposta SOC.

## SENTINELA SOC 6.0

- Incidentes passaram a ser entidade persistida em `incidents`, com relacionamento em `incident_alerts` e trilha manual em `incident_audit_log`.
- A correlação multi-IP/multi-entidade considera `source_ip`, destino, usuário, serviço/porta, MITRE, `replay_id` e janela temporal de 10 minutos.
- Overrides legados em `incident_overrides` foram preservados para compatibilidade, mas os endpoints 6.0 priorizam os incidentes materializados.
- A investigação por IP foi refinada com resumo do analista, recomendações defensivas e incidentes relacionados.
- A timeline passou a carregar fases técnicas como `RECONNAISSANCE`, `CREDENTIAL_ACCESS`, `IOC_MATCH`, `ESCALATION`, `CORRELATION` e `RESPONSE_SIMULATED`.
- `/metrics` agora entrega métricas JSON reais para o dashboard; o formato Prometheus fica disponível em `/metrics/prometheus`.
- `/rules` expõe regras YAML carregadas e validadas, com fallback seguro para defaults internos.
- `scripts/replay_attack.py` passou a suportar múltiplos cenários simulados sem rede externa, ataque real ou bloqueio real, incluindo `multi_ip_campaign`.
- Relatórios de incidente agora têm saída Markdown e PDF local, sem serviço externo.

## Decisões de Segurança

- `ENABLE_BLOCK=false` permanece como padrão obrigatório.
- Nenhum bloqueio real por firewall ou `iptables` é executado.
- JWT usa segredo por variável de ambiente.
- O token padrão existe apenas para facilitar a demo local.
- O modo demo registra `simulated_block=true`, mas não executa firewall, `iptables` ou bloqueio real.
- A simulação de incidente é educacional e foi desenhada para demonstrar fluxo SOC sem risco operacional.
- Alertas 6.0 carregam MITRE ATT&CK, explicação humana, investigação por IP e incidentes editáveis pela API.
- A timeline é visual e educacional; ela melhora a narrativa de investigação sem adicionar ação ofensiva ou bloqueio real.

## Decisões de Escalabilidade

- Kafka continua desacoplando ingestão, detecção e persistência.
- Redis prepara o projeto para correlação mais madura entre reinícios e múltiplos workers.
- A correlação ainda exige estratégia de particionamento por IP para escalar horizontalmente com consistência forte.

## Redução de Ruído e Correlação SOC

- O pipeline consolida alertas repetidos por chave composta de IP, tipo de evento, status, porta e categoria de ameaça.
- O dashboard lê alertas consolidados para reduzir repetição visual, mas o histórico bruto continua persistido no PostgreSQL.
- `first_seen`, `last_seen`, `occurrence_count`, `ports`, `services` e `event_types` foram adicionados para explicar a agregação.
- O modo `demo` é tratado como visão controlada para apresentação, sem apagar retenção real do SIEM.
