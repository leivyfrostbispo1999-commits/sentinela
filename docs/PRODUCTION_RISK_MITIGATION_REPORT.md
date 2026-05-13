# Relatório de Mitigação de Riscos em Produção

## 1. Visão Geral
Este documento detalha as camadas de proteção implementadas no motor de resposta (SOAR) do SENTINELA para evitar impactos operacionais indevidos ("lock-outs") e garantir a resiliência do sistema.

## 2. Camadas de Proteção Implementadas

### 2.1 Whitelist de Ativos Críticos
- **Mecanismo:** Filtro mandatório antes de qualquer ação destrutiva (`block_ip`, `isolate_container`, etc.).
- **Escopo:** IPs estáticos, sub-redes (CIDR), nomes de hosts e identificadores de containers.
- **Configuração:** Gerida via `config/soar_whitelist.yml`.
- **Impacto:** Impede que o próprio SENTINELA ou componentes vitais da infraestrutura sejam bloqueados automaticamente.

### 2.2 Controle de Cooldown de Ação
- **Mecanismo:** Estado persistido no Redis (ou Memória) com TTL de 30 minutos (1800s).
- **Lógica:** Uma ação destrutiva só é repetida para o mesmo alvo após o término do cooldown.
- **Impacto:** Evita "storms" de ações de resposta e degradação de performance por chamadas repetitivas de API.

### 2.3 Condições de Execução Rigorosas (Anti-Lockout)
- **Dry-Run por Padrão:** O SOAR inicia em modo simulação (`SENTINELA_SOAR_EXECUTE=false`).
- **Score Mínimo:** Ações reais só são disparadas se o risco do alerta for `>= 70`.
- **Severidade:** Exige severidade `HIGH` ou `CRITICAL` para execução automática.

### 2.4 Planos de Auto-Recuperação (Rollback)
- **Mecanismo:** Cada ação destrutiva gera automaticamente uma contra-medida correspondente no log de execução.
- **Exemplo:** `block_ip` gera `unblock_ip`.
- **Benefício:** Facilita a reversão rápida por analistas humanos em caso de falso positivo.

## 3. Conclusão
O SENTINELA agora opera sob um modelo de "Confiança Zero mas Segurança Máxima", onde a automação é balanceada por salvaguardas que protegem a continuidade do negócio.
