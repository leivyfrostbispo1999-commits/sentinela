# Autonomous SOC Documentation

O SENTINELA evoluiu para um modelo de SOC Autônomo com governança humana.

## Playbooks Implementados
- `brute_force_response`: Bloqueio de IP e notificação Slack.
- `lateral_movement_response`: Quarentena de host e escalação de incidente.
- `cloud_abuse_response`: Suspensão de chaves de API e isolamento de conta.

## Ciclo de Vida de Ações (States)
1. **Proposed**: Ação sugerida pelo motor de IA/Regras.
2. **Pending Approval**: Ação crítica aguardando intervenção humana.
3. **Approved**: Ação validada pelo analista.
4. **Rejected**: Ação descartada pelo analista.
5. **Executed**: Ação disparada com sucesso no alvo.
6. **Failed**: Falha técnica na execução da resposta.

## Governança
Ações de severidade `CRITICAL` nunca são executadas automaticamente em modo `real` (produção), exigindo sempre aprovação via Dashboard API.
