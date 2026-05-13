# Plano de Validação em Nuvem (Cloud Validation Plan)

## 1. Objetivos
Validar a resiliência, escalabilidade e segurança do SENTINELA em ambiente produtivo (AWS/GCP/Azure).

## 2. Cenários de Teste
### 2.1 Resiliência de Pipeline
- **Falha do Broker Kafka:** Induzir queda de um nó do Kafka e verificar reconexão dos workers.
- **Sobrecarga do Rule Engine:** Enviar 10k eventos/segundo e monitorar latência no Prometheus.
- **Queda do Redis:** Validar fallback do `CorrelationEngine` para modo em memória.

### 2.2 Segurança SOAR (Anti Lock-out)
- **Whitelist Real:** Tentar bloquear IPs do cluster (K8s control plane) e validar log `blocked_by_whitelist`.
- **Cooldown:** Gerar múltiplos alertas para o mesmo host e validar que apenas uma ação de quarentena é disparada por janela de 30min.
- **Rollback:** Executar um `block_ip` e validar a presença do `rollback_plan` no log de auditoria.

### 2.3 Detecção em Escala
- **Cenário de Replay:** Usar `scripts/replay_events.py` com datasets reais de ataques (e.g., CIC-IDS2017).
- **Detecção de Campanha:** Validar correlação distribuída entre múltiplos tenants.

## 3. Critérios de Aceitação
- Zero perda de eventos durante failover de componentes.
- Ações destrutivas bloqueadas para alvos da whitelist.
- Latência de correlação (P95) abaixo de 200ms.
